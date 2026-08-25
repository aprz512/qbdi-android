'use strict';

// Frida -l executes this file in the target process, without Node require().
// This is the only user-edited tracer configuration.
const config = {
  loader: {
    remoteDir: '/data/local/tmp/qbdi-android',
    tracer: 'libqbdi_tracer.so',
    shadowhookCompanion: 'libshadowhook_nothing.so'
  },

  tracer: {
    schemaVersion: 1,
    packageName: 'com.aprz.qbdiandroid',
    targetModule: 'libdemo_target.so',

    trace: {
      profile: 'fast',
      compression: true,
      lz4Level: 2,
      autoBuffer: true,
      bufferMb: 0,
      hexdumpLimit: 32
    },

    flight: {
      enabled: true,
      entryScene: 'init',
      capacityMb: 512,
      chunkKb: 256,
      maxThreads: 256,
      protectedChunks: 4
    },

    scenes: [
      {
        name: 'init',
        location: { offset: '0x6ac90' }
      },
      {
        name: 'algorithm',
        location: {
          imageBase: '0x0',
          address: '0x6db38'
        }
      }
    ]
  }
};

const QTRACE_JSON_OK = 0;
const QTRACE_JSON_RESPONSE_TOO_SMALL = 1;
const INITIAL_RESPONSE_CAPACITY = 16 * 1024;
const MAX_JSON_BYTES = 1024 * 1024;
const TERMINAL_STATES = new Set([
  'installed', 'hook_failed', 'rollback_failed', 'superseded'
]);
const STATUS_STATES = new Set([
  'waiting_for_module', 'installing', 'installed', 'hook_failed',
  'rollback_failed', 'superseded'
]);
const SCENE_STATES = new Set([
  'pending', 'installing', 'installed', 'hook_failed', 'rolled_back',
  'rollback_failed'
]);

function utf8ByteLength(value) {
  let bytes = 0;
  for (const character of value) {
    const point = character.codePointAt(0);
    if (point <= 0x7f) bytes += 1;
    else if (point <= 0x7ff) bytes += 2;
    else if (point <= 0xffff) bytes += 3;
    else bytes += 4;
  }
  return bytes;
}

function callJsonAbi(call) {
  let capacity = INITIAL_RESPONSE_CAPACITY;
  for (let attempt = 0; attempt < 2; ++attempt) {
    const response = Memory.alloc(capacity);
    const responseSize = Memory.alloc(8);
    responseSize.writeU64(new UInt64(0));
    const transportCode = call(response, capacity, responseSize);
    const requiredSize = responseSize.readU64().toNumber();

    if (requiredSize > MAX_JSON_BYTES) {
      throw new Error('JSON ABI response exceeds 1 MiB: ' + requiredSize);
    }
    if (transportCode === QTRACE_JSON_RESPONSE_TOO_SMALL) {
      if (attempt !== 0) {
        throw new Error('JSON ABI response was too small more than once');
      }
      if (requiredSize <= capacity) {
        throw new Error('JSON ABI returned an invalid retry size: ' + requiredSize);
      }
      capacity = requiredSize;
      continue;
    }
    if (transportCode !== QTRACE_JSON_OK) {
      throw new Error('JSON ABI transport failed with code ' + transportCode);
    }
    if (requiredSize === 0 || requiredSize > capacity) {
      throw new Error('JSON ABI returned an invalid response size: ' + requiredSize);
    }
    if (response.add(requiredSize - 1).readU8() !== 0) {
      throw new Error('JSON ABI response is not NUL terminated');
    }
    return response.readUtf8String(requiredSize - 1);
  }
  throw new Error('JSON ABI retry loop exhausted');
}

function responseObject(response) {
  try {
    return typeof response === 'string' ? JSON.parse(response) : response;
  } catch (error) {
    throw new Error('invalid JSON ABI response: malformed JSON: ' + error);
  }
}

function invalidResponse(message) {
  throw new Error('invalid JSON ABI response: ' + message);
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function validateWarningArray(warnings, path) {
  if (!Array.isArray(warnings)) invalidResponse(path + ' must be an array');
  for (let index = 0; index < warnings.length; ++index) {
    const warning = warnings[index];
    if (!isObject(warning) || typeof warning.code !== 'string' ||
        typeof warning.message !== 'string') {
      invalidResponse(path + '[' + index + '] must contain string code and message');
    }
  }
}

function validateErrorResponse(response) {
  const error = response.error;
  if (!isObject(error) || typeof error.code !== 'string' ||
      typeof error.path !== 'string' || typeof error.message !== 'string') {
    invalidResponse('error must contain string code, path, and message');
  }
}

function validateResponseEnvelope(value) {
  const response = responseObject(value);
  if (!isObject(response)) invalidResponse('root must be an object');
  if (response.responseSchemaVersion !== 1) {
    invalidResponse('responseSchemaVersion must equal 1');
  }
  if (typeof response.ok !== 'boolean') invalidResponse('ok must be a boolean');
  if (!response.ok) {
    validateErrorResponse(response);
    return response;
  }
  if (typeof response.generation !== 'number' ||
      !Number.isInteger(response.generation) || response.generation <= 0) {
    invalidResponse('generation must be a positive integer');
  }
  if (typeof response.state !== 'string') invalidResponse('state must be a string');
  if (typeof response.targetModule !== 'string' || response.targetModule.length === 0) {
    invalidResponse('targetModule must be a non-empty string');
  }
  if (!Array.isArray(response.scenes)) invalidResponse('scenes must be an array');
  validateWarningArray(response.warnings, 'warnings');
  return response;
}

function validateConfigureResponse(value) {
  const response = validateResponseEnvelope(value);
  if (!response.ok) return response;
  if (response.state !== 'waiting_for_module') {
    invalidResponse('configure state must be waiting_for_module');
  }
  for (let index = 0; index < response.scenes.length; ++index) {
    const scene = response.scenes[index];
    if (!isObject(scene) || typeof scene.name !== 'string' ||
        typeof scene.offset !== 'string' ||
        !Object.prototype.hasOwnProperty.call(scene, 'endOffset') ||
        (scene.endOffset !== null && typeof scene.endOffset !== 'string')) {
      invalidResponse('scenes[' + index + '] has an invalid normalized scene shape');
    }
  }
  return response;
}

function validateStatusResponse(value) {
  const response = validateResponseEnvelope(value);
  if (!response.ok) return response;
  if (!STATUS_STATES.has(response.state)) invalidResponse('unknown status state');
  if (!Object.prototype.hasOwnProperty.call(response, 'moduleBase') ||
      (response.moduleBase !== null && typeof response.moduleBase !== 'string')) {
    invalidResponse('moduleBase must be null or a string');
  }
  for (let index = 0; index < response.scenes.length; ++index) {
    const scene = response.scenes[index];
    if (!isObject(scene) || typeof scene.name !== 'string' ||
        typeof scene.offset !== 'string' ||
        !Object.prototype.hasOwnProperty.call(scene, 'runtimeAddress') ||
        (scene.runtimeAddress !== null && typeof scene.runtimeAddress !== 'string') ||
        !Object.prototype.hasOwnProperty.call(scene, 'runtimeEnd') ||
        (scene.runtimeEnd !== null && typeof scene.runtimeEnd !== 'string') ||
        !SCENE_STATES.has(scene.state)) {
      invalidResponse('scenes[' + index + '] has an invalid status scene shape');
    }
    validateWarningArray(scene.warnings, 'scenes[' + index + '].warnings');
    if (scene.error !== undefined &&
        (!isObject(scene.error) || typeof scene.error.code !== 'string' ||
         typeof scene.error.hookError !== 'number' ||
         !Number.isInteger(scene.error.hookError))) {
      invalidResponse('scenes[' + index + '].error has an invalid shape');
    }
  }
  return response;
}

function renderWarning(owner, warning) {
  const code = warning.code ? ' [' + warning.code + ']' : '';
  return '[!] ' + owner + code + ': ' + warning.message;
}

function renderConfigureResponse(value) {
  const response = validateConfigureResponse(value);
  if (!response.ok) {
    const error = response.error || {};
    return ['[-] tracer config rejected ' + (error.code || 'UNKNOWN_ERROR') +
      ' at ' + (error.path || '$') + ': ' + (error.message || 'unknown error')];
  }

  const lines = [
    '[+] tracer config accepted schema=' + response.responseSchemaVersion +
      ' generation=' + response.generation
  ];
  for (const scene of response.scenes || []) {
    let line = '[+] scene ' + scene.name + ': offset=' + scene.offset;
    if (scene.endOffset !== null && scene.endOffset !== undefined) {
      line += ' endOffset=' + scene.endOffset;
    }
    lines.push(line);
  }
  for (const warning of response.warnings || []) {
    lines.push(renderWarning('configuration', warning));
  }
  return lines;
}

function renderStatusResponse(value, includeWaitingForModule) {
  const response = validateStatusResponse(value);
  const showWaiting = includeWaitingForModule !== false;
  if (!response.ok) {
    const error = response.error || {};
    return ['[-] status lookup failed ' + (error.code || 'UNKNOWN_ERROR') +
      ' at ' + (error.path || '$') + ': ' + (error.message || 'unknown error')];
  }

  const lines = [];
  if (response.state === 'waiting_for_module' && showWaiting) {
    lines.push('[+] waiting for ' + response.targetModule);
  }
  for (const warning of response.warnings || []) {
    lines.push(renderWarning('generation ' + response.generation, warning));
  }
  for (const scene of response.scenes || []) {
    for (const warning of scene.warnings || []) {
      lines.push(renderWarning('scene ' + scene.name, warning));
    }
    if (scene.state === 'installed') {
      const address = scene.runtimeAddress ||
        (response.targetModule + '+' + scene.offset);
      lines.push('[+] scene ' + scene.name + ' installed at ' + address);
    } else if (scene.state === 'rolled_back') {
      lines.push('[+] scene ' + scene.name + ' rolled back');
    } else if (scene.state === 'hook_failed' ||
               scene.state === 'rollback_failed') {
      const error = scene.error || {};
      let failure = '[-] scene ' + scene.name + ' ' + scene.state + ': ' +
        (error.code || 'UNKNOWN_ERROR');
      if (error.hookError !== undefined) failure += ' hookError=' + error.hookError;
      lines.push(failure);
    }
  }

  if (response.state === 'installed') {
    lines.push('[+] generation ' + response.generation + ' installed');
  } else if (response.state === 'hook_failed') {
    lines.push('[-] generation ' + response.generation +
      ' finished with hook_failed; rollback complete');
  } else if (TERMINAL_STATES.has(response.state)) {
    lines.push('[-] generation ' + response.generation +
      ' finished with ' + response.state);
  }
  return lines;
}

function pollGeneration(getStatus, schedule, emit) {
  let lastPayload = null;
  let waitingForModuleEmitted = false;

  function poll() {
    let payload;
    let status;
    try {
      payload = getStatus();
      status = validateStatusResponse(payload);
    } catch (error) {
      emit('[-] tracer status polling failed: ' + error);
      return;
    }

    if (payload !== lastPayload) {
      const includeWaiting = status.state !== 'waiting_for_module' ||
        !waitingForModuleEmitted;
      for (const line of renderStatusResponse(status, includeWaiting)) emit(line);
      if (status.state === 'waiting_for_module') waitingForModuleEmitted = true;
      lastPayload = payload;
    }
    if (!status.ok || TERMINAL_STATES.has(status.state)) return;
    schedule(poll);
  }

  poll();
}

function loadLibrary(path) {
  try {
    const module = Module.load(path);
    console.log('[+] loaded ' + path + ' base=' + module.base);
    return module;
  } catch (error) {
    console.error('[-] failed to load ' + path + ': ' + error);
    throw error;
  }
}

function findTracerExport(tracerModule, symbol) {
  if (tracerModule && typeof tracerModule.getExportByName === 'function') {
    return tracerModule.getExportByName(symbol);
  }

  if (typeof Process.getModuleByName === 'function') {
    const moduleNames = [
      tracerModule && tracerModule.name, config.loader.tracer
    ].filter(Boolean);
    for (const moduleName of moduleNames) {
      try {
        return Process.getModuleByName(moduleName).getExportByName(symbol);
      } catch (_) {
      }
    }
  }

  if (typeof Module.getExportByName === 'function') {
    for (const moduleName of [config.loader.tracer, null]) {
      try {
        const address = Module.getExportByName(moduleName, symbol);
        if (!address.isNull()) return address;
      } catch (_) {
      }
    }
  }

  if (typeof Module.getGlobalExportByName === 'function') {
    return Module.getGlobalExportByName(symbol);
  }
  throw new Error(symbol + ' export not found');
}

function configureTracer(request, tracerModule) {
  const requestSize = utf8ByteLength(request);
  if (requestSize === 0 || requestSize > MAX_JSON_BYTES) {
    throw new Error('tracer configuration must be between 1 byte and 1 MiB');
  }

  const configurePtr = findTracerExport(tracerModule, 'qbdi_tracer_configure_json');
  const configure = new NativeFunction(configurePtr, 'int32', ['pointer', 'uint64', 'pointer', 'uint64', 'pointer']);
  const nativeRequest = Memory.allocUtf8String(request);
  return callJsonAbi((response, capacity, responseSize) => configure(
    nativeRequest, new UInt64(requestSize), response, new UInt64(capacity),
    responseSize));
}

function statusReader(tracerModule, generation) {
  const statusPtr = findTracerExport(tracerModule, 'qbdi_tracer_get_status_json');
  const getStatus = new NativeFunction(statusPtr, 'int32', ['uint64', 'pointer', 'uint64', 'pointer']);
  const nativeGeneration = new UInt64(String(generation));
  return () => callJsonAbi((response, capacity, responseSize) => getStatus(
    nativeGeneration, response, new UInt64(capacity), responseSize));
}

function configureShadowHookHelper(path, tracerModule) {
  const setterPtr = findTracerExport(
    tracerModule, 'qbdi_tracer_set_shadowhook_helper_path');
  const setter = new NativeFunction(setterPtr, 'int', ['pointer']);
  if (setter(Memory.allocUtf8String(path)) !== 0) {
    throw new Error('failed to configure ShadowHook companion path: ' + path);
  }
}

function loadConfiguredTracer() {
  const dir = config.loader.remoteDir.replace(/\/$/, '');
  const tracerModule = loadLibrary(dir + '/' + config.loader.tracer);
  configureShadowHookHelper(
    dir + '/' + config.loader.shadowhookCompanion, tracerModule);
  return tracerModule;
}

function runConfigurationRetentionAcceptance() {
  const tracerModule = loadConfiguredTracer();
  const accepted = validateConfigureResponse(configureTracer(
    JSON.stringify(config.tracer), tracerModule));
  if (!accepted.ok) {
    throw new Error('valid configuration was rejected: ' + accepted.error.code);
  }

  const rejected = validateConfigureResponse(configureTracer('{', tracerModule));
  if (rejected.ok || rejected.error.code !== 'MALFORMED_JSON') {
    throw new Error('malformed configuration did not return MALFORMED_JSON');
  }

  const retained = validateStatusResponse(
    statusReader(tracerModule, accepted.generation)());
  if (!retained.ok || retained.generation !== accepted.generation) {
    throw new Error('accepted generation was not retained after rejection');
  }
  return {
    generation: accepted.generation,
    rejectedCode: rejected.error.code,
    retainedState: retained.state,
    targetModule: retained.targetModule
  };
}

function main() {
  const tracerModule = loadConfiguredTracer();

  const configurePayload = configureTracer(JSON.stringify(config.tracer), tracerModule);
  const configureResponse = validateConfigureResponse(configurePayload);
  for (const line of renderConfigureResponse(configureResponse)) console.log(line);
  if (!configureResponse.ok) return;

  const getStatus = statusReader(tracerModule, configureResponse.generation);
  pollGeneration(getStatus, callback => setTimeout(callback, 250),
    line => console.log(line));
  console.log('[+] tracer injected; tap a demo button for non-init scenes');
}

if (globalThis.__QTRACE_TEST__ !== true) {
  setImmediate(main);
}
