'use strict';

// Frida -l executes this source inside the spawned target process.
const config = {
  shadowhookCompanion: 'libshadowhook_nothing.so',
  tracer: 'libqbdi_tracer.so',
  iterations: 256,
  seed: '0x514244492d626173'
};
const request = __QTRACE_CONFIG_JSON__;
const RESPONSE_CAPACITY = 64 * 1024;

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

function invalidResponse(message) {
  throw new Error('benchmark configuration returned an invalid response: ' + message);
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

function validateConfigureResponse(response) {
  if (!isObject(response)) invalidResponse('root must be an object');
  if (response.responseSchemaVersion !== 1) {
    invalidResponse('responseSchemaVersion must equal 1');
  }
  if (typeof response.ok !== 'boolean') invalidResponse('ok must be a boolean');
  if (!response.ok) {
    const error = response.error;
    if (!isObject(error) || typeof error.code !== 'string' ||
        typeof error.path !== 'string' || typeof error.message !== 'string') {
      invalidResponse('error must contain string code, path, and message');
    }
    return response;
  }
  if (typeof response.generation !== 'number' ||
      !Number.isInteger(response.generation) || response.generation <= 0) {
    invalidResponse('generation must be a positive integer');
  }
  if (response.state !== 'waiting_for_module') {
    invalidResponse('configure state must be waiting_for_module');
  }
  if (typeof response.targetModule !== 'string' || response.targetModule.length === 0) {
    invalidResponse('targetModule must be a non-empty string');
  }
  if (response.targetModule !== request.targetModule) {
    invalidResponse('targetModule does not match the submitted request');
  }
  if (!Array.isArray(response.scenes)) invalidResponse('scenes must be an array');
  validateWarningArray(response.warnings, 'warnings');
  for (let index = 0; index < response.scenes.length; ++index) {
    const scene = response.scenes[index];
    if (!isObject(scene) || typeof scene.name !== 'string' ||
        typeof scene.offset !== 'string' ||
        !Object.prototype.hasOwnProperty.call(scene, 'endOffset') ||
        (scene.endOffset !== null && typeof scene.endOffset !== 'string')) {
      invalidResponse('scenes[' + index + '] has an invalid normalized scene shape');
    }
  }
  if (!Array.isArray(request.scenes) || request.scenes.length !== 1 ||
      response.scenes.length !== 1) {
    invalidResponse('scenes must contain exactly the submitted benchmark scene');
  }
  const expectedScene = request.scenes[0];
  const expectedEndOffset = Object.prototype.hasOwnProperty.call(
    expectedScene.location, 'endOffset') ? expectedScene.location.endOffset : null;
  const scene = response.scenes[0];
  if (scene.name !== expectedScene.name ||
      scene.offset !== expectedScene.location.offset ||
      scene.endOffset !== expectedEndOffset) {
    invalidResponse('normalized benchmark scene does not match the submitted request');
  }
  return response;
}

function findTracerExport(tracerModule, symbol) {
  if (typeof tracerModule.getExportByName === 'function') {
    return tracerModule.getExportByName(symbol);
  }
  return Module.getGlobalExportByName(symbol);
}

function loadTracerThroughApplicationLoader() {
  if (!Java.available) {
    throw new Error('Java runtime is required to load the tracer through the application loader');
  }

  let companionPath = null;
  Java.performNow(() => {
    const ActivityThread = Java.use('android.app.ActivityThread');
    const application = ActivityThread.currentApplication();
    if (application === null) {
      throw new Error('application is not ready for tracer loading');
    }
    const applicationInfo = application.getApplicationInfo();
    companionPath = String(applicationInfo.nativeLibraryDir.value) +
      '/' + config.shadowhookCompanion;
    const tracerPath = String(application.getFilesDir().getAbsolutePath()) + '/' + config.tracer;
    const Runtime = Java.use('java.lang.Runtime');
    Runtime.getRuntime().load0.overload('java.lang.Class', 'java.lang.String').call(
      Runtime.getRuntime(), application.getClass(), tracerPath);
  });

  const tracer = Process.findModuleByName(config.tracer);
  if (tracer === null) {
    throw new Error('application loader did not map ' + config.tracer);
  }
  const setter = new NativeFunction(
    findTracerExport(tracer, 'qbdi_tracer_set_shadowhook_helper_path'), 'int', ['pointer']);
  if (setter(Memory.allocUtf8String(companionPath)) !== 0) {
    throw new Error('failed to configure ShadowHook companion path: ' + companionPath);
  }
  return tracer;
}

function startBenchmark(targetModule) {
  try {
    const benchmark = targetModule.getExportByName('demo_benchmark_case');
    const offset = benchmark.sub(targetModule.base);
    const tracer = loadTracerThroughApplicationLoader();
    const configure = new NativeFunction(
      findTracerExport(tracer, 'qbdi_tracer_configure_json'), 'int32',
      ['pointer', 'uint64', 'pointer', 'uint64', 'pointer']);
    const install = new NativeFunction(
      findTracerExport(tracer, 'qbdi_tracer_install_module'), 'void', ['pointer', 'pointer', 'pointer']);
    request.scenes[0].location.offset = '0x' + offset.toString(16);
    const encoded = JSON.stringify(request);
    const responseBuffer = Memory.alloc(RESPONSE_CAPACITY);
    const responseSizeBuffer = Memory.alloc(8);
    responseSizeBuffer.writeU64(new UInt64(0));
    const transportCode = configure(
      Memory.allocUtf8String(encoded), new UInt64(utf8ByteLength(encoded)),
      responseBuffer, new UInt64(RESPONSE_CAPACITY), responseSizeBuffer);
    if (transportCode !== 0) {
      throw new Error('benchmark configuration transport failed with code ' + transportCode);
    }
    const responseSize = responseSizeBuffer.readU64().toNumber();
    if (responseSize === 0 || responseSize > RESPONSE_CAPACITY ||
        responseBuffer.add(responseSize - 1).readU8() !== 0) {
      throw new Error('benchmark configuration returned an invalid response');
    }
    const response = validateConfigureResponse(
      JSON.parse(responseBuffer.readUtf8String(responseSize - 1)));
    if (response.ok !== true) {
      const code = response && response.error && response.error.code;
      throw new Error('benchmark configuration rejected: ' + (code || 'unknown error'));
    }
    install(Memory.allocUtf8String(targetModule.path), targetModule.base, ptr(targetModule.size));

    const call = new NativeFunction(benchmark, 'uint64', ['uint64', 'uint64']);
    const returned = call(new UInt64(config.iterations), new UInt64(config.seed));
    send({type: 'benchmark-result', return: '0x' + returned.toString(16), offset: offset.toString()});
  } catch (error) {
    send({type: 'benchmark-error', error: String(error)});
  }
}

function waitForTarget() {
  const loaded = Process.findModuleByName(request.targetModule);
  if (loaded !== null) {
    startBenchmark(loaded);
    return;
  }
  setTimeout(waitForTarget, 25);
}

setImmediate(waitForTarget);
