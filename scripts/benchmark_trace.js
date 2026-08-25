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
    const response = JSON.parse(responseBuffer.readUtf8String(responseSize - 1));
    if (response === null || typeof response !== 'object' || Array.isArray(response) ||
        response.responseSchemaVersion !== 1 || typeof response.ok !== 'boolean') {
      throw new Error('benchmark configuration returned an invalid response object');
    }
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
