'use strict';

// Frida -l executes this source inside the spawned target process.
const config = {
  tracer: 'libqbdi_tracer.so',
  targetSo: 'libdemo_target.so',
  profile: '__QTRACE_PROFILE__',
  compression: '__QTRACE_COMPRESSION__',
  iterations: 256,
  seed: '0x514244492d626173'
};

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

  Java.performNow(() => {
    const ActivityThread = Java.use('android.app.ActivityThread');
    const application = ActivityThread.currentApplication();
    if (application === null) {
      throw new Error('application is not ready for tracer loading');
    }
    const tracerPath = String(application.getFilesDir().getAbsolutePath()) + '/' + config.tracer;
    const Runtime = Java.use('java.lang.Runtime');
    Runtime.getRuntime().load0.overload('java.lang.Class', 'java.lang.String').call(
      Runtime.getRuntime(), application.getClass(), tracerPath);
  });

  const tracer = Process.findModuleByName(config.tracer);
  if (tracer === null) {
    throw new Error('application loader did not map ' + config.tracer);
  }
  return tracer;
}

function startBenchmark(targetModule) {
  try {
    const benchmark = targetModule.getExportByName('demo_benchmark_case');
    const offset = benchmark.sub(targetModule.base);
    const tracer = loadTracerThroughApplicationLoader();
    const configure = new NativeFunction(
      findTracerExport(tracer, 'qbdi_tracer_configure'), 'void', ['pointer']);
    const install = new NativeFunction(
      findTracerExport(tracer, 'qbdi_tracer_install_module'), 'void', ['pointer', 'pointer', 'pointer']);
    configure(Memory.allocUtf8String(
      'target=' + config.targetSo + ';scene=benchmark,0x' + offset.toString(16) +
      ';profile=' + config.profile + ';compression=' + config.compression +
      '__QTRACE_TEST_CONFIG__'));
    install(Memory.allocUtf8String(targetModule.path), targetModule.base, ptr(targetModule.size));

    const call = new NativeFunction(benchmark, 'uint64', ['uint64', 'uint64']);
    const returned = call(new UInt64(config.iterations), new UInt64(config.seed));
    send({type: 'benchmark-result', return: '0x' + returned.toString(16), offset: offset.toString()});
  } catch (error) {
    send({type: 'benchmark-error', error: String(error)});
  }
}

function waitForTarget() {
  const loaded = Process.findModuleByName(config.targetSo);
  if (loaded !== null) {
    startBenchmark(loaded);
    return;
  }
  setTimeout(waitForTarget, 25);
}

setImmediate(waitForTarget);
