'use strict';

const config = {
  shadowhookCompanion: 'libshadowhook_nothing.so',
  tracer: 'libqbdi_tracer.so',
  target: 'libdemo_target.so'
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

  let companionPath = null;
  Java.performNow(() => {
    const ActivityThread = Java.use('android.app.ActivityThread');
    const application = ActivityThread.currentApplication();
    if (application === null) throw new Error('application is not ready for tracer loading');
    const applicationInfo = application.getApplicationInfo();
    companionPath = String(applicationInfo.nativeLibraryDir.value) +
      '/' + config.shadowhookCompanion;
    const tracerPath = String(application.getFilesDir().getAbsolutePath()) + '/' + config.tracer;
    const Runtime = Java.use('java.lang.Runtime');
    Runtime.getRuntime().load0.overload('java.lang.Class', 'java.lang.String').call(
      Runtime.getRuntime(), application.getClass(), tracerPath);
  });

  const tracer = Process.findModuleByName(config.tracer);
  if (tracer === null) throw new Error('application loader did not map ' + config.tracer);
  const setter = new NativeFunction(
    findTracerExport(tracer, 'qbdi_tracer_set_shadowhook_helper_path'), 'int', ['pointer']);
  if (setter(Memory.allocUtf8String(companionPath)) !== 0) {
    throw new Error('failed to configure ShadowHook companion path: ' + companionPath);
  }
  return tracer;
}

function runProbe(targetModule) {
  const tracer = loadTracerThroughApplicationLoader();
  const entry = targetModule.getExportByName('demo_signal_probe');
  const probe = new NativeFunction(
    findTracerExport(tracer, 'qbdi_signal_probe_bits'), 'uint32', ['pointer', 'pointer']);
  const bits = probe(entry, targetModule.base);
  const result = {
    guest_handler_called: (bits & (1 << 0)) !== 0,
    guest_pc_original: (bits & (1 << 1)) !== 0,
    register_cookie: (bits & (1 << 2)) !== 0,
    qbdi_handler_untraced: (bits & (1 << 3)) === 0,
    handler_query_hidden: (bits & (1 << 4)) !== 0
  };
  const output = JSON.stringify(result);
  console.log(output);
  if (!Object.values(result).every(Boolean)) {
    throw new Error('native signal probe failed: ' + output);
  }
}

function waitForTarget() {
  const target = Process.findModuleByName(config.target);
  if (target === null) {
    setTimeout(waitForTarget, 25);
    return;
  }
  runProbe(target);
}

setImmediate(waitForTarget);
