'use strict';

// Frida -l executes this source inside the spawned target process.
const config = {
  remoteDir: '/data/local/tmp/qbdi-android',
  tracer: 'libqbdi_tracer.so',
  targetSo: 'libdemo_target.so',
  iterations: 256,
  seed: '0x514244492d626173'
};

function findTracerExport(tracerModule, symbol) {
  if (typeof tracerModule.getExportByName === 'function') {
    return tracerModule.getExportByName(symbol);
  }
  return Module.getGlobalExportByName(symbol);
}

function startBenchmark(targetModule) {
  try {
    const benchmark = targetModule.getExportByName('demo_benchmark_case');
    const offset = benchmark.sub(targetModule.base);
    const tracer = Module.load(config.remoteDir + '/' + config.tracer);
    const configure = new NativeFunction(
      findTracerExport(tracer, 'qbdi_tracer_configure'), 'void', ['pointer']);
    const install = new NativeFunction(
      findTracerExport(tracer, 'qbdi_tracer_install_module'), 'void', ['pointer', 'pointer', 'pointer']);
    configure(Memory.allocUtf8String(
      'target=' + config.targetSo + ';scene=benchmark,0x' + offset.toString(16)));
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
