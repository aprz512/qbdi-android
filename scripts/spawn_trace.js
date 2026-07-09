'use strict';

// Frida -l executes this file in the target process, without Node require().
// Keep this config in sync with scripts/trace_config.js after finding offsets.
const config = {
  packageName: 'com.aprz.qbdiandroid',
  remoteDir: '/data/local/tmp/qbdi-android',
  shadowhook: 'libshadowhook.so',
  tracer: 'libqbdi_tracer.so',
  targetSo: 'libdemo_target.so',
  scenes: {
    init: { offset: '0x0', bypass: [] },
    jni: { offset: '0x0', bypass: [] },
    libc: { offset: '0x0', bypass: [] },
    algorithm: { offset: '0x0', bypass: [] },
    integrity: { offset: '0x0', bypass: ['text_restore', 'maps_sanitize'] }
  }
};

function loadLibrary(path) {
  try {
    const module = Module.load(path);
    console.log('[+] loaded ' + path + ' base=' + module.base);
    return module;
  } catch (e) {
    console.error('[-] failed to load ' + path + ': ' + e);
    throw e;
  }
}

function encodeConfig(cfg) {
  const parts = ['package=' + cfg.packageName, 'target=' + cfg.targetSo];
  for (const [name, scene] of Object.entries(cfg.scenes)) {
    parts.push(['scene=' + name, scene.offset].concat(scene.bypass).join(','));
  }
  return parts.join(';');
}

function findConfigureExport() {
  const candidates = [config.tracer, null];
  for (const moduleName of candidates) {
    try {
      const ptr = Module.getExportByName(moduleName, 'qbdi_tracer_configure');
      if (!ptr.isNull()) return ptr;
    } catch (_) {
    }
  }
  throw new Error('qbdi_tracer_configure export not found');
}

function configureTracer(encoded) {
  const configurePtr = findConfigureExport();
  const configure = new NativeFunction(configurePtr, 'void', ['pointer']);
  const nativeConfig = Memory.allocUtf8String(encoded);
  configure(nativeConfig);
  console.log('[+] tracer configured: ' + encoded);
}

function main() {
  const dir = config.remoteDir.replace(/\/$/, '');
  loadLibrary(dir + '/' + config.shadowhook);
  loadLibrary(dir + '/' + config.tracer);
  configureTracer(encodeConfig(config));
  console.log('[+] tracer injected; tap a demo button for non-init scenes');
}

setImmediate(main);
