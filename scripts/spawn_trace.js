'use strict';

// Frida -l executes this file in the target process, without Node require().
// Keep this config in sync with scripts/trace_config.js after finding offsets.
const config = {
  packageName: 'com.aprz.qbdiandroid',
  remoteDir: '/data/local/tmp/qbdi-android',
  tracer: 'libqbdi_tracer.so',
  targetSo: 'libdemo_target.so',
  scenes: {
    init: { offset: '0x6AC90' },
    jni: { offset: '0x6DCA8' },
    libc: { offset: '0x6E204' },
    algorithm: { offset: '0x6DB38' },
    integrity: { offset: '0x6E584' }
  }
};

let moduleObserver = null;

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
    parts.push(['scene=' + name, scene.offset].join(','));
  }
  return parts.join(';');
}

function findTracerExport(tracerModule, symbol) {
  if (tracerModule && typeof tracerModule.getExportByName === 'function') {
    return tracerModule.getExportByName(symbol);
  }

  if (typeof Process.getModuleByName === 'function') {
    const moduleNames = [tracerModule && tracerModule.name, config.tracer].filter(Boolean);
    for (const moduleName of moduleNames) {
      try {
        return Process.getModuleByName(moduleName).getExportByName(symbol);
      } catch (_) {
      }
    }
  }

  if (typeof Module.getExportByName === 'function') {
    const moduleNames = [config.tracer, null];
    for (const moduleName of moduleNames) {
      try {
        const ptr = Module.getExportByName(moduleName, symbol);
        if (!ptr.isNull()) return ptr;
      } catch (_) {
      }
    }
  }

  if (typeof Module.getGlobalExportByName === 'function') {
    return Module.getGlobalExportByName(symbol);
  }

  throw new Error(symbol + ' export not found');
}

function configureTracer(encoded, tracerModule) {
  const configurePtr = findTracerExport(tracerModule, 'qbdi_tracer_configure');
  const configure = new NativeFunction(configurePtr, 'void', ['pointer']);
  const nativeConfig = Memory.allocUtf8String(encoded);
  configure(nativeConfig);
  console.log('[+] tracer configured: ' + encoded);
}

function installModuleObserver(tracerModule) {
  const installPtr = findTracerExport(tracerModule, 'qbdi_tracer_install_module');
  const installModule = new NativeFunction(installPtr, 'void', ['pointer', 'pointer', 'pointer']);

  function maybeInstall(module) {
    if (module.name !== config.targetSo) return;
    const path = module.path || module.name;
    installModule(Memory.allocUtf8String(path), module.base, ptr(module.size));
    console.log('[+] install requested for ' + module.name + ' base=' + module.base + ' size=0x' + module.size.toString(16));
  }

  moduleObserver = Process.attachModuleObserver({
    onAdded(module) {
      maybeInstall(module);
    }
  });
}

function main() {
  const dir = config.remoteDir.replace(/\/$/, '');
  const tracerModule = loadLibrary(dir + '/' + config.tracer);
  configureTracer(encodeConfig(config), tracerModule);
  installModuleObserver(tracerModule);
  console.log('[+] tracer injected; tap a demo button for non-init scenes');
}

setImmediate(main);
