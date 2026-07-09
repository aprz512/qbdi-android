'use strict';

module.exports = {
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
