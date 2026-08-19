'use strict';

module.exports = {
  packageName: 'com.aprz.qbdiandroid',
  remoteDir: '/data/local/tmp/qbdi-android',
  tracer: 'libqbdi_tracer.so',
  targetSo: 'libdemo_target.so',
  scenes: {
    init: { offset: '0x6AC90' },
    jni: { offset: '0x6DCA8' },
    libc: { offset: '0x6E204' },
    algorithm: { offset: '0x6DB38' },
    integrity: { offset: '0x0' },
    benchmark: { offset: '0x0' }
  }
};
