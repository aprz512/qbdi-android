'use strict';

module.exports = {
  packageName: 'com.aprz.qbdiandroid',
  remoteDir: '/data/local/tmp/qbdi-android',
  shadowhookCompanion: 'libshadowhook_nothing.so',
  tracer: 'libqbdi_tracer.so',
  targetSo: 'libdemo_target.so',
  trace: {
    profile: 'fast',
    compression: true,
    lz4Level: 2,
    autoBuffer: true,
    bufferMb: 0,
    hexdumpLimit: 32
  },
  flight: { enabled: true, capacityMb: 512, chunkKb: 256, maxThreads: 256, protectedChunks: 4 },
  scenes: {
    init: { offset: '0x6AC90' },
    jni: { offset: '0x6DCA8' },
    libc: { offset: '0x6E204' },
    algorithm: { offset: '0x6DB38' },
    integrity: { offset: '0x0' },
    benchmark: { offset: '0x0' }
  }
};
