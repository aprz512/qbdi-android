'use strict';

function jsonCall(fn, args) {
  const capacity = 64 * 1024;
  const output = Memory.alloc(capacity);
  const size = Memory.alloc(8);
  size.writeU64(0);
  const code = fn(...args, output, new UInt64(capacity), size);
  if (code !== 0) throw new Error('JSON ABI transport: ' + code);
  return JSON.parse(output.readUtf8String(size.readU64().toNumber() - 1));
}

function canonicalPath(path) {
  const realpath = new NativeFunction(Module.getGlobalExportByName('realpath'),
    'pointer', ['pointer', 'pointer']);
  const output = Memory.alloc(4096);
  const resolved = realpath(Memory.allocUtf8String(path), output);
  if (resolved.isNull()) throw new Error('realpath failed');
  return resolved.readUtf8String();
}

rpc.exports = {
  run(input) {
    const result = {pid: Process.id, mode: input.mode};
    const tracerPath = canonicalPath(input.tracerSo);
    const tracer = Module.load(tracerPath);
    result.canonicalTracerPath = tracerPath;
    const setCompanion = new NativeFunction(
      tracer.getExportByName('qbdi_tracer_set_shadowhook_helper_path'), 'int', ['pointer']);
    result.companionResult = setCompanion(Memory.allocUtf8String(canonicalPath(input.companion)));
    if (result.companionResult !== 0) throw new Error('companion rejected');
    if (input.helper) {
      const helper = Module.load(canonicalPath(input.helper));
      const begin = new NativeFunction(helper.getExportByName('qguard_probe_start'), 'int', ['pointer', 'int']);
      result.guardProbe = begin(Memory.allocUtf8String(tracerPath), input.guardMode || 0);
      if (result.guardProbe !== 0) throw new Error('guard probe failed: ' + result.guardProbe);
    }
    if (input.mode === 'load') return result;
    const configure = new NativeFunction(
      tracer.getExportByName('qbdi_tracer_configure_json'), 'int32',
      ['pointer', 'uint64', 'pointer', 'uint64', 'pointer']);
    const text = JSON.stringify(input.nativeRequest);
    const allocation = Memory.allocUtf8String(text);
    result.configuration = jsonCall(configure, [allocation, new UInt64(text.length)]);
    if (result.configuration.ok !== true || result.configuration.state !== 'waiting_for_module') {
      throw new Error('native configuration rejected: ' + JSON.stringify(result.configuration));
    }
    return result;
  }
};
