"use strict";

const RESPONSE_CAPACITY = 64 * 1024;
const PATH_CAPACITY = 4096;
const POLL_INTERVAL_MS = 50;
const MAX_DETAIL_CHARS = 512;

class AgentFailure extends Error {
  constructor(stage, code, detail) {
    super(String(detail));
    this.stage = stage;
    this.code = code;
  }
}

function fail(stage, code, detail) {
  throw new AgentFailure(stage, code, detail);
}

function ownKeys(value, expected) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const wanted = expected.slice().sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function boundedDetail(value) {
  return String(value)
    .replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, " ")
    .slice(0, MAX_DETAIL_CHARS) || "agent failure";
}

function sendFailure(error) {
  const failure = error instanceof AgentFailure
    ? error
    : new AgentFailure("agent", "AGENT_INTERNAL_ERROR", error);
  send({
    type: "error",
    stage: failure.stage,
    code: failure.code,
    detail: boundedDetail(failure.message),
  });
}

function strictHex(value) {
  return typeof value === "string" && /^0x[0-9a-f]+$/.test(value);
}

function requestHex(value, location) {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]+$/.test(value)) {
    fail("request", "STARTUP_REQUEST_INVALID", `${location} is not hexadecimal`);
  }
  return BigInt(value);
}

function validateEnvelope(value) {
  if (!ownKeys(value, [
    "package", "sessionId", "tracerSo", "companion", "nativeRequest", "setupTimeoutMs",
  ])) {
    fail("request", "STARTUP_REQUEST_INVALID", "startup envelope has invalid shape");
  }
  for (const field of ["package", "sessionId", "tracerSo", "companion"]) {
    if (typeof value[field] !== "string" || value[field].length === 0) {
      fail("request", "STARTUP_REQUEST_INVALID", `${field} must be nonempty text`);
    }
  }
  if (!Number.isSafeInteger(value.setupTimeoutMs) || value.setupTimeoutMs <= 0) {
    fail("request", "STARTUP_REQUEST_INVALID", "setupTimeoutMs must be a positive integer");
  }
  const nativeRequest = value.nativeRequest;
  if (nativeRequest === null || typeof nativeRequest !== "object" || Array.isArray(nativeRequest)) {
    fail("request", "STARTUP_REQUEST_INVALID", "nativeRequest must be an object");
  }
  if (nativeRequest.packageName !== value.package) {
    fail("request", "STARTUP_REQUEST_INVALID", "native package does not match startup package");
  }
  if (typeof nativeRequest.targetModule !== "string" || nativeRequest.targetModule.length === 0) {
    fail("request", "STARTUP_REQUEST_INVALID", "native target module is invalid");
  }
  if (!ownKeys(nativeRequest.session, ["id", "durationMs"]) &&
      !ownKeys(nativeRequest.session, ["id"])) {
    fail("request", "STARTUP_REQUEST_INVALID", "native session has invalid shape");
  }
  if (nativeRequest.session.id !== value.sessionId) {
    fail("request", "STARTUP_REQUEST_INVALID", "native session does not match startup session");
  }
  if (!Array.isArray(nativeRequest.scenes) || nativeRequest.scenes.length === 0) {
    fail("request", "STARTUP_REQUEST_INVALID", "native scenes must be a nonempty array");
  }
  for (let index = 0; index < nativeRequest.scenes.length; ++index) {
    const scene = nativeRequest.scenes[index];
    if (!ownKeys(scene, ["name", "location"]) || typeof scene.name !== "string" ||
        !ownKeys(scene.location, ["offset", "endOffset"])) {
      fail("request", "STARTUP_REQUEST_INVALID", `native scene ${index} has invalid shape`);
    }
    const start = requestHex(scene.location.offset, `native scene ${index} offset`);
    const end = requestHex(scene.location.endOffset, `native scene ${index} end offset`);
    if (start <= 0n || end <= start) {
      fail("request", "STARTUP_REQUEST_INVALID", `native scene ${index} range is invalid`);
    }
  }
  return value;
}

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

function nativeUtf8(value) {
  return { allocation: Memory.allocUtf8String(value), length: utf8ByteLength(value) };
}

function decodeBoundedResponse(buffer, responseSize) {
  const numericSize = responseSize.readU64().toNumber();
  if (!Number.isSafeInteger(numericSize) || numericSize < 2 || numericSize > RESPONSE_CAPACITY) {
    fail("native", "NATIVE_RESPONSE_MALFORMED", "native response size is outside 2 through 65536 bytes");
  }
  if (buffer.add(numericSize - 1).readU8() !== 0) {
    fail("native", "NATIVE_RESPONSE_MALFORMED", "native response is not NUL terminated");
  }
  let text;
  try {
    text = buffer.readUtf8String(numericSize - 1);
  } catch (error) {
    fail("native", "NATIVE_RESPONSE_MALFORMED", `native response is not UTF-8: ${error}`);
  }
  if (typeof text !== "string" || text.indexOf("\u0000") !== -1 ||
      utf8ByteLength(text) !== numericSize - 1) {
    fail("native", "NATIVE_RESPONSE_MALFORMED", "native response length or encoding is invalid");
  }
  try {
    return JSON.parse(text);
  } catch (error) {
    fail("native", "NATIVE_RESPONSE_MALFORMED", `native response is not JSON: ${error}`);
  }
}

function callJson(nativeCall, args, transportCode) {
  const response = Memory.alloc(RESPONSE_CAPACITY);
  const responseSize = Memory.alloc(8);
  responseSize.writeU64(new UInt64(0));
  const code = nativeCall(
    ...args, response, new UInt64(RESPONSE_CAPACITY), responseSize,
  );
  if (code !== 0) {
    fail("native", transportCode, `native JSON transport returned ${code}`);
  }
  return decodeBoundedResponse(response, responseSize);
}

function normalizedSession(request) {
  return {
    id: request.session.id,
    durationMs: Object.prototype.hasOwnProperty.call(request.session, "durationMs")
      ? request.session.durationMs
      : 0,
  };
}

function validateSession(value, request) {
  const expected = normalizedSession(request);
  if (!ownKeys(value, ["id", "durationMs"]) || value.id !== expected.id ||
      value.durationMs !== expected.durationMs || !Number.isSafeInteger(value.durationMs)) {
    fail("native", "NATIVE_RESPONSE_MALFORMED", "native session does not match the request");
  }
}

function validateHeader(value, request, generation, final) {
  const keys = [
    "responseSchemaVersion", "ok", "generation", "state", "targetModule",
    "session", "scenes", "warnings",
  ];
  if (final) keys.push("moduleBase");
  if (!ownKeys(value, keys)) {
    fail("native", "NATIVE_RESPONSE_MALFORMED", "native response has invalid shape");
  }
  if (value.responseSchemaVersion !== 1 || value.ok !== true ||
      !Number.isSafeInteger(value.generation) || value.generation <= 0 ||
      (generation !== null && value.generation !== generation) ||
      value.targetModule !== request.targetModule || !Array.isArray(value.warnings)) {
    fail("native", "NATIVE_RESPONSE_MALFORMED", "native response header is invalid");
  }
  validateSession(value.session, request);
}

function nativeRejection(value, stage, code) {
  if (!ownKeys(value, ["responseSchemaVersion", "ok", "error"]) ||
      value.responseSchemaVersion !== 1 || value.ok !== false ||
      !ownKeys(value.error, ["code", "path", "message"]) ||
      typeof value.error.code !== "string" || typeof value.error.path !== "string" ||
      typeof value.error.message !== "string") {
    fail("native", "NATIVE_RESPONSE_MALFORMED", "native rejection has invalid shape");
  }
  fail(stage, code, `${value.error.code} at ${value.error.path}: ${value.error.message}`);
}

function validateInitialized(value, request) {
  if (value !== null && typeof value === "object" && value.ok === false) {
    nativeRejection(value, "configure", "NATIVE_CONFIG_REJECTED");
  }
  validateHeader(value, request, null, false);
  if (value.state !== "waiting_for_module" || value.scenes.length !== request.scenes.length) {
    fail("native", "NATIVE_RESPONSE_MALFORMED", "initial native state or scenes are invalid");
  }
  for (let index = 0; index < value.scenes.length; ++index) {
    const actual = value.scenes[index];
    const expected = request.scenes[index];
    if (!ownKeys(actual, ["name", "offset", "endOffset"]) ||
        actual.name !== expected.name || !strictHex(actual.offset) ||
        !strictHex(actual.endOffset) ||
        BigInt(actual.offset) !== requestHex(expected.location.offset, "scene offset") ||
        BigInt(actual.endOffset) !== requestHex(expected.location.endOffset, "scene end offset")) {
      fail("native", "NATIVE_RESPONSE_MALFORMED", "initialized scenes do not match the request");
    }
  }
  return value;
}

function validRuntimeAddress(value) {
  return value === null || strictHex(value);
}

function validateStatus(value, request, initialized) {
  if (value !== null && typeof value === "object" && value.ok === false) {
    nativeRejection(value, "status", "NATIVE_STATUS_REJECTED");
  }
  validateHeader(value, request, initialized.generation, true);
  if (!validRuntimeAddress(value.moduleBase) || value.scenes.length !== initialized.scenes.length) {
    fail("native", "NATIVE_RESPONSE_MALFORMED", "native status module or scenes are invalid");
  }
  const continuing = value.state === "waiting_for_module" || value.state === "installing";
  const terminal = value.state === "hook_failed" || value.state === "rollback_failed" ||
    value.state === "superseded";
  if (!continuing && !terminal && value.state !== "installed") {
    fail("native", "NATIVE_RESPONSE_MALFORMED", "native status state is invalid");
  }
  for (let index = 0; index < value.scenes.length; ++index) {
    const actual = value.scenes[index];
    const expected = initialized.scenes[index];
    const allowed = ["name", "offset", "runtimeAddress", "runtimeEnd", "state", "warnings"];
    if (Object.prototype.hasOwnProperty.call(actual, "error")) allowed.push("error");
    if (!ownKeys(actual, allowed) || actual.name !== expected.name ||
        actual.offset !== expected.offset || !validRuntimeAddress(actual.runtimeAddress) ||
        !validRuntimeAddress(actual.runtimeEnd) || typeof actual.state !== "string" ||
        !Array.isArray(actual.warnings)) {
      fail("native", "NATIVE_RESPONSE_MALFORMED", "native status scenes do not match initialization");
    }
    if (value.state === "installed" && actual.state !== "installed") {
      fail("native", "NATIVE_RESPONSE_MALFORMED", "installed generation contains a non-installed scene");
    }
  }
  return { value, continuing, terminal };
}

function exportFrom(module, name) {
  try {
    return module.getExportByName(name);
  } catch (error) {
    fail("load", "TRACER_LOAD_FAILED", `tracer export ${name} is unavailable: ${error}`);
  }
}

function canonicalFile(realpathCall, path, stage, code, label) {
  const output = Memory.alloc(PATH_CAPACITY);
  let result;
  try {
    result = realpathCall(Memory.allocUtf8String(path), output);
  } catch (error) {
    fail(stage, code, `${label} staged path canonicalization failed: ${error}`);
  }
  if (result.isNull()) {
    fail(stage, code, `${label} staged path cannot be canonicalized`);
  }
  let canonical;
  try {
    canonical = output.readUtf8String();
  } catch (error) {
    fail(stage, code, `${label} canonical path is not UTF-8: ${error}`);
  }
  if (typeof canonical !== "string" || !canonical.startsWith("/") ||
      canonical.indexOf("\u0000") !== -1) {
    fail(stage, code, `${label} canonical path is invalid`);
  }
  return canonical;
}

function parentDirectory(path) {
  const separator = path.lastIndexOf("/");
  return separator > 0 ? path.slice(0, separator) : null;
}

function start(rawEnvelope) {
  const envelope = validateEnvelope(rawEnvelope);
  const deadline = Date.now() + envelope.setupTimeoutMs;
  let realpathCall;
  try {
    realpathCall = new NativeFunction(
      Module.getGlobalExportByName("realpath"),
      "pointer",
      ["pointer", "pointer"],
    );
  } catch (error) {
    fail("load", "TRACER_LOAD_FAILED", `realpath is unavailable: ${error}`);
  }
  const tracerPath = canonicalFile(
    realpathCall, envelope.tracerSo, "load", "TRACER_LOAD_FAILED", "tracer",
  );
  const companionPath = canonicalFile(
    realpathCall, envelope.companion, "companion", "COMPANION_CONFIG_FAILED", "companion",
  );
  if (parentDirectory(tracerPath) === null ||
      parentDirectory(tracerPath) !== parentDirectory(companionPath)) {
    fail(
      "companion",
      "COMPANION_CONFIG_FAILED",
      "canonical staged libraries do not share a directory",
    );
  }
  let tracer;
  try {
    tracer = Module.load(tracerPath);
  } catch (error) {
    fail("load", "TRACER_LOAD_FAILED", `authoritative tracer load failed: ${error}`);
  }

  const setCompanion = new NativeFunction(
    exportFrom(tracer, "qbdi_tracer_set_shadowhook_helper_path"),
    "int",
    ["pointer"],
  );
  const configure = new NativeFunction(
    exportFrom(tracer, "qbdi_tracer_configure_json"),
    "int",
    ["pointer", "uint64", "pointer", "uint64", "pointer"],
  );
  const getStatus = new NativeFunction(
    exportFrom(tracer, "qbdi_tracer_get_status_json"),
    "int",
    ["uint64", "pointer", "uint64", "pointer"],
  );

  const companionPathAllocation = Memory.allocUtf8String(companionPath);
  if (setCompanion(companionPathAllocation) !== 0) {
    fail("companion", "COMPANION_CONFIG_FAILED", "native companion path was rejected");
  }

  let requestText;
  try {
    requestText = JSON.stringify(envelope.nativeRequest);
  } catch (error) {
    fail("request", "STARTUP_REQUEST_INVALID", `native request cannot be serialized: ${error}`);
  }
  const request = nativeUtf8(requestText);
  const initialized = validateInitialized(
    callJson(
      configure,
      [request.allocation, new UInt64(request.length)],
      "NATIVE_CONFIG_TRANSPORT_FAILED",
    ),
    envelope.nativeRequest,
  );
  send({
    type: "initialized",
    sessionId: envelope.sessionId,
    generation: initialized.generation,
    status: initialized,
  });

  function poll() {
    try {
      if (Date.now() >= deadline) {
        fail("status", "HOOK_INSTALL_TIMEOUT", "native generation did not install before the setup deadline");
      }
      const checked = validateStatus(
        callJson(
          getStatus,
          [new UInt64(initialized.generation)],
          "NATIVE_STATUS_TRANSPORT_FAILED",
        ),
        envelope.nativeRequest,
        initialized,
      );
      if (checked.value.state === "installed") {
        send({
          type: "installed",
          sessionId: envelope.sessionId,
          generation: initialized.generation,
          status: checked.value,
        });
        return;
      }
      if (checked.terminal) {
        fail("status", "HOOK_INSTALL_FAILED", `native generation ended as ${checked.value.state}`);
      }
      setTimeout(poll, Math.min(POLL_INTERVAL_MS, Math.max(1, deadline - Date.now())));
    } catch (error) {
      sendFailure(error);
    }
  }

  setTimeout(poll, Math.min(POLL_INTERVAL_MS, Math.max(1, deadline - Date.now())));
}

recv("qtrace-startup", (message) => {
  try {
    if (!ownKeys(message, ["type", "payload"]) || message.type !== "qtrace-startup") {
      fail("request", "STARTUP_REQUEST_INVALID", "startup message has invalid shape");
    }
    start(message.payload);
  } catch (error) {
    sendFailure(error);
  }
});
