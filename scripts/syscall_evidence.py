"""Validate and pair optional syscall detail observations without guessing returns."""
from __future__ import annotations

import json
import re


class SyscallEvidenceError(ValueError):
    pass


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise SyscallEvidenceError("duplicate syscall detail field")
        value[key] = item
    return value


def _hex(value):
    return type(value) is str and re.fullmatch(r"0x[0-9a-f]{1,16}", value) is not None


def _validate_path(path, arguments):
    if (type(path) is not dict or set(path) != {"argument", "address", "status", "limit", "bytesHex", "display"} or
            type(path["argument"]) is not int or not 0 <= path["argument"] < 6 or
            type(path["limit"]) is not int or path["limit"] != 128 or
            path["address"] != arguments[path["argument"]] or
            type(path["status"]) is not str or path["status"] not in {"complete", "partial", "truncated", "unreadable"} or
            type(path["bytesHex"]) is not str or
            re.fullmatch(r"(?:[0-9a-f]{2}){0,128}", path["bytesHex"]) is None or
            type(path["display"]) is not str):
        raise SyscallEvidenceError("invalid syscall path snapshot")
    raw = bytes.fromhex(path["bytesHex"])
    display = "".join(chr(byte) if 0x20 <= byte < 0x7f else f"\\x{byte:02x}" for byte in raw)
    if (path["display"] != display or 0 in raw or
            (path["status"] == "unreadable" and raw) or
            (path["status"] == "partial" and not 0 < len(raw) < 128) or
            (path["status"] == "truncated" and len(raw) != 128) or
            (path["status"] == "complete" and len(raw) >= 128)):
        raise SyscallEvidenceError("inconsistent syscall path state")


def decode_syscall_detail(category, detail):
    """Legacy enters stay raw; schema 1 and 2 have exact bounded fields."""
    if category not in {"syscall-enter", "syscall-return"}:
        return None
    try:
        size = len(detail.encode("utf-8")) if type(detail) is str else 4097
    except UnicodeError as error:
        raise SyscallEvidenceError("syscall detail is not UTF-8") from error
    if size > 4096:
        raise SyscallEvidenceError("syscall detail exceeds bound")
    try:
        value = json.loads(detail, object_pairs_hook=_object)
    except (ValueError, TypeError, RecursionError) as error:
        raise SyscallEvidenceError("invalid syscall detail JSON") from error
    if type(value) is not dict:
        raise SyscallEvidenceError("syscall detail must be an object")
    if category == "syscall-enter" and "schema" not in value:
        return None
    common = {"schema", "id", "number", "pc"}
    expected = common | ({"args", "paths" if value.get("schema") == 2 else "path"} if category == "syscall-enter" else
                         {"observed", "rawReturn", "linuxErrorNumber", "reason"})
    if (set(value) != expected or type(value["schema"]) is not int or value["schema"] not in (1, 2) or
            type(value["id"]) is not int or not 0 < value["id"] < 2**64 or
            type(value["number"]) is not int or not -(2**63) <= value["number"] < 2**63 or
            not _hex(value["pc"])):
        raise SyscallEvidenceError("invalid syscall detail header")
    if category == "syscall-enter":
        if type(value["args"]) is not list or len(value["args"]) != 6 or not all(map(_hex,value["args"])):
            raise SyscallEvidenceError("invalid syscall arguments")
        if value["schema"] == 1:
            path = value["path"]
            if value["number"] != 56:
                if path is not None:
                    raise SyscallEvidenceError("unexpected syscall path")
            else:
                _validate_path(path, value["args"])
                if path["argument"] != 1:
                    raise SyscallEvidenceError("invalid legacy path argument")
        else:
            paths = value["paths"]
            if type(paths) is not list or len(paths) > 2:
                raise SyscallEvidenceError("invalid syscall path count")
            arguments = set()
            for path in paths:
                _validate_path(path, value["args"])
                if path["argument"] in arguments:
                    raise SyscallEvidenceError("duplicate syscall path argument")
                arguments.add(path["argument"])
    else:
        observed = value["observed"]
        if type(observed) is not bool:
            raise SyscallEvidenceError("invalid syscall return observation")
        if observed:
            if not _hex(value["rawReturn"]) or value["reason"] != "post_instruction":
                raise SyscallEvidenceError("invalid observed syscall return")
            raw = int(value["rawReturn"],16)
            expected_error = 2**64 - raw if raw >= 2**64 - 4095 else None
            error = value["linuxErrorNumber"]
            if error != expected_error or (error is not None and type(error) is not int):
                raise SyscallEvidenceError("inconsistent Linux error interpretation")
        elif (value["rawReturn"] is not None or value["linuxErrorNumber"] is not None or type(value["reason"]) is not str or
              value["reason"] not in {"signal_intervened","unexpected_pc","post_not_observed","capture_ended"}):
            raise SyscallEvidenceError("unobserved syscall return must stay unknown")
    return value


class _SyscallPairer:
    def __init__(self, maximum):
        if type(maximum) is not int or not 1 <= maximum <= 65536:
            raise SyscallEvidenceError("syscall entry bound must be in 1..65536")
        self.maximum = maximum
        self.calls = {}
        self.orphaned = self.legacy = 0

    def accept(self, event):
        if event.kind != "call" or event.data.get("category") not in {"syscall-enter","syscall-return"}:
            return
        if type(event.tid) is not int or event.tid <= 0 or type(event.global_seq) is not int or event.global_seq <= 0:
            raise SyscallEvidenceError("invalid syscall event identity")
        category = event.data["category"]
        value = decode_syscall_detail(category,event.data.get("detail"))
        if value is None:
            self.legacy += 1
            return
        key = (event.tid,value["id"])
        if category == "syscall-enter":
            if key in self.calls or len(self.calls) >= self.maximum:
                raise SyscallEvidenceError("duplicate or excessive syscall entries")
            self.calls[key] = {"tid":event.tid,"id":value["id"],"entry_sequence":event.global_seq,
                          "entry":value,"return":None,"return_sequence":None}
        else:
            row = self.calls.get(key)
            if row is None:
                self.orphaned += 1
                return
            if (row["return"] is not None or event.global_seq <= row["entry_sequence"] or
                    value["pc"] != row["entry"]["pc"] or value["number"] != row["entry"]["number"] or
                    value["schema"] != row["entry"]["schema"]):
                raise SyscallEvidenceError("ambiguous syscall return pairing")
            row["return"],row["return_sequence"] = value,event.global_seq

    def result(self):
        return {"calls":list(self.calls.values()),"orphaned_returns":self.orphaned,"legacy_entries":self.legacy}


def pair_syscall_events(events, maximum=4096):
    """Pair only matching TID/id in this artifact; retain missing ends as unknown."""
    pairer = _SyscallPairer(maximum)
    for event in events:
        pairer.accept(event)
    return pairer.result()


def recover_qtrb_syscalls(source, maximum=4096, *, allow_partial=False):
    """Validate a decompressed QTRB stream and pair calls in physical record order."""
    from scripts.flight_trace import FlightEvent
    from scripts.trace_binary import convert_binary_stream

    pairer = _SyscallPairer(maximum)

    def on_call(tid, ordinal, category, name, detail):
        pairer.accept(FlightEvent(ordinal, tid, "call", {"category":category,"name":name,"detail":detail}))

    class DiscardText:
        def write(self, line):
            return len(line)

    stats = convert_binary_stream(source, DiscardText(), allow_partial=allow_partial, on_call=on_call)
    return {"source_order":"qtrb_record_ordinal", "termination":stats.termination, **pairer.result()}
