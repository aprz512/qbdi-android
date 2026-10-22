import io
import json
import struct
import unittest

from scripts.flight_trace import FlightEvent, recover_flight
from scripts.syscall_evidence import SyscallEvidenceError, decode_syscall_detail, pair_syscall_events, recover_qtrb_syscalls
from scripts.tests.test_flight_trace import artifact, chunk, core_records, directory_entry, flight_record, string_definition
from scripts.tests.test_trace_binary import complete_stream, call
from scripts.trace_binary import convert_binary_stream


def entry(id=1):
    return {"schema":1,"id":id,"number":56,"pc":"0x1000","args":["0x0","0x2000",*(["0x0"]*4)],
            "path":{"argument":1,"address":"0x2000","status":"complete","limit":128,
                    "bytesHex":b"/dev/null".hex(),"display":"/dev/null"}}


def returned(id=1):
    return {"schema":1,"id":id,"number":56,"pc":"0x1000","observed":True,
            "rawReturn":"0xfffffffffffffff2","linuxErrorNumber":14,"reason":"post_instruction"}


def event(sequence, category, value, tid=42):
    return FlightEvent(sequence,tid,"call",{"category":category,"name":"svc","detail":json.dumps(value)})


class SyscallEvidenceTests(unittest.TestCase):
    def test_schema_two_double_paths_pair_in_qtrb_and_keep_legacy_reading(self):
        entered = entry()
        path = entered.pop("path")
        entered.update(schema=2, number=38, paths=[path, {**path,"argument":3,"address":"0x3000"}])
        entered["args"][3] = "0x3000"
        finished = {**returned(), "schema":2, "number":38}
        raw = complete_stream(call("syscall-enter","svc",json.dumps(entered)),
                              call("syscall-return","svc",json.dumps(finished)))
        result = recover_qtrb_syscalls(io.BytesIO(raw))
        self.assertEqual("qtrb_record_ordinal",result["source_order"])
        self.assertEqual(entered,result["calls"][0]["entry"])
        self.assertEqual(finished,result["calls"][0]["return"])
        for paths in ([path,path], [path]*3, [{**path,"argument":6}], [{**path,"address":"0x1"}]):
            with self.subTest(paths=paths),self.assertRaises(SyscallEvidenceError):
                decode_syscall_detail("syscall-enter",json.dumps({**entered,"paths":paths}))
        with self.assertRaises(SyscallEvidenceError):
            pair_syscall_events([event(1,"syscall-enter",entry()),event(2,"syscall-return",{**returned(),"schema":2})])

    def test_qtrb_missing_return_and_bad_terminal_do_not_create_evidence(self):
        raw=complete_stream(call("syscall-enter","svc",json.dumps(entry())))
        self.assertIsNone(recover_qtrb_syscalls(io.BytesIO(raw))["calls"][0]["return"])
        from scripts.trace_binary import BinaryTraceError
        with self.assertRaises(BinaryTraceError):
            recover_qtrb_syscalls(io.BytesIO(raw+b"bad"))

    def test_legacy_entry_is_preserved_without_inventing_return(self):
        legacy={"number":56,"pc":"0x1000","args":["0x0"]*6}
        result=pair_syscall_events([event(1,"syscall-enter",legacy)])
        self.assertEqual([],result["calls"])
        self.assertEqual(1,result["legacy_entries"])

    def test_concurrent_threads_and_missing_entry_do_not_cross_pair(self):
        events=[event(1,"syscall-enter",entry(),42),event(2,"syscall-enter",entry(),43),
                event(3,"syscall-return",returned(),43),event(4,"syscall-return",returned(8),42)]
        result=pair_syscall_events(events)
        self.assertEqual(1,result["orphaned_returns"])
        self.assertIsNone(result["calls"][0]["return"])
        self.assertTrue(result["calls"][1]["return"]["observed"])

    def test_missing_and_explicitly_unobserved_returns_stay_unknown(self):
        unknown={**returned(),"observed":False,"rawReturn":None,"linuxErrorNumber":None,"reason":"signal_intervened"}
        result=pair_syscall_events([event(1,"syscall-enter",entry()),event(2,"syscall-return",unknown)])
        self.assertFalse(result["calls"][0]["return"]["observed"])
        self.assertIsNone(pair_syscall_events([event(1,"syscall-enter",entry())])["calls"][0]["return"])
        unknown["rawReturn"]="0x0"
        with self.assertRaises(SyscallEvidenceError):
            decode_syscall_detail("syscall-return",json.dumps(unknown))

    def test_duplicate_identity_mismatch_and_budget_fail_explicitly(self):
        for events in ([event(1,"syscall-enter",entry()),event(2,"syscall-enter",entry())],
                       [event(1,"syscall-enter",entry()),event(2,"syscall-return",{**returned(),"pc":"0x1004"})],
                       [event(1,"syscall-enter",entry()),event(2,"syscall-return",returned()),event(3,"syscall-return",returned())]):
            with self.assertRaises(SyscallEvidenceError):
                pair_syscall_events(events)
        with self.assertRaises(SyscallEvidenceError):
            pair_syscall_events([event(1,"syscall-enter",entry()),event(2,"syscall-enter",entry(2))],maximum=1)

    def test_strict_types_fields_duplicates_and_interpreted_errors(self):
        for value in ({**returned(),"observed":1},{**returned(),"schema":True},
                      {**returned(),"linuxErrorNumber":2},{**returned(),"extra":0},
                      {**returned(),"id":2**64},{**returned(),"rawReturn":"0x10000000000000000"}):
            with self.subTest(value=value),self.assertRaises(SyscallEvidenceError):
                decode_syscall_detail("syscall-return",json.dumps(value))
        with self.assertRaises(SyscallEvidenceError):
            decode_syscall_detail("syscall-return",json.dumps(returned())[:-1]+',"id":2}')

    def test_path_states_preserve_raw_bytes_and_reject_false_completeness(self):
        for status,raw in (("complete",b"/dev/null"),("partial",b"/dev"),("unreadable",b""),("truncated",b"q"*128)):
            value=entry()
            value["path"].update(status=status,bytesHex=raw.hex(),display=raw.decode())
            self.assertEqual(status,decode_syscall_detail("syscall-enter",json.dumps(value))["path"]["status"])
        for changes in ({"status":"complete","bytesHex":b"q".hex()*128,"display":"q"*128},
                        {"display":"wrong"},{"status":[]},{"limit":True},{"argument":True},
                        {"bytesHex":"00","display":"\\x00"}):
            value=entry();value["path"].update(changes)
            with self.subTest(changes=changes),self.assertRaises(SyscallEvidenceError):
                decode_syscall_detail("syscall-enter",json.dumps(value))

    def test_flight_generic_call_transport_keeps_new_detail_json_lossless(self):
        entered,finished=json.dumps(entry()).encode(),json.dumps(returned()).encode()
        records=core_records(42)+[
            flight_record(6,3,string_definition(1,b"syscall-enter"),flags=3),
            flight_record(6,4,string_definition(2,b"svc"),flags=3),
            flight_record(6,5,string_definition(3,entered),flags=3),
            flight_record(6,6,struct.pack("<III",1,2,3)),
            flight_record(6,7,string_definition(4,b"syscall-return"),flags=3),
            flight_record(6,8,string_definition(5,finished),flags=3),
            flight_record(6,9,struct.pack("<III",4,2,5))]
        raw=artifact(directories=[directory_entry(42,1,9,0,1)],chunks=[chunk(0,42,1,records)])
        result=pair_syscall_events(recover_flight(io.BytesIO(raw)).merged)
        self.assertEqual(entry(),result["calls"][0]["entry"])
        self.assertEqual(returned(),result["calls"][0]["return"])

    def test_qtrb_generic_call_transport_keeps_detail_without_wire_change(self):
        detail=json.dumps(entry())
        raw=complete_stream(call("syscall-enter","svc",detail))
        output=io.StringIO()
        convert_binary_stream(io.BytesIO(raw),output)
        calls=[line for line in output.getvalue().splitlines() if line.startswith("CALL ")]
        self.assertEqual(1,len(calls))
        self.assertIn('category="syscall-enter"',calls[0])
        self.assertEqual(entry(),json.loads(json.loads(calls[0].split(" detail=",1)[1])))


if __name__ == "__main__":
    unittest.main()
