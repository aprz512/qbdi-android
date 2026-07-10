# Text Trace Format

Trace files live under the app private directory:

```text
/data/data/com.aprz.qbdiandroid/files/qbdi-traces/
```

Each trace starts with `TRACE_BEGIN` and ends with `TRACE_END`.

Instruction line:

```text
<seq> <module>+<offset> <disassembly> | R:<register reads> | W:<register writes> | MEM:<memory events>
```

Call events:

```text
CALL libc.strlen x0=0x... preview="qbdi"
CALL jni.FindClass name="java/lang/String"
CALL return strlen target=0x... ret=0x...
```

Libc, ART, and JNI call events are emitted from QBDI `EXEC_TRANSFER_CALL` / `EXEC_TRANSFER_RETURN` VM events when execution leaves the instrumented module and returns through QBDI's ExecBroker.

Code rule events:

```text
RULE set_equals_flag offset=0x... z=1
RULE force_return offset=0x... ret=0x0
```
