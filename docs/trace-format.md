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
```

Code rule events:

```text
RULE set_equals_flag offset=0x... z=1
RULE force_return offset=0x... ret=0x0
```
