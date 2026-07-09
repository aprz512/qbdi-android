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

Bypass events:

```text
BYPASS text_hash_restore range=libdemo_target.so+0x...
BYPASS maps_sanitize hidden=frida,libqbdi_tracer,libQBDI
```
