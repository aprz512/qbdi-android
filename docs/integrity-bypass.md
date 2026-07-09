# Integrity Checks and Bypass Demo

The integrity scene contains two checks:

1. `.text` hash validation for a selected executable range.
2. `/proc/self/maps` inspection for injected modules and suspicious mappings.

Without bypass, the scene can intentionally crash. With bypass enabled, tracer events show what was repaired or hidden before the target check observes it.

First-version bypass handlers emit explicit `BYPASS` markers and skip selected libc comparison/search calls from QBDI. Precise `.text` byte restoration and maps buffer rewriting can be implemented around the same handler names so the trace format remains stable.
