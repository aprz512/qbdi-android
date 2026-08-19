.text
.align 2
.global call_target_arm64
.type call_target_arm64, %function
call_target_arm64:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    mov x9, x0
    mov x10, x1
    mov x11, x2
    ldp x0, x1, [x10, #0]
    ldp x2, x3, [x10, #16]
    ldp x4, x5, [x10, #32]
    ldp x6, x7, [x10, #48]
    mov x8, x11
    blr x9
    ldp x29, x30, [sp], #16
    ret
.size call_target_arm64, .-call_target_arm64

.align 3
.global trace_proxy_stubs
.hidden trace_proxy_stubs
.type trace_proxy_stubs, %function
trace_proxy_stubs:
// Each entry is exactly two instructions; tracer_entry.cpp uses the same 8-byte stride.
.rept 256
    adr x16, .
    b trace_proxy_common
.endr
.size trace_proxy_stubs, .-trace_proxy_stubs

.type trace_proxy_common, %function
trace_proxy_common:
    sub sp, sp, #96
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x29, x30, [sp, #80]
    add x29, sp, #80
    mov x2, x8
    adrp x17, trace_proxy_stubs
    add x17, x17, :lo12:trace_proxy_stubs
    sub x0, x16, x17
    lsr x0, x0, #3
    mov x1, sp
    bl trace_proxy_dispatch
    ldp x29, x30, [sp, #80]
    add sp, sp, #96
    ret
.size trace_proxy_common, .-trace_proxy_common
