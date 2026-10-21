.text
.align 2
.global qtrace_native_vfork_boundary
.hidden qtrace_native_vfork_boundary
.hidden qtrace_vfork_target
.hidden qtrace_vfork_child_return
.hidden qtrace_vfork_broker_return
.type qtrace_native_vfork_boundary, %function
qtrace_native_vfork_boundary:
    hint #34 // bti c
    // No stack frame: the native child may reuse all memory below the caller's
    // SP. Saving the broker LR there would corrupt the suspended parent.
    adrp x16, qtrace_vfork_broker_return
    str x30, [x16, :lo12:qtrace_vfork_broker_return]
    dmb ish
    adrp x16, qtrace_vfork_target
    ldr x16, [x16, :lo12:qtrace_vfork_target]
    blr x16
    cbnz x0, 1f
    // Child: touch no engine/TLS/allocator state. Resume the real call site
    // natively. Valid vfork children proceed to exec or _exit without returning
    // from this caller. Only the parent may return through QBDI's broker.
    adrp x16, qtrace_vfork_child_return
    ldr x30, [x16, :lo12:qtrace_vfork_child_return]
    ret
1:
    adrp x16, qtrace_vfork_broker_return
    ldr x30, [x16, :lo12:qtrace_vfork_broker_return]
    ret
.size qtrace_native_vfork_boundary, .-qtrace_native_vfork_boundary
.section .note.GNU-stack,"",%progbits
