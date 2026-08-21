#include "core/signal_context_arm64.h"

#include <cstddef>

bool qbdi_gpr_to_signal_context(const QBDI::GPRState &source,
                                Arm64SignalContext *destination) noexcept {
  if (destination == nullptr)
    return false;
  for (size_t index = 0; index < destination->regs.size(); ++index) {
    destination->regs[index] = QBDI_GPR_GET(&source, index);
  }
  destination->sp = source.sp;
  destination->pc = source.pc;
  destination->pstate = source.nzcv;
  return true;
}

bool signal_context_to_qbdi_gpr(const Arm64SignalContext &source,
                                QBDI::GPRState *destination) noexcept {
  if (destination == nullptr)
    return false;
  for (size_t index = 0; index < source.regs.size(); ++index) {
    QBDI_GPR_SET(destination, index, source.regs[index]);
  }
  destination->sp = source.sp;
  destination->pc = source.pc;
  destination->nzcv = source.pstate;
  return true;
}

#if defined(__ANDROID__) && defined(__aarch64__)
bool qbdi_gpr_to_ucontext(const QBDI::GPRState &source,
                          ucontext_t *destination) noexcept {
  if (destination == nullptr)
    return false;
  Arm64SignalContext context{};
  if (!qbdi_gpr_to_signal_context(source, &context))
    return false;
  for (size_t index = 0; index < context.regs.size(); ++index) {
    destination->uc_mcontext.regs[index] = context.regs[index];
  }
  destination->uc_mcontext.sp = context.sp;
  destination->uc_mcontext.pc = context.pc;
  destination->uc_mcontext.pstate = context.pstate;
  return true;
}

bool ucontext_to_qbdi_gpr(const ucontext_t &source,
                          QBDI::GPRState *destination) noexcept {
  if (destination == nullptr)
    return false;
  Arm64SignalContext context{};
  for (size_t index = 0; index < context.regs.size(); ++index) {
    context.regs[index] = source.uc_mcontext.regs[index];
  }
  context.sp = source.uc_mcontext.sp;
  context.pc = source.uc_mcontext.pc;
  context.pstate = source.uc_mcontext.pstate;
  return signal_context_to_qbdi_gpr(context, destination);
}
#endif
