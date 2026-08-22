#include "core/qbdi_execution_control.h"

QbdiControlExtentResult QbdiControlExtentSet::ensure(
        QbdiControlExtent extent,
        const QbdiControlExtentRegistration &registration) noexcept {
    if (extent.start >= extent.end ||
        registration.add_instrumented_range == nullptr ||
        registration.add_pre_observer == nullptr) {
        return QbdiControlExtentResult::Invalid;
    }
    for (size_t index = 0; index < size_; ++index) {
        if (extents_[index] == extent) {
            return QbdiControlExtentResult::AlreadyPresent;
        }
    }
    if (size_ == extents_.size()) {
        return QbdiControlExtentResult::CapacityExceeded;
    }
    if (!registration.add_instrumented_range(
                registration.opaque, extent.start, extent.end)) {
        return QbdiControlExtentResult::InstrumentationFailed;
    }
    if (!registration.add_pre_observer(
                registration.opaque, extent.start, extent.end)) {
        return QbdiControlExtentResult::ObserverFailed;
    }
    extents_[size_++] = extent;
    return QbdiControlExtentResult::Added;
}

bool QbdiNoProgressTracker::observe(
        const QbdiExecutionState &state) noexcept {
    if (!observed_ || !(previous_ == state)) {
        previous_ = state;
        repeated_ = 0;
        observed_ = true;
        return false;
    }
    ++repeated_;
    if (repeated_ < kRepeatedStateYieldInterval) return false;
    repeated_ = 0;
    return true;
}
