#pragma once

class TraceCallbackGate {
public:
    bool enabled() const { return enabled_; }

    void observe_failure(bool failed) {
        if (failed) enabled_ = false;
    }

    void observe_memory_instrumentation(bool memory_enabled,
                                        bool recording_enabled,
                                        bool callback_valid) {
        observe_failure(memory_enabled && (!recording_enabled || !callback_valid));
    }

    bool completion_succeeded(bool target_succeeded, bool writer_failed) const {
        return target_succeeded && enabled_ && !writer_failed;
    }

    template <typename Writer>
    Writer *writer_or_null(Writer *writer) const {
        return enabled_ ? writer : nullptr;
    }

    template <typename Action, typename Operation>
    Action trace(Action action, Operation operation) {
        if (enabled_ && !operation()) enabled_ = false;
        return action;
    }

private:
    bool enabled_ = true;
};
