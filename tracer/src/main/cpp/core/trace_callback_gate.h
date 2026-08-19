#pragma once

class TraceCallbackGate {
public:
    bool enabled() const { return enabled_; }

    void observe_failure(bool failed) {
        if (failed) enabled_ = false;
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
