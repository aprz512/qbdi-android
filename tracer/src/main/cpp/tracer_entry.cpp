#include "core/logging.h"

#include <shadowhook.h>

__attribute__((constructor)) static void qbdi_tracer_init() {
    int init_result = shadowhook_init(SHADOWHOOK_MODE_UNIQUE, true);
    if (init_result != 0) {
        QTRACE_E("shadowhook_init failed: %d", init_result);
        return;
    }
    QTRACE_I("libqbdi_tracer loaded");
}
