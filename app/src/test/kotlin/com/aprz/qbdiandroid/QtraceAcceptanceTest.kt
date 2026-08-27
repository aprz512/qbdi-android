package com.aprz.qbdiandroid

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class QtraceAcceptanceTest {
    @Test fun parses_only_explicit_supported_fixture_intents() {
        assertEquals(
            QtraceAcceptanceRequest("timed", 5855319310239641971L, 30L),
            QtraceAcceptance.parse(mapOf(
                "qtrace_acceptance" to true,
                "qtrace_acceptance_mode" to "timed",
                "qtrace_acceptance_seed" to 5855319310239641971L,
                "qtrace_acceptance_iterations" to 30L,
            )),
        )
        assertNull(QtraceAcceptance.parse(mapOf("qtrace_acceptance" to true, "qtrace_acceptance_mode" to "unknown", "qtrace_acceptance_seed" to 1L, "qtrace_acceptance_iterations" to 1L)))
        assertNull(QtraceAcceptance.parse(mapOf("qtrace_acceptance_mode" to "timed", "qtrace_acceptance_seed" to 1L, "qtrace_acceptance_iterations" to 1L)))
    }

    @Test fun serializes_fixture_results_as_strict_stable_json() {
        assertEquals(
            "{\"iterations\":30,\"seed\":5855319310239641971,\"result\":\"0x42\"}",
            QtraceAcceptance.resultJson(QtraceAcceptanceRequest("timed", 5855319310239641971L, 30L), 0x42L),
        )
    }

}
