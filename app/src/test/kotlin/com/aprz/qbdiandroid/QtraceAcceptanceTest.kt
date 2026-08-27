package com.aprz.qbdiandroid

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.concurrent.Executors

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

    @Test fun serializes_high_bit_native_return_as_unsigned_hex() {
        assertEquals(
            "{\"iterations\":1,\"seed\":1,\"result\":\"0x8000000000000000\"}",
            QtraceAcceptance.resultJson(QtraceAcceptanceRequest("timed", 1L, 1L), Long.MIN_VALUE),
        )
    }

    @Test fun process_gate_allows_only_one_concurrent_claim() {
        val pool = Executors.newFixedThreadPool(2)
        try {
            val claims = listOf(
                pool.submit<Boolean> { QtraceAcceptance.claimStartForTest() },
                pool.submit<Boolean> { QtraceAcceptance.claimStartForTest() },
            ).count { it.get() }
            assertEquals(1, claims)
        } finally {
            pool.shutdownNow()
        }
    }

}
