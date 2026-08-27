package com.aprz.qbdiandroid

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files
import java.util.concurrent.Executors

class QtraceAcceptanceTest {
    private fun runningStatus(session: String, state: String = "running"): String =
        "{\"schemaVersion\":1,\"sessionId\":\"$session\",\"generation\":1," +
            "\"packageName\":\"com.aprz.qbdiandroid\",\"pid\":4242,\"state\":\"$state\"," +
            "\"reason\":\"\",\"transitionMonotonicNs\":100,\"normalizedScenes\":[]," +
            "\"activeScenes\":[],\"artifacts\":[],\"stopAcknowledged\":false," +
            "\"warnings\":[],\"errors\":[]}"

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

    @Test fun parses_exit_and_crash_requests_without_timed_entry_evidence() {
        for (mode in listOf("exit", "flight-crash")) {
            assertEquals(
                QtraceAcceptanceRequest(mode, 1L, 1L),
                QtraceAcceptance.parse(mapOf(
                    "qtrace_acceptance" to true,
                    "qtrace_acceptance_mode" to mode,
                    "qtrace_acceptance_seed" to 1L,
                    "qtrace_acceptance_iterations" to 1L,
                )),
            )
        }
    }

    @Test fun traced_worker_requires_bounded_session_and_nonce_evidence() {
        val session = "123e4567-e89b-42d3-a456-426614174000"
        val nonce = "223e4567-e89b-42d3-a456-426614174001"
        val evidence = mapOf(
            "qtrace_acceptance_worker" to 0,
            "qtrace_acceptance_session_id" to session,
            "qtrace_acceptance_nonce" to nonce,
        )
        assertEquals(
            QtraceAcceptanceEvidence(session, nonce),
            QtraceAcceptance.parseTracedEvidence(evidence),
        )
        assertNull(QtraceAcceptance.parseTracedEvidence(evidence - "qtrace_acceptance_session_id"))
        assertNull(QtraceAcceptance.parseTracedEvidence(evidence - "qtrace_acceptance_nonce"))
        assertNull(QtraceAcceptance.parseTracedEvidence(evidence - "qtrace_acceptance_worker"))
    }

    @Test fun entry_receipt_contains_only_identity_and_real_native_entry_time() {
        val evidence = QtraceAcceptanceEvidence(
            "123e4567-e89b-42d3-a456-426614174000",
            "223e4567-e89b-42d3-a456-426614174001",
        )
        assertEquals(
            "{\"sessionId\":\"${evidence.sessionId}\",\"nonce\":\"${evidence.nonce}\",\"entryMonotonicNs\":123}",
            QtraceAcceptance.entryReceiptJson(evidence, 123L),
        )
    }

    @Test fun running_entry_snapshot_is_selected_before_absolute_deadline() {
        val session = "123e4567-e89b-42d3-a456-426614174000"
        val directory = Files.createTempDirectory("qtrace-entry-status").toFile()
        val status = directory.resolve("status.json")
        status.writeText(runningStatus(session, "installed"))
        var now = 0L
        val selected = QtraceAcceptance.awaitRunningEntryStatus(
            status,
            session,
            deadlineMonotonicNs = 1_000_000_000L,
            nowMonotonicNs = { now },
            pause = {
                now += it
                status.writeText(runningStatus(session))
            },
        )
        assertTrue(selected.contains("\"state\":\"running\""))
    }

    @Test fun entry_snapshot_rejects_oversize_and_invalid_utf8_within_deadline() {
        val session = "123e4567-e89b-42d3-a456-426614174000"
        for (payload in listOf(
            ByteArray(65_537) { 'x'.code.toByte() },
            byteArrayOf(0xc3.toByte()),
            "{\"sessionId\":\"$session\",\"state\":\"running\"}".toByteArray(),
        )) {
            val status = Files.createTempFile("qtrace-entry-status", ".json").toFile()
            status.writeBytes(payload)
            var now = 0L
            val failure = runCatching {
                QtraceAcceptance.awaitRunningEntryStatus(
                    status,
                    session,
                    deadlineMonotonicNs = 100L,
                    nowMonotonicNs = { now },
                    pause = { now += it },
                )
            }.exceptionOrNull()
            assertEquals(IllegalStateException::class, failure!!::class)
        }
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

    @Test fun rejects_baseline_launch_when_stale_fixture_result_cannot_be_removed() {
        val deleted = mutableListOf<String>()
        val failure = runCatching {
            QtraceAcceptance.clearStaleTimedResults { name ->
                deleted += name
                name != "qtrace-acceptance-timed.json"
            }
        }.exceptionOrNull()

        assertEquals(
            listOf("qtrace-acceptance-baseline.json", "qtrace-acceptance-timed.json"),
            deleted,
        )
        assertEquals(IllegalStateException::class, failure!!::class)
    }

}
