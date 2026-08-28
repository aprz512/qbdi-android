package com.aprz.qbdiandroid

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.concurrent.Executors

class QtraceAcceptanceTest {
    private fun runningStatus(
        session: String,
        state: String = "running",
        activeScenes: String = "[]",
        artifacts: String = "[]",
    ): String =
        "{\"schemaVersion\":1,\"sessionId\":\"$session\",\"generation\":1," +
            "\"packageName\":\"com.aprz.qbdiandroid\",\"pid\":4242,\"state\":\"$state\"," +
            "\"reason\":\"\",\"transitionMonotonicNs\":100," +
            "\"deadlineMonotonicNs\":2000000000,\"normalizedScenes\":[]," +
            "\"activeScenes\":$activeScenes,\"artifacts\":$artifacts,\"stopAcknowledged\":false," +
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

    @Test fun timed_receipt_uses_native_entry_getter_after_native_call_returns() {
        val evidence = QtraceAcceptanceEvidence(
            "123e4567-e89b-42d3-a456-426614174000",
            "223e4567-e89b-42d3-a456-426614174001",
        )
        val calls = mutableListOf<String>()

        val invocation = QtraceAcceptance.completeTimedInvocation(
            evidence,
            invokeNative = { calls += "native"; 42L },
            readNativeEntryMonotonicNs = { calls += "entry"; 123L },
        )

        assertEquals(listOf("native", "entry"), calls)
        assertEquals(42L, invocation.result)
        assertEquals(
            "{\"sessionId\":\"${evidence.sessionId}\",\"nonce\":\"${evidence.nonce}\",\"entryMonotonicNs\":123}",
            invocation.receipt,
        )
    }

    @Test fun timed_receipt_rejects_missing_native_entry_timestamp() {
        val evidence = QtraceAcceptanceEvidence(
            "123e4567-e89b-42d3-a456-426614174000",
            "223e4567-e89b-42d3-a456-426614174001",
        )

        val failure = runCatching {
            QtraceAcceptance.completeTimedInvocation(
                evidence,
                invokeNative = { 42L },
                readNativeEntryMonotonicNs = { 0L },
            )
        }.exceptionOrNull()

        assertEquals(IllegalStateException::class, failure!!::class)
    }

    @Test fun traced_timed_invocation_observes_running_while_native_call_is_active() {
        val evidence = QtraceAcceptanceEvidence(
            "123e4567-e89b-42d3-a456-426614174000",
            "223e4567-e89b-42d3-a456-426614174001",
        )
        val status = Files.createTempFile("qtrace-concurrent-entry-status", ".json").toFile()
        status.writeText(runningStatus(evidence.sessionId, "installed"))
        var published: String? = null

        val invocation = QtraceAcceptance.completeTracedTimedInvocation(
            evidence,
            status,
            invokeNative = {
                val statusParent = checkNotNull(status.toPath().parent)
                val replacement = Files.createTempFile(
                    statusParent,
                    "qtrace-concurrent-entry-status-replacement",
                    ".json",
                )
                Files.write(replacement, runningStatus(evidence.sessionId).toByteArray())
                Files.move(
                    replacement,
                    status.toPath(),
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING,
                )
                Thread.sleep(100)
                42L
            },
            readNativeEntryMonotonicNs = { 123L },
            publishEntryStatus = { published = it },
        )

        assertEquals(42L, invocation.result)
        assertTrue(published!!.contains("\"state\":\"running\""))
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

    @Test fun exit_invocation_traces_before_publishing_the_real_result_and_terminating() {
        val request = QtraceAcceptanceRequest("exit", 7L, 3L)
        val calls = mutableListOf<String>()
        var payload: String? = null

        QtraceAcceptance.completeExitInvocation(
            request,
            invokeNative = { calls += "native"; 42L },
            publishResult = { calls += "publish"; payload = it },
            prepareExit = { calls += "finish-task" },
            terminate = { code -> calls += "exit:$code" },
        )

        assertEquals(listOf("native", "publish", "finish-task", "exit:0"), calls)
        assertEquals(
            "{\"iterations\":3,\"seed\":7,\"result\":\"0x2a\"}",
            payload,
        )
    }

    @Test fun exit_readiness_waits_for_committed_inactive_scene_status() {
        val session = "123e4567-e89b-42d3-a456-426614174000"
        val status = Files.createTempFile("qtrace-exit-status", ".json").toFile()
        status.writeText(runningStatus(
            session,
            activeScenes = "[{\"sceneIndex\":0,\"tid\":7,\"sealed\":false}]",
            artifacts = "[\"run.trace.bin.lz4\"]",
        ))
        var now = 0L
        var pauses = 0

        QtraceAcceptance.awaitQuiescentExitStatus(
            status,
            session,
            deadlineMonotonicNs = 1_000_000_000L,
            nowMonotonicNs = { now },
            pause = {
                pauses += 1
                now += it
                status.writeText(runningStatus(
                    session,
                    activeScenes = "[]",
                    artifacts = "[\"run.trace.bin.lz4\"]",
                ))
            },
        )

        assertEquals(1, pauses)
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
