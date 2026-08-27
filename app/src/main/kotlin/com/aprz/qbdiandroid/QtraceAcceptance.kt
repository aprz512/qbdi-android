package com.aprz.qbdiandroid

import android.os.Process
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import kotlin.system.exitProcess

/** Fixture-only protocol used by the manually invoked qtrace device gate. */
data class QtraceAcceptanceRequest(val mode: String, val seed: Long, val iterations: Long)
data class QtraceAcceptanceEvidence(val sessionId: String, val nonce: String)

object QtraceAcceptance {
    private const val enabled = "qtrace_acceptance"
    private const val mode = "qtrace_acceptance_mode"
    private const val seed = "qtrace_acceptance_seed"
    private const val iterations = "qtrace_acceptance_iterations"
    private const val worker = "qtrace_acceptance_worker"
    private const val sessionId = "qtrace_acceptance_session_id"
    private const val nonce = "qtrace_acceptance_nonce"
    private const val maximumIterations = 300L
    private const val maximumStatusBytes = 64 * 1024
    private const val entryStatusWaitNs = 1_000_000_000L
    private const val entryStatusPollNs = 25_000_000L
    private val uuid4 = Regex("[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
    private val started = AtomicBoolean(false)

    fun claimStartForTest(): Boolean = started.compareAndSet(false, true)

    internal fun clearStaleTimedResults(removeIfPresent: (String) -> Boolean) {
        for (name in listOf("qtrace-acceptance-baseline.json", "qtrace-acceptance-timed.json")) {
            if (!removeIfPresent(name)) {
                throw IllegalStateException("cannot remove stale $name")
            }
        }
    }

    fun parse(extras: Map<String, Any?>): QtraceAcceptanceRequest? {
        if ((extras[enabled] as? Boolean) != true) return null
        val selectedMode = extras[mode] as? String ?: return null
        val selectedSeed = extras[seed] as? Long ?: return null
        val selectedIterations = extras[iterations] as? Long ?: return null
        if (selectedMode !in setOf("timed", "exit", "flight-crash") || selectedSeed < 0L ||
            selectedIterations !in 1..maximumIterations) return null
        return QtraceAcceptanceRequest(selectedMode, selectedSeed, selectedIterations)
    }

    fun parseTracedEvidence(extras: Map<String, Any?>): QtraceAcceptanceEvidence? {
        val selectedWorker = extras[worker] as? Int ?: return null
        val selectedSessionId = extras[sessionId] as? String ?: return null
        val selectedNonce = extras[nonce] as? String ?: return null
        if (selectedWorker < 0 || !uuid4.matches(selectedSessionId) ||
            !uuid4.matches(selectedNonce)) return null
        return QtraceAcceptanceEvidence(selectedSessionId, selectedNonce)
    }

    fun resultJson(request: QtraceAcceptanceRequest, result: Long): String =
        "{\"iterations\":${request.iterations},\"seed\":${request.seed},\"result\":\"0x${java.lang.Long.toUnsignedString(result, 16)}\"}"

    fun entryReceiptJson(evidence: QtraceAcceptanceEvidence, entryMonotonicNs: Long): String {
        require(entryMonotonicNs >= 0L)
        return "{\"sessionId\":\"${evidence.sessionId}\",\"nonce\":\"${evidence.nonce}\",\"entryMonotonicNs\":$entryMonotonicNs}"
    }

    internal fun awaitRunningEntryStatus(
        statusFile: File,
        expectedSessionId: String,
        deadlineMonotonicNs: Long,
        nowMonotonicNs: () -> Long = System::nanoTime,
        pause: (Long) -> Unit = { nanoseconds ->
            Thread.sleep(
                nanoseconds / 1_000_000L,
                (nanoseconds % 1_000_000L).toInt(),
            )
        },
    ): String {
        while (nowMonotonicNs() < deadlineMonotonicNs) {
            val snapshot = try {
                readBoundedUtf8(statusFile)
            } catch (_: IOException) {
                null
            }
            val afterRead = nowMonotonicNs()
            if (afterRead >= deadlineMonotonicNs) break
            if (snapshot != null && isRunningStatus(snapshot, expectedSessionId)) return snapshot
            pause(minOf(entryStatusPollNs, deadlineMonotonicNs - afterRead))
        }
        throw IllegalStateException("native running status was not available before entry deadline")
    }

    private fun readBoundedUtf8(statusFile: File): String {
        val bytes = FileInputStream(statusFile).use { input ->
            val result = ByteArray(maximumStatusBytes + 1)
            var used = 0
            while (used < result.size) {
                val count = input.read(result, used, result.size - used)
                if (count < 0) break
                if (count == 0) continue
                used += count
            }
            if (used == 0 || used > maximumStatusBytes || input.read() >= 0) {
                throw IllegalStateException("native entry status is empty or exceeds 64 KiB")
            }
            result.copyOf(used)
        }
        return try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString()
        } catch (error: Exception) {
            throw IllegalStateException("native entry status is not strict UTF-8", error)
        }
    }

    private fun isRunningStatus(snapshot: String, expectedSessionId: String): Boolean {
        if (!snapshot.startsWith('{') || !snapshot.endsWith('}')) return false
        val requiredFields = setOf(
            "schemaVersion", "sessionId", "generation", "packageName", "pid", "state",
            "reason", "transitionMonotonicNs", "deadlineMonotonicNs",
            "normalizedScenes", "activeScenes",
            "artifacts", "stopAcknowledged", "warnings", "errors",
        )
        if (requiredFields.any { field ->
                Regex("\\\"$field\\\"\\s*:").findAll(snapshot).count() != 1
            }) return false
        fun single(field: String): String? {
            val matches = Regex("\\\"$field\\\"\\s*:\\s*\\\"([^\\\"]*)\\\"")
                .findAll(snapshot)
                .map { it.groupValues[1] }
                .toList()
            return matches.singleOrNull()
        }
        return single("sessionId") == expectedSessionId && single("state") == "running"
    }

    fun start(activity: MainActivity, request: QtraceAcceptanceRequest) {
        val traced = activity.intent.hasExtra(worker)
        val evidence = if (request.mode == "timed" && traced) {
            parseTracedEvidence(mapOf(
                worker to activity.intent.getIntExtra(worker, -1),
                sessionId to activity.intent.getStringExtra(sessionId),
                nonce to activity.intent.getStringExtra(nonce),
            )) ?: return
        } else null
        if (!started.compareAndSet(false, true)) return
        if (request.mode == "timed" && !traced) {
            clearStaleTimedResults { name ->
                val stale = File(activity.filesDir, name)
                !stale.exists() || stale.delete()
            }
        }
        thread(name = "qtrace-acceptance-${request.mode}", isDaemon = false) {
            when (request.mode) {
                "timed" -> {
                    if (evidence != null) {
                        val started = System.nanoTime()
                        val deadline = if (started > Long.MAX_VALUE - entryStatusWaitNs) {
                            Long.MAX_VALUE
                        } else {
                            started + entryStatusWaitNs
                        }
                        val statusFile = File(
                            activity.filesDir,
                            "qbdi-traces/session-${evidence.sessionId}.status.json",
                        )
                        val entryStatus = awaitRunningEntryStatus(
                            statusFile,
                            evidence.sessionId,
                            deadline,
                        )
                        writeAtomic(
                            activity.filesDir,
                            "qtrace-acceptance-entry-status.json",
                            entryStatus,
                        )
                        val entryMonotonicNs = System.nanoTime()
                        writeAtomic(activity.filesDir, "qtrace-acceptance-receipt.json",
                            entryReceiptJson(evidence, entryMonotonicNs))
                    }
                    val result = NativeDemo.runTimedAcceptance(request.iterations, request.seed)
                    val name = if (traced) "qtrace-acceptance-timed.json" else "qtrace-acceptance-baseline.json"
                    writeAtomic(activity.filesDir, name, resultJson(request, result))
                }
                "exit" -> {
                    writeAtomic(activity.filesDir, "qtrace-acceptance-exit.json", resultJson(request, 0L))
                    exitProcess(0)
                }
                "flight-crash" -> NativeDemo.runFlightAcceptance(request.seed, 2, 0)
            }
        }
    }

    private fun writeAtomic(directory: File, name: String, payload: String) {
        val destination = File(directory, name)
        val temporary = File(directory, ".${name}.${Process.myPid()}.${UUID.randomUUID()}.tmp")
        FileOutputStream(temporary).use { stream ->
            stream.write(payload.toByteArray(Charsets.UTF_8))
            stream.fd.sync()
        }
        if (!temporary.renameTo(destination)) {
            temporary.delete()
            throw IllegalStateException("cannot atomically publish $name")
        }
    }
}
