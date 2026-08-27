package com.aprz.qbdiandroid

import android.os.Process
import java.io.File
import java.io.FileOutputStream
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import kotlin.system.exitProcess

/** Fixture-only protocol used by the manually invoked qtrace device gate. */
data class QtraceAcceptanceRequest(val mode: String, val seed: Long, val iterations: Long)

object QtraceAcceptance {
    private const val enabled = "qtrace_acceptance"
    private const val mode = "qtrace_acceptance_mode"
    private const val seed = "qtrace_acceptance_seed"
    private const val iterations = "qtrace_acceptance_iterations"
    private const val maximumIterations = 300L
    private val started = AtomicBoolean(false)

    fun claimStartForTest(): Boolean = started.compareAndSet(false, true)

    fun parse(extras: Map<String, Any?>): QtraceAcceptanceRequest? {
        if ((extras[enabled] as? Boolean) != true) return null
        val selectedMode = extras[mode] as? String ?: return null
        val selectedSeed = extras[seed] as? Long ?: return null
        val selectedIterations = extras[iterations] as? Long ?: return null
        if (selectedMode !in setOf("timed", "exit", "flight-crash") || selectedSeed < 0L ||
            selectedIterations !in 1..maximumIterations) return null
        return QtraceAcceptanceRequest(selectedMode, selectedSeed, selectedIterations)
    }

    fun resultJson(request: QtraceAcceptanceRequest, result: Long): String =
        "{\"iterations\":${request.iterations},\"seed\":${request.seed},\"result\":\"0x${java.lang.Long.toUnsignedString(result, 16)}\"}"

    fun start(activity: MainActivity, request: QtraceAcceptanceRequest) {
        if (!started.compareAndSet(false, true)) return
        val traced = activity.intent.hasExtra("qtrace_acceptance_worker")
        if (request.mode == "timed" && !traced) {
            File(activity.filesDir, "qtrace-acceptance-baseline.json").delete()
            File(activity.filesDir, "qtrace-acceptance-timed.json").delete()
        }
        thread(name = "qtrace-acceptance-${request.mode}", isDaemon = false) {
            when (request.mode) {
                "timed" -> {
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
