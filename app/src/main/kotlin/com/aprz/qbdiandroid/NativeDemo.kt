package com.aprz.qbdiandroid

object NativeDemo {
    external fun runJniCase(): String
    external fun runLibcCase(): String
    external fun runAlgorithmCase(): String
    external fun runIntegrityCase(): String
    external fun runBenchmarkCase(): String
    external fun runTimedAcceptance(iterations: Long, seed: Long): Long
    external fun getLastTimedAcceptanceEntryMonotonicNs(): Long
    external fun runFlightAcceptance(seed: Long, mode: Int, selectedWorker: Int): Long
}
