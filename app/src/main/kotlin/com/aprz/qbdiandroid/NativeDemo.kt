package com.aprz.qbdiandroid

object NativeDemo {
    init {
        System.loadLibrary("demo_target")
    }

    external fun runJniCase(): String
    external fun runLibcCase(): String
    external fun runAlgorithmCase(): String
    external fun runIntegrityCase(): String
}
