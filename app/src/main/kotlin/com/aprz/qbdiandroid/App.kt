package com.aprz.qbdiandroid

import android.app.Application

class App : Application() {
    override fun onCreate() {
        super.onCreate()
        System.loadLibrary("demo_target")
    }
}
