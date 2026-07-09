package com.aprz.qbdiandroid

import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    private lateinit var output: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        output = TextView(this).apply {
            textSize = 14f
            text = "QBDI Android Demo ready. Inject tracer with Frida spawn, then tap a scene."
            setPadding(24, 24, 24, 24)
        }

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 24, 24, 24)
            addView(makeButton(getString(R.string.trace_jni)) { NativeDemo.runJniCase() })
            addView(makeButton(getString(R.string.trace_libc)) { NativeDemo.runLibcCase() })
            addView(makeButton(getString(R.string.trace_algorithm)) { NativeDemo.runAlgorithmCase() })
            addView(makeButton(getString(R.string.trace_integrity)) { NativeDemo.runIntegrityCase() })
            addView(output)
        }

        setContentView(ScrollView(this).apply { addView(content) })
    }

    private fun makeButton(label: String, action: () -> String): Button {
        return Button(this).apply {
            text = label
            setOnClickListener {
                output.text = runCatching(action).fold(
                    onSuccess = { "$label\n$it" },
                    onFailure = { "$label failed: ${it.javaClass.simpleName}: ${it.message}" }
                )
            }
        }
    }
}
