package com.aprz.qbdiandroid

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            QbdiDemoApp()
        }
    }
}

@Composable
private fun QbdiDemoApp() {
    var output by rememberSaveable {
        mutableStateOf("QBDI Android Demo ready. Inject tracer with Frida spawn, then tap a scene.")
    }

    fun runScene(label: String, action: () -> String) {
        output = runCatching(action).fold(
            onSuccess = { "$label\n$it" },
            onFailure = { "$label failed: ${it.javaClass.simpleName}: ${it.message}" }
        )
    }

    MaterialTheme {
        Surface(modifier = Modifier.fillMaxSize()) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
                    .padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(
                    text = stringResource(R.string.app_name),
                    style = MaterialTheme.typography.headlineSmall
                )
                Text(
                    text = "Spawn-inject libqbdi_tracer.so first, then run a native scene.",
                    style = MaterialTheme.typography.bodyMedium
                )
                Spacer(modifier = Modifier.height(4.dp))
                SceneButton(label = stringResource(R.string.trace_jni)) {
                    runScene(it) { NativeDemo.runJniCase() }
                }
                SceneButton(label = stringResource(R.string.trace_libc)) {
                    runScene(it) { NativeDemo.runLibcCase() }
                }
                SceneButton(label = stringResource(R.string.trace_algorithm)) {
                    runScene(it) { NativeDemo.runAlgorithmCase() }
                }
                SceneButton(label = stringResource(R.string.trace_integrity)) {
                    runScene(it) { NativeDemo.runIntegrityCase() }
                }
                OutlinedCard(modifier = Modifier.fillMaxWidth()) {
                    Text(
                        text = output,
                        modifier = Modifier.padding(16.dp),
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
            }
        }
    }
}

@Composable
private fun SceneButton(label: String, onClick: (String) -> Unit) {
    Button(
        modifier = Modifier.fillMaxWidth(),
        onClick = { onClick(label) }
    ) {
        Text(text = label)
    }
}
