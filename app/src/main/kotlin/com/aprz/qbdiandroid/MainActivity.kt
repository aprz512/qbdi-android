package com.aprz.qbdiandroid

import android.graphics.Color
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
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
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT)
        )
        super.onCreate(savedInstanceState)
        val acceptanceMode = intent.getIntExtra("flight_acceptance_mode", -1)
        if (acceptanceMode >= 0) {
            val seed = intent.getLongExtra("flight_acceptance_seed", 0)
            val worker = intent.getIntExtra("flight_acceptance_worker", 0)
            Thread({
                val returned = NativeDemo.runFlightAcceptance(seed, acceptanceMode, worker)
                Log.e("QBDI-FlightAcceptance", "fixture unexpectedly returned $returned")
            }, "flight-acceptance-trigger").start()
        }
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

    QbdiDemoScreen(
        output = output,
        onRunJni = { runScene("Trace JNI Case") { NativeDemo.runJniCase() } },
        onRunLibc = { runScene("Trace Libc Case") { NativeDemo.runLibcCase() } },
        onRunAlgorithm = { runScene("Trace Algorithm Case") { NativeDemo.runAlgorithmCase() } },
        onRunIntegrity = { runScene("Trace Integrity Case") { NativeDemo.runIntegrityCase() } },
        onRunBenchmark = { runScene("Run Trace Benchmark") { NativeDemo.runBenchmarkCase() } }
    )
}

@Composable
private fun QbdiDemoScreen(
    output: String,
    onRunJni: () -> Unit,
    onRunLibc: () -> Unit,
    onRunAlgorithm: () -> Unit,
    onRunIntegrity: () -> Unit,
    onRunBenchmark: () -> Unit,
    modifier: Modifier = Modifier
) {
    MaterialTheme {
        Surface(modifier = modifier.fillMaxSize()) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .safeDrawingPadding()
                    .verticalScroll(rememberScrollState())
                    .padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(
                    text = "QBDI Android Demo",
                    style = MaterialTheme.typography.headlineSmall
                )
                Text(
                    text = "Spawn-inject libqbdi_tracer.so first, then run a native scene.",
                    style = MaterialTheme.typography.bodyMedium
                )
                Spacer(modifier = Modifier.height(4.dp))
                SceneButton(label = "Trace JNI Case", onClick = onRunJni)
                SceneButton(label = "Trace Libc Case", onClick = onRunLibc)
                SceneButton(label = "Trace Algorithm Case", onClick = onRunAlgorithm)
                SceneButton(label = "Trace Integrity Case", onClick = onRunIntegrity)
                SceneButton(label = "Run Trace Benchmark", onClick = onRunBenchmark)
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
private fun SceneButton(label: String, onClick: () -> Unit) {
    Button(
        modifier = Modifier.fillMaxWidth(),
        onClick = onClick
    ) {
        Text(text = label)
    }
}

@Preview(showBackground = true, widthDp = 360)
@Composable
private fun QbdiDemoScreenPreview() {
    QbdiDemoScreen(
        output = "Trace Algorithm Case\nalgorithm: size=24, hash=0x51f00d42",
        onRunJni = {},
        onRunLibc = {},
        onRunAlgorithm = {},
        onRunIntegrity = {},
        onRunBenchmark = {}
    )
}
