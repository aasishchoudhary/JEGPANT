package com.jegpant.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.jegpant.app.net.JegpantApiClient
import com.jegpant.app.security.AndroidKeystoreIdentity
import java.util.UUID
import java.util.concurrent.Executors

class MainActivity : ComponentActivity() {
    private val executor = Executors.newSingleThreadExecutor()
    private lateinit var identity: AndroidKeystoreIdentity
    private lateinit var api: JegpantApiClient
    private val preferences by lazy {
        getSharedPreferences("jegpant-owner-config", Context.MODE_PRIVATE)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        identity = AndroidKeystoreIdentity(this)
        api = JegpantApiClient(contentResolver, identity)

        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    OwnerConsole(
                        initialServerUrl = preferences.getString("server_url", "") ?: "",
                        initialCaseId = preferences.getString("case_id", "") ?: "",
                        initialJobId = preferences.getString("job_id", "") ?: "",
                        initialReportId = preferences.getString("report_id", "") ?: "",
                        onServerUrlChanged = { value ->
                            preferences.edit().putString("server_url", value).apply()
                        },
                        onGenerateIdentity = { callback ->
                            executor.execute {
                                runCatching {
                                    val owner = identity.ownerKey()
                                    val device = identity.deviceKey()
                                    "Owner key: ${owner.securityLevel}\n" +
                                        "Device key: ${device.securityLevel}\n" +
                                        "Owner public key (Base64 DER):\n${owner.publicKeyBase64}\n" +
                                        "Owner SHA-256 fingerprint:\n${identity.ownerPublicKeyFingerprint()}\n\n" +
                                        "The public key must be configured on the private server. " +
                                        "The private signing keys remain in Android Keystore."
                                }.onSuccess { runOnUiThread { callback(it, true) } }
                                    .onFailure { error ->
                                        runOnUiThread { callback(error.message ?: "Key setup failed", false) }
                                    }
                            }
                        },
                        onCopyOwnerPublicKey = {
                            val publicKey = identity.ownerKey().publicKeyBase64
                            val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
                            clipboard.setPrimaryClip(
                                ClipData.newPlainText("JEGPANT owner public key", publicKey)
                            )
                        },
                        onConnectAndEnroll = { serverUrl, callback ->
                            executor.execute {
                                runCatching {
                                    val owner = identity.ownerKey()
                                    val device = identity.deviceKey()
                                    val remote = api.getServerIdentity(serverUrl)
                                    require(remote.ownerKeyAlgorithm == "ecdsa_p256") {
                                        "Server is not configured for the Android P-256 owner key."
                                    }
                                    require(
                                        remote.ownerKeyFingerprintSha256 ==
                                            identity.ownerPublicKeyFingerprint()
                                    ) {
                                        "Owner key fingerprint mismatch. Do not enroll; configure the server with the public key shown above."
                                    }
                                    require("ecdsa_p256" in remote.supportedDeviceKeyAlgorithms) {
                                        "Server does not advertise P-256 device support."
                                    }
                                    val deviceId = preferences.getString("device_id", null)
                                        ?: UUID.randomUUID().toString()
                                    val response = api.enrollDevice(
                                        serverUrl,
                                        remote.instanceId,
                                        deviceId
                                    )
                                    preferences.edit()
                                        .putString("instance_id", remote.instanceId)
                                        .putString("device_id", deviceId)
                                        .putString("server_url", serverUrl)
                                        .apply()
                                    "Enrolled device ${response.getString("device_id")}\n" +
                                        "Instance: ${remote.instanceId}\n" +
                                        "Owner key: ${owner.securityLevel}\n" +
                                        "Device key: ${device.securityLevel}\n" +
                                        "Granted scopes: ${response.getJSONArray("scopes")}\n" +
                                        "Server status: ${response.getString("status")}"
                                }.onSuccess { runOnUiThread { callback(it, true) } }
                                    .onFailure { error ->
                                        runOnUiThread { callback(error.message ?: "Enrollment failed", false) }
                                    }
                            }
                        },
                        onCreateCase = { serverUrl, callback ->
                            executor.execute {
                                runCatching {
                                    val instanceId = requireInstanceId()
                                    val deviceId = requireDeviceId()
                                    val caseId = api.createCase(serverUrl, instanceId, deviceId)
                                    preferences.edit().putString("case_id", caseId).apply()
                                    caseId
                                }.onSuccess { runOnUiThread { callback(it, true) } }
                                    .onFailure { error ->
                                        runOnUiThread { callback(error.message ?: "Case creation failed", false) }
                                    }
                            }
                        },
                        onAddObservation = { serverUrl, caseId, observation, callback ->
                            executor.execute {
                                runCatching {
                                    val result = api.addObservation(
                                        serverUrl,
                                        requireInstanceId(),
                                        requireDeviceId(),
                                        caseId,
                                        observation
                                    )
                                    result.toString(2)
                                }.onSuccess { runOnUiThread { callback(it, true) } }
                                    .onFailure { error ->
                                        runOnUiThread { callback(error.message ?: "Evidence write failed", false) }
                                    }
                            }
                        },
                        onQueueInvestigation = { serverUrl, caseId, goal, callback ->
                            executor.execute {
                                runCatching {
                                    val jobId = api.queueInvestigation(
                                        serverUrl,
                                        requireInstanceId(),
                                        requireDeviceId(),
                                        caseId,
                                        goal
                                    )
                                    preferences.edit().putString("job_id", jobId).apply()
                                    jobId
                                }.onSuccess { runOnUiThread { callback(it, true) } }
                                    .onFailure { error ->
                                        runOnUiThread { callback(error.message ?: "Queueing failed", false) }
                                    }
                            }
                        },
                        onCheckJob = { serverUrl, jobId, callback ->
                            executor.execute {
                                runCatching {
                                    val result = api.getJobStatus(
                                        serverUrl,
                                        requireInstanceId(),
                                        requireDeviceId(),
                                        jobId
                                    )
                                    val resultId = result.optString("result_id")
                                    if (resultId.isNotBlank() && resultId != "null") {
                                        preferences.edit().putString("report_id", resultId).apply()
                                    }
                                    result.toString(2)
                                }.onSuccess { runOnUiThread { callback(it, true) } }
                                    .onFailure { error ->
                                        runOnUiThread { callback(error.message ?: "Job query failed", false) }
                                    }
                            }
                        },
                        onFetchReport = { serverUrl, caseId, reportId, callback ->
                            executor.execute {
                                runCatching {
                                    val result = api.getReport(
                                        serverUrl,
                                        requireInstanceId(),
                                        requireDeviceId(),
                                        caseId,
                                        reportId
                                    )
                                    result.toString(2)
                                }.onSuccess { runOnUiThread { callback(it, true) } }
                                    .onFailure { error ->
                                        runOnUiThread { callback(error.message ?: "Report retrieval failed", false) }
                                    }
                            }
                        },
                        onUploadVideo = { serverUrl, caseId, uri, callback ->
                            executor.execute {
                                runCatching {
                                    api.uploadMedia(
                                        serverUrl,
                                        requireInstanceId(),
                                        requireDeviceId(),
                                        caseId,
                                        uri
                                    ).toString(2)
                                }.onSuccess { runOnUiThread { callback(it, true) } }
                                    .onFailure { error ->
                                        runOnUiThread { callback(error.message ?: "Video upload failed", false) }
                                    }
                            }
                        }
                    )
                }
            }
        }
    }

    private fun requireInstanceId(): String =
        preferences.getString("instance_id", null)
            ?: throw IllegalStateException("Connect and enroll this device first.")

    private fun requireDeviceId(): String =
        preferences.getString("device_id", null)
            ?: throw IllegalStateException("Connect and enroll this device first.")

    override fun onDestroy() {
        executor.shutdown()
        super.onDestroy()
    }
}

@Composable
private fun OwnerConsole(
    initialServerUrl: String,
    initialCaseId: String,
    initialJobId: String,
    initialReportId: String,
    onServerUrlChanged: (String) -> Unit,
    onGenerateIdentity: ((String, Boolean) -> Unit) -> Unit,
    onCopyOwnerPublicKey: () -> Unit,
    onConnectAndEnroll: (String, (String, Boolean) -> Unit) -> Unit,
    onCreateCase: (String, (String, Boolean) -> Unit) -> Unit,
    onAddObservation: (String, String, String, (String, Boolean) -> Unit) -> Unit,
    onQueueInvestigation: (String, String, String, (String, Boolean) -> Unit) -> Unit,
    onCheckJob: (String, String, (String, Boolean) -> Unit) -> Unit,
    onFetchReport: (String, String, String, (String, Boolean) -> Unit) -> Unit,
    onUploadVideo: (String, String, Uri, (String, Boolean) -> Unit) -> Unit
) {
    val context = LocalContext.current
    var serverUrl by rememberSaveable { mutableStateOf(initialServerUrl) }
    var caseId by rememberSaveable { mutableStateOf(initialCaseId) }
    var jobId by rememberSaveable { mutableStateOf(initialJobId) }
    var reportId by rememberSaveable { mutableStateOf(initialReportId) }
    var observation by rememberSaveable { mutableStateOf("") }
    var goal by rememberSaveable { mutableStateOf("") }
    var status by rememberSaveable { mutableStateOf("Private owner console. No account registration exists.") }
    var busy by rememberSaveable { mutableStateOf(false) }

    val videoPicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null && caseId.isNotBlank()) {
            runCatching {
                context.contentResolver.takePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION
                )
            }
            busy = true
            onUploadVideo(serverUrl, caseId, uri) { message, success ->
                busy = false
                status = message
                if (!success) status = "Video upload failed: $message"
            }
        } else if (uri != null) {
            status = "Create or enter a case ID before uploading video."
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("JEGPANT", style = MaterialTheme.typography.headlineLarge)
        Text(
            "Private cognitive system · single-owner instance",
            style = MaterialTheme.typography.bodyMedium
        )

        OutlinedTextField(
            value = serverUrl,
            onValueChange = {
                serverUrl = it
                onServerUrlChanged(it)
            },
            modifier = Modifier.fillMaxWidth(),
            label = { Text("Private server HTTPS URL") },
            placeholder = { Text("https://your-private-domain.example") },
            singleLine = true
        )

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text("Owner identity and device trust", style = MaterialTheme.typography.titleMedium)
                Button(
                    onClick = {
                        busy = true
                        onGenerateIdentity { message, success ->
                            busy = false
                            status = if (success) message else "Identity setup failed: $message"
                        }
                    },
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Generate / inspect Keystore identity")
                }
                TextButton(
                    onClick = {
                        runCatching(onCopyOwnerPublicKey)
                            .onSuccess { status = "Owner public key copied. Private keys remain in Android Keystore." }
                            .onFailure { status = it.message ?: "Copy failed" }
                    },
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Copy owner public key for server configuration")
                }
                Button(
                    onClick = {
                        busy = true
                        onConnectAndEnroll(serverUrl) { message, success ->
                            busy = false
                            status = if (success) message else "Connection or enrollment failed: $message"
                        }
                    },
                    enabled = !busy && serverUrl.startsWith("https://"),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Verify owner key and enroll this device")
                }
            }
        }

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text("Investigation", style = MaterialTheme.typography.titleMedium)
                OutlinedTextField(
                    value = caseId,
                    onValueChange = { caseId = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Case ID") },
                    singleLine = true
                )
                Button(
                    onClick = {
                        busy = true
                        onCreateCase(serverUrl) { value, success ->
                            busy = false
                            if (success) caseId = value
                            status = if (success) "Case created: $value" else value
                        }
                    },
                    enabled = !busy && serverUrl.startsWith("https://"),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Create case")
                }
                OutlinedTextField(
                    value = observation,
                    onValueChange = { observation = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Source observation") },
                    minLines = 2
                )
                Button(
                    onClick = {
                        busy = true
                        onAddObservation(serverUrl, caseId, observation) { value, success ->
                            busy = false
                            status = if (success) "Observation stored:\n$value" else value
                            if (success) observation = ""
                        }
                    },
                    enabled = !busy && caseId.isNotBlank() && observation.isNotBlank(),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Add evidence observation")
                }
                Button(
                    onClick = { videoPicker.launch(arrayOf("video/*")) },
                    enabled = !busy && caseId.isNotBlank() && serverUrl.startsWith("https://"),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Select and encrypt video upload")
                }
                Text(
                    "Uploads are streamed to the private server and encrypted at rest. " +
                        "This app does not yet extract frames, audio or events on the phone.",
                    style = MaterialTheme.typography.bodySmall
                )
                OutlinedTextField(
                    value = goal,
                    onValueChange = { goal = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Investigation goal") },
                    minLines = 2
                )
                Button(
                    onClick = {
                        busy = true
                        onQueueInvestigation(serverUrl, caseId, goal) { value, success ->
                            busy = false
                            if (success) jobId = value
                            status = if (success) "Analysis queued: $value" else value
                        }
                    },
                    enabled = !busy && caseId.isNotBlank() && goal.isNotBlank(),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Queue cognitive investigation")
                }
            }
        }

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text("Asynchronous analysis", style = MaterialTheme.typography.titleMedium)
                OutlinedTextField(
                    value = jobId,
                    onValueChange = { jobId = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Job ID") },
                    singleLine = true
                )
                Button(
                    onClick = {
                        busy = true
                        onCheckJob(serverUrl, jobId) { value, success ->
                            busy = false
                            val parsed = runCatching {
                                org.json.JSONObject(value).optString("result_id")
                            }.getOrNull()
                            if (success && !parsed.isNullOrBlank() && parsed != "null") {
                                reportId = parsed
                            }
                            status = value
                        }
                    },
                    enabled = !busy && jobId.isNotBlank(),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Check job status")
                }
                OutlinedTextField(
                    value = reportId,
                    onValueChange = { reportId = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Investigation report ID") },
                    singleLine = true
                )
                Button(
                    onClick = {
                        busy = true
                        onFetchReport(serverUrl, caseId, reportId) { value, success ->
                            busy = false
                            status = value
                        }
                    },
                    enabled = !busy && caseId.isNotBlank() && reportId.isNotBlank(),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Retrieve report")
                }
            }
        }

        if (busy) {
            Text("Working…", style = MaterialTheme.typography.labelLarge)
        }
        Text("System output", style = MaterialTheme.typography.titleMedium)
        Card(modifier = Modifier.fillMaxWidth()) {
            Text(
                text = status,
                modifier = Modifier.padding(16.dp),
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace
            )
        }
        Spacer(Modifier.height(12.dp))
    }
}
