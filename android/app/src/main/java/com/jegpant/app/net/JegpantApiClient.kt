package com.jegpant.app.net

import android.content.ContentResolver
import android.net.Uri
import android.util.Base64
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.URL
import java.security.MessageDigest
import java.time.Instant
import java.util.UUID
import javax.net.ssl.HttpsURLConnection
import com.jegpant.app.security.AndroidKeystoreIdentity

data class ServerIdentity(
    val instanceId: String,
    val ownerKeyAlgorithm: String,
    val ownerKeyFingerprintSha256: String,
    val supportedDeviceKeyAlgorithms: List<String>
)

class JegpantApiException(
    val httpStatus: Int,
    message: String
) : IOException(message)

class JegpantApiClient(
    private val contentResolver: ContentResolver,
    private val identity: AndroidKeystoreIdentity,
    private val maximumUploadBytes: Long = 8L * 1024L * 1024L * 1024L
) {
    companion object {
        private const val CONNECT_TIMEOUT_MS = 20_000
        private const val READ_TIMEOUT_MS = 120_000
        private const val MAX_RESPONSE_BYTES = 32 * 1024 * 1024
        private const val API_KEY_ALGORITHM = "ecdsa_p256"
    }

    private fun normalizedBaseUrl(baseUrl: String): String {
        val trimmed = baseUrl.trim().trimEnd('/')
        val url = try {
            URL(trimmed)
        } catch (_: Exception) {
            throw IllegalArgumentException("Server URL is invalid")
        }
        require(url.protocol.equals("https", ignoreCase = true)) {
            "JEGPANT requires HTTPS. Do not send private evidence over cleartext HTTP."
        }
        require(url.userInfo == null && url.query == null && url.ref == null) {
            "Server URL must not include credentials, query parameters or fragments"
        }
        return trimmed
    }

    private fun openConnection(baseUrl: String, path: String): HttpsURLConnection {
        require(path.startsWith("/") && !path.startsWith("//")) {
            "API path must be an absolute origin-relative path"
        }
        val url = URL(normalizedBaseUrl(baseUrl) + path)
        return (url.openConnection() as? HttpsURLConnection
            ?: throw IOException("HTTPS connection could not be created")).apply {
            connectTimeout = CONNECT_TIMEOUT_MS
            readTimeout = READ_TIMEOUT_MS
            useCaches = false
            instanceFollowRedirects = false
            setRequestProperty("Accept", "application/json")
            setRequestProperty("User-Agent", "JEGPANT-Android/0.1.0")
        }
    }

    private fun readResponse(connection: HttpsURLConnection): ByteArray {
        val status = connection.responseCode
        val stream = if (status in 200..299) connection.inputStream else connection.errorStream
        val output = ByteArrayOutputStream()
        if (stream != null) {
            stream.use { input ->
                val buffer = ByteArray(16 * 1024)
                var total = 0
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    total += read
                    if (total > MAX_RESPONSE_BYTES) {
                        throw IOException("Server response exceeded the application size limit")
                    }
                    output.write(buffer, 0, read)
                }
            }
        }
        val bytes = output.toByteArray()
        if (status !in 200..299) {
            val detail = try {
                JSONObject(String(bytes, Charsets.UTF_8)).optString("detail")
            } catch (_: Exception) {
                ""
            }
            throw JegpantApiException(
                status,
                if (detail.isNotBlank()) "Server rejected request ($status): $detail"
                else "Server rejected request ($status)"
            )
        }
        return bytes
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { byte -> "%02x".format(byte) }

    private fun base64(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.NO_WRAP)

    private fun requestSigningBytes(
        instanceId: String,
        deviceId: String,
        requestId: String,
        method: String,
        path: String,
        issuedAt: String,
        expiresAt: String,
        bodySha256: String
    ): ByteArray = CanonicalJson.encode(
        mapOf(
            "purpose" to "jegpant.device.request.v1",
            "instance_id" to instanceId,
            "device_id" to deviceId,
            "request_id" to requestId,
            "method" to method,
            "path" to path,
            "issued_at" to issuedAt,
            "expires_at" to expiresAt,
            "body_sha256" to bodySha256
        )
    )

    private fun signedHeaders(
        method: String,
        path: String,
        instanceId: String,
        deviceId: String,
        bodySha256: String
    ): Map<String, String> {
        val issuedAt = Instant.now().toString()
        val expiresAt = Instant.now().plusSeconds(45).toString()
        val requestId = UUID.randomUUID().toString()
        val signature = identity.sign(
            AndroidKeystoreIdentity.DEVICE_ALIAS,
            requestSigningBytes(
                instanceId = instanceId,
                deviceId = deviceId,
                requestId = requestId,
                method = method,
                path = path,
                issuedAt = issuedAt,
                expiresAt = expiresAt,
                bodySha256 = bodySha256
            )
        )
        return mapOf(
            "X-Jegpant-Instance-Id" to instanceId,
            "X-Jegpant-Device-Id" to deviceId,
            "X-Jegpant-Request-Id" to requestId,
            "X-Jegpant-Issued-At" to issuedAt,
            "X-Jegpant-Expires-At" to expiresAt,
            "X-Jegpant-Body-Sha256" to bodySha256,
            "X-Jegpant-Signature" to base64(signature)
        )
    }

    private fun signedJsonRequest(
        baseUrl: String,
        instanceId: String,
        deviceId: String,
        method: String,
        path: String,
        requiredScope: String,
        payload: JSONObject
    ): JSONObject {
        val body = payload.toString().toByteArray(Charsets.UTF_8)
        val digest = sha256(body)
        val headers = signedHeaders(method, path, instanceId, deviceId, digest)
        val connection = openConnection(baseUrl, path)
        try {
            connection.requestMethod = method
            connection.doOutput = true
            connection.setFixedLengthStreamingMode(body.size)
            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
            headers.forEach(connection::setRequestProperty)
            connection.outputStream.use { it.write(body) }
            return JSONObject(String(readResponse(connection), Charsets.UTF_8))
        } finally {
            connection.disconnect()
        }
    }

    fun getServerIdentity(baseUrl: String): ServerIdentity {
        val path = "/health/identity"
        val connection = openConnection(baseUrl, path)
        try {
            connection.requestMethod = "GET"
            val json = JSONObject(String(readResponse(connection), Charsets.UTF_8))
            val algorithms = json.optJSONArray("supported_device_key_algorithms")
            val supported = buildList {
                if (algorithms != null) {
                    for (index in 0 until algorithms.length()) {
                        add(algorithms.getString(index))
                    }
                }
            }
            return ServerIdentity(
                instanceId = json.getString("instance_id"),
                ownerKeyAlgorithm = json.getString("owner_key_algorithm"),
                ownerKeyFingerprintSha256 = json.getString("owner_key_fingerprint_sha256"),
                supportedDeviceKeyAlgorithms = supported
            )
        } finally {
            connection.disconnect()
        }
    }

    fun enrollDevice(baseUrl: String, instanceId: String, deviceId: String): JSONObject {
        val owner = identity.ownerKey()
        val device = identity.deviceKey()
        require(owner.algorithm == API_KEY_ALGORITHM && device.algorithm == API_KEY_ALGORITHM) {
            "Android device enrollment requires P-256 ECDSA keys"
        }
        val issuedAt = Instant.now().toString()
        val expiresAt = Instant.now().plusSeconds(180).toString()
        val enrollmentId = UUID.randomUUID().toString()
        val scopes = listOf(
            "create_case",
            "write_evidence",
            "read_evidence",
            "ingest_media",
            "queue_analysis",
            "read_jobs",
            "read_reports"
        ).sorted()
        val canonical = CanonicalJson.encode(
            mapOf(
                "purpose" to "jegpant.device.enrollment.v1",
                "instance_id" to instanceId,
                "device_id" to deviceId,
                "device_public_key_b64" to device.publicKeyBase64,
                "device_key_algorithm" to API_KEY_ALGORITHM,
                "scopes" to scopes,
                "enrollment_id" to enrollmentId,
                "issued_at" to issuedAt,
                "expires_at" to expiresAt
            )
        )
        val ownerSignature = identity.sign(AndroidKeystoreIdentity.OWNER_ALIAS, canonical)
        val deviceProof = identity.sign(AndroidKeystoreIdentity.DEVICE_ALIAS, canonical)

        val body = JSONObject()
            .put("instance_id", instanceId)
            .put("device_id", deviceId)
            .put("device_public_key_b64", device.publicKeyBase64)
            .put("device_key_algorithm", API_KEY_ALGORITHM)
            .put("scopes", org.json.JSONArray(scopes))
            .put("enrollment_id", enrollmentId)
            .put("issued_at", issuedAt)
            .put("expires_at", expiresAt)
            .put("owner_signature_b64", base64(ownerSignature))
            .put("device_proof_b64", base64(deviceProof))

        val connection = openConnection(baseUrl, "/v1/devices/enroll")
        try {
            connection.requestMethod = "POST"
            connection.doOutput = true
            val bytes = body.toString().toByteArray(Charsets.UTF_8)
            connection.setFixedLengthStreamingMode(bytes.size)
            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
            connection.outputStream.use { it.write(bytes) }
            return JSONObject(String(readResponse(connection), Charsets.UTF_8))
        } finally {
            connection.disconnect()
        }
    }

    fun createCase(baseUrl: String, instanceId: String, deviceId: String): String {
        val response = signedJsonRequest(
            baseUrl,
            instanceId,
            deviceId,
            "POST",
            "/v1/cases",
            "create_case",
            JSONObject()
        )
        return response.getString("case_id")
    }

    fun addObservation(
        baseUrl: String,
        instanceId: String,
        deviceId: String,
        caseId: String,
        observation: String
    ): JSONObject {
        require(observation.isNotBlank()) { "Observation must not be blank" }
        val path = "/v1/cases/$caseId/evidence"
        val body = JSONObject()
            .put("record_id", UUID.randomUUID().toString())
            .put("source_ref", "owner://manual-observation")
            .put("independence_group", "owner-manual-entry")
            .put("observation", observation)
            .put("quality_level", 2)
            .put("limitations", org.json.JSONArray(listOf("Owner-entered observation; verify against source material.")))
        return signedJsonRequest(
            baseUrl,
            instanceId,
            deviceId,
            "POST",
            path,
            "write_evidence",
            body
        )
    }

    fun queueInvestigation(
        baseUrl: String,
        instanceId: String,
        deviceId: String,
        caseId: String,
        goal: String
    ): String {
        require(goal.isNotBlank()) { "Investigation goal must not be blank" }
        val path = "/v1/cases/$caseId/investigations"
        val response = signedJsonRequest(
            baseUrl,
            instanceId,
            deviceId,
            "POST",
            path,
            "queue_analysis",
            JSONObject().put("goal", goal).put("max_attempts", 3)
        )
        return response.getString("job_id")
    }

    fun getJobStatus(
        baseUrl: String,
        instanceId: String,
        deviceId: String,
        jobId: String
    ): JSONObject = signedJsonRequest(
        baseUrl,
        instanceId,
        deviceId,
        "GET",
        "/v1/jobs/$jobId",
        "read_jobs",
        JSONObject()
    )

    fun getReport(
        baseUrl: String,
        instanceId: String,
        deviceId: String,
        caseId: String,
        investigationId: String
    ): JSONObject = signedJsonRequest(
        baseUrl,
        instanceId,
        deviceId,
        "GET",
        "/v1/cases/$caseId/reports/$investigationId",
        "read_reports",
        JSONObject()
    )

    fun uploadMedia(
        baseUrl: String,
        instanceId: String,
        deviceId: String,
        caseId: String,
        uri: Uri
    ): JSONObject {
        val firstPass = hashContent(uri)
        require(firstPass.first > 0L) { "Selected video is empty" }
        require(firstPass.first <= maximumUploadBytes) {
            "Selected video exceeds the configured application upload limit"
        }

        val assetId = UUID.randomUUID().toString()
        val path = "/v1/cases/$caseId/media/$assetId"
        val headers = signedHeaders(
            "PUT",
            path,
            instanceId,
            deviceId,
            firstPass.second
        )
        val connection = openConnection(baseUrl, path)
        try {
            connection.requestMethod = "PUT"
            connection.doOutput = true
            connection.setFixedLengthStreamingMode(firstPass.first)
            connection.setRequestProperty("Content-Type", "application/octet-stream")
            connection.setRequestProperty("X-Jegpant-Content-Sha256", firstPass.second)
            connection.setRequestProperty("X-Jegpant-Content-Length", firstPass.first.toString())
            headers.forEach(connection::setRequestProperty)

            var sent = 0L
            contentResolver.openInputStream(uri)?.use { input ->
                connection.outputStream.use { output ->
                    val buffer = ByteArray(256 * 1024)
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        output.write(buffer, 0, count)
                        sent += count
                        if (sent > firstPass.first) {
                            throw IOException("Selected video changed during upload")
                        }
                    }
                }
            } ?: throw IOException("Selected video could not be opened")

            if (sent != firstPass.first) {
                throw IOException("Selected video changed between hashing and upload")
            }
            return JSONObject(String(readResponse(connection), Charsets.UTF_8))
        } finally {
            connection.disconnect()
        }
    }

    private fun hashContent(uri: Uri): Pair<Long, String> {
        val digest = MessageDigest.getInstance("SHA-256")
        var count = 0L
        contentResolver.openInputStream(uri)?.use { input ->
            val buffer = ByteArray(256 * 1024)
            while (true) {
                val size = input.read(buffer)
                if (size < 0) break
                count += size
                require(count <= maximumUploadBytes) {
                    "Selected video exceeds the configured application upload limit"
                }
                digest.update(buffer, 0, size)
            }
        } ?: throw IOException("Selected video could not be opened")
        val sha256 = digest.digest().joinToString("") { byte -> "%02x".format(byte) }
        return count to sha256
    }
}
