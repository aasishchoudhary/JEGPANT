package com.jegpant.app.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

enum class KeySecurityLevel {
    STRONGBOX,
    TRUSTED_ENVIRONMENT,
    SOFTWARE,
    UNKNOWN
}

data class KeyDescriptor(
    val alias: String,
    val algorithm: String,
    val publicKeyDer: ByteArray,
    val securityLevel: KeySecurityLevel
) {
    val publicKeyBase64: String
        get() = Base64.encodeToString(publicKeyDer, Base64.NO_WRAP)

    val isHardwareBacked: Boolean
        get() = securityLevel == KeySecurityLevel.STRONGBOX ||
            securityLevel == KeySecurityLevel.TRUSTED_ENVIRONMENT
}

class AndroidKeystoreIdentity(private val context: Context) {
    companion object {
        const val OWNER_ALIAS = "jegpant.owner.ec-p256.v1"
        const val DEVICE_ALIAS = "jegpant.device.ec-p256.v1"
        const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
        const val API_KEY_ALGORITHM = "ecdsa_p256"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }

    private fun keyStore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    fun ownerKey(): KeyDescriptor = ensureKey(OWNER_ALIAS)

    fun deviceKey(): KeyDescriptor = ensureKey(DEVICE_ALIAS)

    @Synchronized
    private fun ensureKey(alias: String): KeyDescriptor {
        val store = keyStore()
        if (!store.containsAlias(alias)) {
            generateKey(alias, preferStrongBox = true)
        }
        return describeKey(alias)
    }

    private fun generateKey(alias: String, preferStrongBox: Boolean) {
        fun generator(): KeyPairGenerator =
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)

        fun specification(useStrongBox: Boolean): KeyGenParameterSpec {
            val builder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setKeySize(256)
                .setDigests(KeyProperties.DIGEST_SHA256)
                // The signing key is non-exportable. Biometric gating is a separate
                // product control and is not silently claimed by this prototype.
                .setUserAuthenticationRequired(false)

            if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                builder.setIsStrongBoxBacked(true)
            }
            return builder.build()
        }

        val supportsStrongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(
                PackageManager.FEATURE_STRONGBOX_KEYSTORE
            )

        if (preferStrongBox && supportsStrongBox) {
            try {
                generator().initialize(specification(useStrongBox = true))
                generator().generateKeyPair()
                return
            } catch (_: StrongBoxUnavailableException) {
                keyStore().deleteEntry(alias)
            }
        }

        generator().initialize(specification(useStrongBox = false))
        generator().generateKeyPair()
    }

    private fun describeKey(alias: String): KeyDescriptor {
        val store = keyStore()
        val certificate = store.getCertificate(alias)
            ?: throw IllegalStateException("Android Keystore public certificate is missing")
        val privateKey = store.getKey(alias, null) as? PrivateKey
            ?: throw IllegalStateException("Android Keystore private key is missing")
        val factory = KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEYSTORE)
        val info = factory.getKeySpec(privateKey, KeyInfo::class.java)

        val level = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> KeySecurityLevel.STRONGBOX
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ->
                    KeySecurityLevel.TRUSTED_ENVIRONMENT
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> KeySecurityLevel.SOFTWARE
                else -> KeySecurityLevel.UNKNOWN
            }
        } else if (info.isInsideSecureHardware) {
            KeySecurityLevel.TRUSTED_ENVIRONMENT
        } else {
            KeySecurityLevel.SOFTWARE
        }

        return KeyDescriptor(
            alias = alias,
            algorithm = API_KEY_ALGORITHM,
            publicKeyDer = certificate.publicKey.encoded,
            securityLevel = level
        )
    }

    fun sign(alias: String, message: ByteArray): ByteArray {
        val privateKey = keyStore().getKey(alias, null) as? PrivateKey
            ?: throw IllegalStateException("Signing key is not available")
        return Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initSign(privateKey)
            update(message)
            sign()
        }
    }

    fun ownerPublicKeyFingerprint(): String =
        java.security.MessageDigest.getInstance("SHA-256")
            .digest(ownerKey().publicKeyDer)
            .joinToString("") { byte -> "%02x".format(byte) }
}
