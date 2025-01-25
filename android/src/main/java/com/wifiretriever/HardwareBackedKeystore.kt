
import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class HardwareBackedKeystore(private val context: Context) {
    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val keyAlias = "wifi_password_key"

    init {
        if (!keyStore.containsAlias(keyAlias)) {
            generateKey()
        }
    }

    private fun generateKey() {
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationValidityDurationSeconds(300)
            .build()

        keyGenerator.init(keyGenParameterSpec)
        keyGenerator.generateKey()
    }

    fun encryptPassword(password: String): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKey())
        val iv = cipher.iv
        val encryptedBytes = cipher.doFinal(password.toByteArray(Charsets.UTF_8))
        return iv + encryptedBytes
    }

    fun decryptPassword(encryptedData: ByteArray): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val iv = encryptedData.sliceArray(0 until 12)
        val encryptedBytes = encryptedData.sliceArray(12 until encryptedData.size)
        val spec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.DECRYPT_MODE, getSecretKey(), spec)
        val decryptedBytes = cipher.doFinal(encryptedBytes)
        return String(decryptedBytes, Charsets.UTF_8)
    }

    private fun getSecretKey(): SecretKey {
        return (keyStore.getEntry(keyAlias, null) as KeyStore.SecretKeyEntry).secretKey
    }
}

// Usage in AndroidCredentialManager.kt
class AndroidCredentialManager(private val context: Context) {
    private val hardwareBackedKeystore = HardwareBackedKeystore(context)

    fun storeWifiPassword(ssid: String, password: String) {
        val encryptedPassword = hardwareBackedKeystore.encryptPassword(password)
        // Store encryptedPassword in SharedPreferences or a secure database
    }

    fun retrieveWifiPassword(ssid: String): String {
        // Retrieve encryptedPassword from SharedPreferences or a secure database
        val encryptedPassword: ByteArray = // ... retrieve encrypted password
        return hardwareBackedKeystore.decryptPassword(encryptedPassword)
    }
}
