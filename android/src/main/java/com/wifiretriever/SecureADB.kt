import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.io.BufferedReader
import java.io.InputStreamReader
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import javax.crypto.Cipher

class SecureADB(private val context: Context) {
    private val keyAlias = "secure_adb_key"
    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    init {
        if (!keyStore.containsAlias(keyAlias)) {
            generateKeyPair()
        }
    }

    private fun generateKeyPair() {
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
        )
        val parameterSpec = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY or
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        ).setDigests(KeyProperties.DIGEST_SHA256)
         .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
         .setUserAuthenticationRequired(true)
         .setUserAuthenticationValidityDurationSeconds(300) // 5 minutes
         .build()

        keyPairGenerator.initialize(parameterSpec)
        keyPairGenerator.generateKeyPair()
    }

    fun signCommand(command: String): String {
        val signature = Signature.getInstance("SHA256withECDSA")
        val privateKey = keyStore.getEntry(keyAlias, null) as KeyStore.PrivateKeyEntry
        signature.initSign(privateKey.privateKey)
        signature.update(command.toByteArray())
        return Base64.encodeToString(signature.sign(), Base64.DEFAULT)
    }

    fun verifySignature(command: String, signatureStr: String): Boolean {
        val signature = Signature.getInstance("SHA256withECDSA")
        val publicKey = keyStore.getCertificate(keyAlias).publicKey
        signature.initVerify(publicKey)
        signature.update(command.toByteArray())
        return signature.verify(Base64.decode(signatureStr, Base64.DEFAULT))
    }

    fun executeSecureCommand(command: String): String {
        val signature = signCommand(command)
        if (!verifySignature(command, signature)) {
            throw SecurityException("Command signature verification failed")
        }

        return try {
            val process = Runtime.getRuntime().exec(arrayOf("su", "-c", command))
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val output = StringBuilder()
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                output.append(line).append("\n")
            }
            process.waitFor()
            output.toString()
        } catch (e: Exception) {
            "Error executing command: ${e.message}"
        }
    }

    fun encryptData(data: String): String {
        val publicKey = keyStore.getCertificate(keyAlias).publicKey
        val cipher = Cipher.getInstance("ECIES")
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val encryptedBytes = cipher.doFinal(data.toByteArray())
        return Base64.encodeToString(encryptedBytes, Base64.DEFAULT)
    }

    fun decryptData(encryptedData: String): String {
        val privateKey = (keyStore.getEntry(keyAlias, null) as KeyStore.PrivateKeyEntry).privateKey
        val cipher = Cipher.getInstance("ECIES")
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        val decryptedBytes = cipher.doFinal(Base64.decode(encryptedData, Base64.DEFAULT))
        return String(decryptedBytes)
    }

    fun isRooted(): Boolean {
        val rootPaths = arrayOf("/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su")
        return rootPaths.any { java.io.File(it).exists() }
    }
}
