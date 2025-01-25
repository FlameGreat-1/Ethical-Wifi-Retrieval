package com.wifiretriever

import android.content.Context
import android.net.wifi.WifiManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class AndroidCredentialManager(private val context: Context) {
    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val keyAlias = "wifi_key_alias"

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

    fun getWifiPassword(ssid: String): String {
        val wifiManager = context.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val configs = wifiManager.configuredNetworks

        return configs.firstOrNull { it.SSID == ssid }?.preSharedKey?.let { encryptedPassword ->
            decryptPassword(encryptedPassword)
        } ?: throw IllegalArgumentException("SSID not found")
    }

    private fun decryptPassword(encryptedPassword: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val secretKey = keyStore.getKey(keyAlias, null) as SecretKey
        val encryptedBytes = Base64.decode(encryptedPassword, Base64.DEFAULT)
        val iv = encryptedBytes.sliceArray(0 until 12)
        val ciphertext = encryptedBytes.sliceArray(12 until encryptedBytes.size)

        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
        return String(cipher.doFinal(ciphertext), Charsets.UTF_8)
    }

    fun encryptPassword(password: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val secretKey = keyStore.getKey(keyAlias, null) as SecretKey
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
     
     fun getWifiPassword(ssid: String): String {
    val wifiManager = context.getSystemService(Context.WIFI_SERVICE) as WifiManager
    val configs = wifiManager.configuredNetworks
    
    return configs.firstOrNull { it.SSID == ssid }?.preSharedKey?.let { 
        // Decrypt using Android Keystore
        val keystore = KeyStore.getInstance("AndroidKeyStore")
        keystore.load(null)
        val key = keystore.getKey("wifi_key_alias", null)
        Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE, key)
            doFinal(Base64.decode(it, Base64.DEFAULT))
        }.toString(Charsets.UTF_8)
    } ?: throw IllegalArgumentException("SSID not found")
}


        val encryptedBytes = cipher.doFinal(password.toByteArray(Charsets.UTF_8))
        val combined = cipher.iv + encryptedBytes
        return Base64.encodeToString(combined, Base64.DEFAULT)
    }
}
