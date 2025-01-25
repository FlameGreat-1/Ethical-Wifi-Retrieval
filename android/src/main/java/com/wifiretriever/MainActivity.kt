package com.wifiretriever

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Color
import android.net.wifi.WifiConfiguration
import android.net.wifi.WifiManager
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.widget.Button
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.google.android.gms.location.FusedLocationProviderClient
import com.google.android.gms.location.LocationServices
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.MultiFormatWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.net.NetworkInterface
import java.security.KeyStore
import java.util.*
import java.util.concurrent.Executor
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class MainActivity : AppCompatActivity() {

    private lateinit var executor: Executor
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var promptInfo: BiometricPrompt.PromptInfo
    private lateinit var fusedLocationClient: FusedLocationProviderClient
    private lateinit var androidCredentialManager: AndroidCredentialManager
    private lateinit var secureADB: SecureADB
    private lateinit var apiService: ApiService
    private lateinit var integrityChecker: IntegrityChecker

    private val LOCATION_PERMISSION_REQUEST_CODE = 1

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        executor = ContextCompat.getMainExecutor(this)
        fusedLocationClient = LocationServices.getFusedLocationProviderClient(this)
        androidCredentialManager = AndroidCredentialManager(this)
        integrityChecker = IntegrityChecker(this)
        secureADB = SecureADB(this)

        setupBiometricAuthentication()
        setupApiService()
        checkAndRequestPermissions()

        if (!integrityChecker.verifyIntegrity()) {
            Toast.makeText(this, "App integrity check failed. Exiting.", Toast.LENGTH_LONG).show()
            finish()
            return
        }

        val userId = getCurrentUserId()
        val ipAddress = getLocalIpAddress()
        val ipAddressAlt = getLocalIpAddressFromNetworkInterface()

        // Start the PasswordUpdateService
        startService(Intent(this, PasswordUpdateService::class.java))
    }

    private fun setupBiometricAuthentication() {
        biometricPrompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    retrieveWiFiPassword()
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    Toast.makeText(this@MainActivity, "Authentication failed", Toast.LENGTH_SHORT).show()
                }
            })

        promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Biometric Authentication")
            .setSubtitle("Log in using your biometric credential")
            .setNegativeButtonText("Cancel")
            .build()
    }

    private fun setupApiService() {
        val retrofit = Retrofit.Builder()
            .baseUrl("https://api.wifiretriever.com/")
            .addConverterFactory(GsonConverterFactory.create())
            .build()

        apiService = retrofit.create(ApiService::class.java)
    }

    private fun checkAndRequestPermissions() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION)
            != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this,
                arrayOf(Manifest.permission.ACCESS_FINE_LOCATION),
                LOCATION_PERMISSION_REQUEST_CODE)
        } else {
            biometricPrompt.authenticate(promptInfo)
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        when (requestCode) {
            LOCATION_PERMISSION_REQUEST_CODE -> {
                if ((grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED)) {
                    biometricPrompt.authenticate(promptInfo)
                } else {
                    Toast.makeText(this, "Location permission is required", Toast.LENGTH_LONG).show()
                }
                return
            }
        }
    }

    private fun isPasswordValid(ssid: String, password: String): Boolean {
        val wifiManager = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val wifiConfig = WifiConfiguration().apply {
            SSID = "\"$ssid\""
            preSharedKey = "\"$password\""
        }
        val netId = wifiManager.addNetwork(wifiConfig)
        if (netId == -1) return false
        
        wifiManager.disconnect()
        val success = wifiManager.enableNetwork(netId, true)
        wifiManager.reconnect()
        
        // Wait for connection attempt
        Thread.sleep(5000)
        
        val connectionInfo = wifiManager.connectionInfo
        val isConnected = connectionInfo != null && connectionInfo.ssid == "\"$ssid\""
        
        // Clean up
        wifiManager.removeNetwork(netId)
        
        return isConnected
    }

    private fun retrieveWiFiPassword() {
        lifecycleScope.launch {
            try {
                val location = withContext(Dispatchers.IO) {
                    fusedLocationClient.lastLocation.await()
                }

                val ssid = getCurrentSSID()
                val request = RetrievalRequest(
                    ssid = ssid,
                    platform = "android",
                    latitude = location.latitude,
                    longitude = location.longitude
                )
                
                val response = apiService.retrieveWifiPassword(request)
                
                if (response.isSuccessful) {
                    val result = response.body()
                    val password = result?.password
                    val qrCode = result?.qrCode
                    
                    if (password != null && isPasswordValid(ssid, password)) {
                        handleRetrievedPassword(password, qrCode)
                    } else {
                        // Password is invalid, attempt to get the updated password
                        val updatedPasswordResponse = apiService.getUpdatedPassword(request)
                        if (updatedPasswordResponse.isSuccessful) {
                            val updatedResult = updatedPasswordResponse.body()
                            val updatedPassword = updatedResult?.password
                            val updatedQrCode = updatedResult?.qrCode
                            if (updatedPassword != null) {
                                handleRetrievedPassword(updatedPassword, updatedQrCode)
                                // Update the stored password
                                updateStoredPassword(ssid, updatedPassword)
                            } else {
                                Toast.makeText(this@MainActivity, "Failed to retrieve updated password", Toast.LENGTH_SHORT).show()
                            }
                        } else {
                            Toast.makeText(this@MainActivity, "Failed to retrieve updated password", Toast.LENGTH_SHORT).show()
                        }
                    }
                } else {
                    Toast.makeText(this@MainActivity, "Failed to retrieve password", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                Toast.makeText(this@MainActivity, "Error: ${e.message}", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun updateStoredPassword(ssid: String, newPassword: String) {
        lifecycleScope.launch {
            try {
                val result = apiService.updateWifiPassword(UpdatePasswordRequest(ssid, newPassword))
                if (result.isSuccessful) {
                    Toast.makeText(this@MainActivity, "Password updated successfully", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(this@MainActivity, "Failed to update password", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                Toast.makeText(this@MainActivity, "Error updating password: ${e.message}", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun getCurrentSSID(): String {
        val wifiManager = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val wifiInfo = wifiManager.connectionInfo
        return wifiInfo.ssid.removeSurrounding("\"")
    }

    private fun decryptPassword(encryptedPassword: String): String {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        val secretKey = keyStore.getKey("wifi_password_key", null) as SecretKey
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, Base64.decode(encryptedPassword.substring(0, 24), Base64.DEFAULT))
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)

        val decodedData = Base64.decode(encryptedPassword.substring(24), Base64.DEFAULT)
        return String(cipher.doFinal(decodedData))
    }

    private fun handleRetrievedPassword(password: String?, qrCode: String?) {
        if (password == null || qrCode == null) {
            Toast.makeText(this, "Failed to retrieve WiFi credentials", Toast.LENGTH_LONG).show()
            return
        }

        // Create a custom dialog
        val dialog = android.app.Dialog(this)
        dialog.requestWindowFeature(android.view.Window.FEATURE_NO_TITLE)
        dialog.setCancelable(false)
        dialog.setContentView(R.layout.dialog_wifi_credentials)

        // Initialize dialog views
        val tvSsid = dialog.findViewById<TextView>(R.id.tvSsid)
        val tvPassword = dialog.findViewById<TextView>(R.id.tvPassword)
        val ivQrCode = dialog.findViewById<ImageView>(R.id.ivQrCode)
        val btnCopy = dialog.findViewById<Button>(R.id.btnCopy)
        val btnDismiss = dialog.findViewById<Button>(R.id.btnDismiss)

        // Set SSID and password
        tvSsid.text = "SSID: ${getCurrentSSID()}"
        tvPassword.text = "Password: $password"

        // Generate and display QR code
        val qrBitmap = generateQrCodeBitmap(qrCode)
        ivQrCode.setImageBitmap(qrBitmap)

        // Set up copy button
        btnCopy.setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("WiFi Password", password)
            clipboard.setPrimaryClip(clip)
            Toast.makeText(this, "Password copied to clipboard", Toast.LENGTH_SHORT).show()
        }

        // Set up dismiss button
        btnDismiss.setOnClickListener {
            dialog.dismiss()
        }

        // Show the dialog
        dialog.show()

        // Set up a timer to automatically dismiss the dialog after 30 seconds
        Handler(Looper.getMainLooper()).postDelayed({
            if (dialog.isShowing) {
                dialog.dismiss()
            }
        }, 30000) // 30 seconds

        // Log the access
        logPasswordAccess()
    }

    private fun generateQrCodeBitmap(qrCodeContent: String): Bitmap {
        val width = 300
        val height = 300
        val hints = hashMapOf<EncodeHintType, Any>().apply {
            put(EncodeHintType.MARGIN, 1)
            put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.H)
        }
        val bitMatrix = MultiFormatWriter().encode(qrCodeContent, BarcodeFormat.QR_CODE, width, height, hints)
        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
        for (x in 0 until width) {
            for (y in 0 until height) {
                bitmap.setPixel(x, y, if (bitMatrix[x, y]) Color.BLACK else Color.WHITE)
            }
        }
        return bitmap
    }

    private fun logPasswordAccess() {
        lifecycleScope.launch {
            try {
                val location = withContext(Dispatchers.IO) {
                    fusedLocationClient.lastLocation.await()
                }
                val accessLog = AccessLog(
                    userId = getCurrentUserId(),
                    action = "PASSWORD_RETRIEVAL",
                    timestamp = System.currentTimeMillis(),
                    ipAddress = getLocalIpAddress(),
                    deviceType = android.os.Build.MODEL,
                    latitude = location.latitude,
                    longitude = location.longitude
                )
                apiService.logAccess(accessLog)
            } catch (e: Exception) {
                android.util.Log.e("MainActivity", "Failed to log password access: ${e.message}")
            }
        }
    }

    private fun generateEncryptionKey() {
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val keyGenParameterSpec = KeyGenParameterSpec.Builder("wifi_password_key",
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .build()

        keyGenerator.init(keyGenParameterSpec)
        keyGenerator.generateKey()
    }

    private fun getCurrentUserId(): String {
        val sharedPrefs = getSharedPreferences("user_prefs", Context.MODE_PRIVATE)
        var userId = sharedPrefs.getString("user_id", null)
        if (userId == null) {
            userId = UUID.randomUUID().toString()
            sharedPrefs.edit().putString("user_id", userId).apply()
        }
        return userId
    }

    private fun getLocalIpAddress(): String {
        val wifiManager = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val wifiInfo = wifiManager.connectionInfo
        val ipAddress = wifiInfo.ipAddress
        return String.format(
            "%d.%d.%d.%d",
            ipAddress and 0xff,
            ipAddress shr 8 and 0xff,
            ipAddress shr 16 and 0xff,
            ipAddress shr 24 and 0xff
        )
    }

    private fun getLocalIpAddressFromNetworkInterface(): String {
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces()
            while (interfaces.hasMoreElements()) {
                val networkInterface = interfaces.nextElement()
                val addresses = networkInterface.inetAddresses
                while (addresses.hasMoreElements()) {
                    val address = addresses.nextElement()
                    if (!address.isLoopbackAddress && address.hostAddress.indexOf(':') < 0) {
                        return address.hostAddress
                    }
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return "Unknown"
    }
}

interface ApiService {
    @retrofit2.http.POST("retrieve-wifi-password")
    suspend fun retrieveWifiPassword(@retrofit2.http.Body request: RetrievalRequest): retrofit2.Response<RetrievalResponse>

    @retrofit2.http.POST("update-wifi-password")
    suspend fun updateWifiPassword(@retrofit2.http.Body request: UpdatePasswordRequest): retrofit2.Response<Unit>

    @retrofit2.http.POST("get-updated-password")
    suspend fun getUpdatedPassword(@retrofit2.http.Body request: RetrievalRequest): retrofit2.Response<RetrievalResponse>

    @retrofit2.http.POST("log-access")
    suspend fun logAccess(@retrofit2.http.Body accessLog: AccessLog): retrofit2.Response<Unit>
}

data class RetrievalRequest(
    val ssid: String,
    val platform: String,
    val latitude: Double,
    val longitude: Double
)

data class RetrievalResponse(
    val password: String,
    val qrCode: String
)

data class UpdatePasswordRequest(
    val ssid: String,
    val newPassword: String
)

data class AccessLog(
    val userId: String,
    val action: String,
    val timestamp: Long,
    val ipAddress: String,
    val deviceType: String,
    val latitude: Double,
    val longitude: Double
)
