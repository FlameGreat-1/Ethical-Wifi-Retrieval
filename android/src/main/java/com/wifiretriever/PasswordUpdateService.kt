package com.wifiretriever

import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.os.Handler
import android.os.Looper
import android.content.Context
import android.net.wifi.WifiManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory

class PasswordUpdateService : Service() {
    private val handler = Handler(Looper.getMainLooper())
    private val updateInterval = 24 * 60 * 60 * 1000L // 24 hours
    private lateinit var apiService: ApiService
    private lateinit var androidCredentialManager: AndroidCredentialManager

    override fun onCreate() {
        super.onCreate()
        setupApiService()
        androidCredentialManager = AndroidCredentialManager(this)
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        scheduleUpdate()
        return START_STICKY
    }

    private fun setupApiService() {
        val retrofit = Retrofit.Builder()
            .baseUrl("https://api.wifiretriever.com/")
            .addConverterFactory(GsonConverterFactory.create())
            .build()

        apiService = retrofit.create(ApiService::class.java)
    }

    private fun scheduleUpdate() {
        handler.postDelayed({
            checkAndUpdatePasswords()
            scheduleUpdate()
        }, updateInterval)
    }

    private fun checkAndUpdatePasswords() {
        CoroutineScope(Dispatchers.IO).launch {
            val wifiManager = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            val configuredNetworks = wifiManager.configuredNetworks

            for (network in configuredNetworks) {
                val ssid = network.SSID.removeSurrounding("\"")
                val storedPassword = androidCredentialManager.getWifiPassword(ssid)

                try {
                    val response = apiService.getUpdatedPassword(RetrievalRequest(
                        ssid = ssid,
                        platform = "android",
                        latitude = 0.0, // We don't need accurate location for background updates
                        longitude = 0.0
                    ))

                    if (response.isSuccessful) {
                        val updatedPassword = response.body()?.password
                        if (updatedPassword != null && updatedPassword != storedPassword) {
                            // Update the password in the system
                            val updateResult = updateWifiPassword(ssid, updatedPassword)
                            if (updateResult) {
                                // Update the password in our secure storage
                                androidCredentialManager.storeWifiPassword(ssid, updatedPassword)
                                
                                // Log the update
                                apiService.logAccess(AccessLog(
                                    userId = androidCredentialManager.getCurrentUserId(),
                                    action = "PASSWORD_AUTO_UPDATE",
                                    timestamp = System.currentTimeMillis(),
                                    ipAddress = androidCredentialManager.getLocalIpAddress(),
                                    deviceType = android.os.Build.MODEL,
                                    latitude = 0.0,
                                    longitude = 0.0
                                ))
                            }
                        }
                    }
                } catch (e: Exception) {
                    // Log the error, but continue with other networks
                    android.util.Log.e("PasswordUpdateService", "Error updating password for $ssid: ${e.message}")
                }
            }
        }
    }

    private fun updateWifiPassword(ssid: String, newPassword: String): Boolean {
        val wifiManager = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val configuredNetworks = wifiManager.configuredNetworks

        for (network in configuredNetworks) {
            if (network.SSID == "\"$ssid\"") {
                // Remove the old configuration
                wifiManager.removeNetwork(network.networkId)
                
                // Add the new configuration
                val newConfig = android.net.wifi.WifiConfiguration().apply {
                    SSID = "\"$ssid\""
                    preSharedKey = "\"$newPassword\""
                }
                
                val newNetworkId = wifiManager.addNetwork(newConfig)
                if (newNetworkId != -1) {
                    wifiManager.enableNetwork(newNetworkId, false)
                    wifiManager.saveConfiguration()
                    return true
                }
            }
        }
        return false
    }
}
