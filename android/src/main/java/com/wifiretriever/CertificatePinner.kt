
import okhttp3.CertificatePinner
import okhttp3.OkHttpClient

class SecureHttpClient {
    private val certificatePinner = CertificatePinner.Builder()
        .add("api.wifiretriever.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        .add("api.wifiretriever.com", "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
        .build()

    private val client = OkHttpClient.Builder()
        .certificatePinner(certificatePinner)
        .build()

    fun makeRequest(url: String): String {
        val request = okhttp3.Request.Builder()
            .url(url)
            .build()

        val response = client.newCall(request).execute()
        return response.body?.string() ?: throw IOException("Empty response body")
    }
}

