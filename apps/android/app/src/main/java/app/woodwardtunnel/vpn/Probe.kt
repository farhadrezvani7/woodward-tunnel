package app.woodwardtunnel.vpn

import java.net.HttpURLConnection
import java.net.URL

/** Checks that traffic really leaves through the tunnel (HTTPS only, nothing is read from the body). */
object Probe {
    private const val URL_204 = "https://cp.cloudflare.com/generate_204"

    fun reachable(timeoutMs: Int = 7000): Boolean = try {
        val c = URL(URL_204).openConnection() as HttpURLConnection
        c.connectTimeout = timeoutMs
        c.readTimeout = timeoutMs
        c.instanceFollowRedirects = false
        c.useCaches = false
        try {
            c.responseCode in 200..399
        } finally {
            c.disconnect()
        }
    } catch (e: Exception) {
        false
    }
}
