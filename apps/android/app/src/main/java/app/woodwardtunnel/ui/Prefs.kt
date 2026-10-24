package app.woodwardtunnel.ui

import android.content.Context
import java.net.InetAddress

/** Non-secret app preferences. */
object Prefs {
    private const val FILE = "wt_prefs"
    private const val K_SELECTED = "selected_profile"
    private const val K_DNS = "dns_servers"
    private const val K_VERIFY = "verify_internet"
    /**
     * Empty means "use the core's default": DNS over HTTPS through the tunnel, which works through every proxy type
     * (plain UDP/53 fails through servers that do not relay UDP).
     */
    val DEFAULT_DNS: List<String> = emptyList()
    private const val OLD_DEFAULT = "1.1.1.1,8.8.8.8" // written by earlier versions of the settings screen

    private fun sp(c: Context) = c.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    fun selectedId(c: Context): String? = sp(c).getString(K_SELECTED, null)
    fun setSelectedId(c: Context, id: String?) = sp(c).edit().putString(K_SELECTED, id).apply()

    /** Whether "connected" requires a successful internet check through the tunnel (default on). */
    fun verifyInternet(c: Context): Boolean = sp(c).getBoolean(K_VERIFY, true)
    fun setVerifyInternet(c: Context, on: Boolean) = sp(c).edit().putBoolean(K_VERIFY, on).apply()

    fun dnsServers(c: Context): List<String> {
        val stored = sp(c).getString(K_DNS, null) ?: return DEFAULT_DNS
        if (stored == OLD_DEFAULT) return DEFAULT_DNS
        return parseDns(stored) ?: DEFAULT_DNS
    }

    fun setDnsServers(c: Context, servers: List<String>) =
        sp(c).edit().putString(K_DNS, servers.joinToString(",")).apply()

    /**
     * Parses "a, b": each entry is an IP address (plain DNS), `https://host[/path]` (DNS over HTTPS) or `tls://host`
     * (DNS over TLS). Blank means "default" (empty list). Returns null when anything is invalid.
     */
    fun parseDns(text: String): List<String>? {
        val parts = text.split(',', ';', ' ', '\n').map { it.trim() }.filter { it.isNotEmpty() }
        if (parts.size > 4) return null
        for (p in parts) if (!isIpLiteral(p) && !isDnsUrl(p)) return null
        return parts
    }

    private val hostRe = Regex("""^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(:\d{1,5})?$""")
    private val pathRe = Regex("""^/[A-Za-z0-9._~/%-]{0,200}$""")

    private fun isDnsUrl(s: String): Boolean {
        val rest = when {
            s.startsWith("https://") -> s.removePrefix("https://")
            s.startsWith("tls://") -> s.removePrefix("tls://")
            else -> return false
        }
        val slash = rest.indexOf('/')
        val host = if (slash < 0) rest else rest.substring(0, slash)
        val path = if (slash < 0) null else rest.substring(slash)
        if (s.startsWith("tls://") && path != null) return false
        return hostRe.matches(host) && (path == null || pathRe.matches(path))
    }

    private val v4 = Regex("""^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$""")

    private fun isIpLiteral(s: String): Boolean {
        if (v4.matches(s)) return true
        // Only attempt a parse for strings that look like IPv6, so no DNS lookup can happen.
        if (s.contains(':') && s.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' }) {
            return runCatching { InetAddress.getByName(s) }.isSuccess
        }
        return false
    }
}
