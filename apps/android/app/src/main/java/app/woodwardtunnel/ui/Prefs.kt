package app.woodwardtunnel.ui

import android.content.Context
import java.net.InetAddress

/** Non-secret app preferences. */
object Prefs {
    private const val FILE = "wt_prefs"
    private const val K_SELECTED = "selected_profile"
    private const val K_DNS = "dns_servers"
    val DEFAULT_DNS = listOf("1.1.1.1", "8.8.8.8")

    private fun sp(c: Context) = c.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    fun selectedId(c: Context): String? = sp(c).getString(K_SELECTED, null)
    fun setSelectedId(c: Context, id: String?) = sp(c).edit().putString(K_SELECTED, id).apply()

    fun dnsServers(c: Context): List<String> =
        sp(c).getString(K_DNS, null)?.let(::parseDns)?.takeIf { it.isNotEmpty() } ?: DEFAULT_DNS

    fun setDnsServers(c: Context, servers: List<String>) =
        sp(c).edit().putString(K_DNS, servers.joinToString(",")).apply()

    /** Parses "a, b" into valid IP literals; returns null when any entry is not an IP address. */
    fun parseDns(text: String): List<String>? {
        val parts = text.split(',', ';', ' ', '\n').map { it.trim() }.filter { it.isNotEmpty() }
        if (parts.isEmpty() || parts.size > 4) return null
        for (p in parts) if (!isIpLiteral(p)) return null
        return parts
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
