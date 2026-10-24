package app.woodwardtunnel.vpn

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.security.SecureRandom
import java.util.concurrent.Callable
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors

/**
 * Network side of the health checks. Everything here talks to public endpoints over the process's default
 * network, which is the VPN while the tunnel is up. No response body is kept except the `ip=` line of the
 * trace (compared, never stored or logged). [cancel] aborts checks in flight.
 */
object Probe {
    const val URL_GOOGLE = "https://www.google.com/generate_204"
    const val URL_CLOUDFLARE = "https://cp.cloudflare.com/generate_204"
    const val URL_TRACE = "https://cp.cloudflare.com/cdn-cgi/trace"
    private const val HOST_1 = "www.google.com"
    private const val HOST_2 = "cp.cloudflare.com"

    private val inflight = ConcurrentHashMap.newKeySet<Any>()
    private val pool = Executors.newCachedThreadPool { Thread(it, "wt-probe").apply { isDaemon = true } }

    /** Aborts every check in flight (user cancelled, or the tunnel is being torn down). */
    fun cancel() {
        for (o in inflight.toList()) runCatching {
            when (o) {
                is HttpURLConnection -> o.disconnect()
                is Socket -> o.close()
                is DatagramSocket -> o.close()
            }
        }
    }

    private fun <T : Any> tracked(o: T, block: (T) -> Boolean): Boolean {
        inflight.add(o)
        return try {
            block(o)
        } catch (e: Exception) {
            false
        } finally {
            inflight.remove(o)
        }
    }

    // ---- single checks ----

    fun dns(host: String): Boolean = try {
        InetAddress.getAllByName(host).isNotEmpty()
    } catch (e: Exception) {
        false
    }

    /** HTTPS 204 through [network] (null = process default, i.e. the VPN). */
    fun https204(url: String, timeoutMs: Int, network: Network? = null): Boolean = try {
        val c = open(url, timeoutMs, network)
        tracked(c) { it.responseCode in 200..399 }.also { runCatching { c.disconnect() } }
    } catch (e: Exception) {
        false
    }

    /** The `ip=` value of the trace endpoint over [network] (null = process default), or null. */
    fun traceIp(timeoutMs: Int, network: Network? = null): String? = try {
        val c = open(URL_TRACE, timeoutMs, network)
        var body: String? = null
        tracked(c) { conn ->
            if (conn.responseCode == 200) {
                body = conn.inputStream.use { it.readNBytes(4096).toString(Charsets.UTF_8) }
                true
            } else false
        }
        runCatching { c.disconnect() }
        Health.parseTraceIp(body)
    } catch (e: Exception) {
        null
    }

    private fun open(url: String, timeoutMs: Int, network: Network?): HttpURLConnection {
        val u = URL(url)
        val c = (if (network != null) network.openConnection(u) else u.openConnection()) as HttpURLConnection
        c.connectTimeout = timeoutMs
        c.readTimeout = timeoutMs
        c.instanceFollowRedirects = false
        c.useCaches = false
        return c
    }

    /**
     * UDP through the tunnel: a STUN binding request to a public server. (A plain DNS query would prove
     * nothing: the engine answers every port-53 query itself, over TCP.) OK when any server answers.
     */
    fun udp(timeoutMs: Int): Boolean {
        for ((host, port) in listOf("stun.l.google.com" to 19302, "stun.cloudflare.com" to 3478)) {
            val ok = try {
                val addr = InetAddress.getAllByName(host).firstOrNull { it.address.size == 4 } ?: continue
                tracked(DatagramSocket()) { s ->
                    s.soTimeout = timeoutMs
                    val req = ByteArray(20)
                    req[0] = 0; req[1] = 1 // binding request
                    req[4] = 0x21; req[5] = 0x12; req[6] = 0xA4.toByte(); req[7] = 0x42 // magic cookie
                    val tid = ByteArray(12).also { SecureRandom().nextBytes(it) }
                    System.arraycopy(tid, 0, req, 8, 12)
                    s.send(DatagramPacket(req, req.size, InetSocketAddress(addr, port)))
                    val buf = ByteArray(512)
                    val p = DatagramPacket(buf, buf.size)
                    s.receive(p)
                    p.length >= 20 && buf[0].toInt() == 1 && buf[1].toInt() == 1 &&
                        (8 until 20).all { buf[it] == req[it] } // success response, same transaction id
                }
            } catch (e: Exception) {
                false
            }
            if (ok) return true
        }
        return false
    }

    /** IPv6 reachability through the tunnel: a TCP connect to a public resolver. Informational only. */
    fun ipv6(timeoutMs: Int): Boolean = tracked(Socket()) { s ->
        s.connect(InetSocketAddress(InetAddress.getByName("2606:4700:4700::1111"), 443), timeoutMs)
        true
    }

    /** Whether the OS routes this app's default traffic into a VPN (so identical addresses mean a shared egress). */
    fun osRoutesThroughVpn(cm: ConnectivityManager): Boolean {
        val caps = cm.getNetworkCapabilities(cm.activeNetwork) ?: return false
        return caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
    }

    // ---- layered checks ----

    private fun <T> parallel(vararg jobs: () -> T): List<T> =
        pool.invokeAll(jobs.map { j -> Callable { j() } }).map { it.get() }

    /** Fast check used by the monitor: DNS and HTTPS to the two targets, in parallel. True when HTTPS works. */
    fun light(timeoutMs: Int = 6000): Boolean {
        val r = parallel(
            { https204(URL_GOOGLE, timeoutMs) },
            { https204(URL_CLOUDFLARE, timeoutMs) },
        )
        return r.any { it }
    }

    /**
     * Full layered check: DNS (two names), HTTPS to two targets, UDP, and the egress comparison against
     * [direct] (the real non-VPN network, or null). Runs the independent parts in parallel.
     */
    fun full(cm: ConnectivityManager, direct: Network?, timeoutMs: Int = 7000): List<CheckResult> {
        val res = parallel(
            { dns(HOST_1) },
            { dns(HOST_2) },
            { https204(URL_GOOGLE, timeoutMs) },
            { https204(URL_CLOUDFLARE, timeoutMs) },
            { udp(3000) },
            { traceIp(timeoutMs) },
            { if (direct != null) traceIp(timeoutMs, direct) else null },
        )
        val out = mutableListOf(
            CheckResult(Check.DNS_1, st(res[0] as Boolean)),
            CheckResult(Check.DNS_2, st(res[1] as Boolean)),
            CheckResult(Check.HTTPS_GOOGLE, st(res[2] as Boolean)),
            CheckResult(Check.HTTPS_CLOUDFLARE, st(res[3] as Boolean)),
            CheckResult(Check.UDP, st(res[4] as Boolean)),
        )
        val e = Health.egress(res[5] as String?, res[6] as String?, osRoutesThroughVpn(cm))
        out += CheckResult(Check.EGRESS, e.status)
        lastSameEgress = e.sameAddress
        return out
    }

    @Volatile
    var lastSameEgress: Boolean = false
        private set

    private fun st(b: Boolean) = if (b) Status.OK else Status.FAIL
}
