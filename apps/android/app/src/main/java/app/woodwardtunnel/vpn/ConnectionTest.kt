package app.woodwardtunnel.vpn

import android.content.Context
import android.net.ConnectivityManager
import androidx.annotation.StringRes
import app.woodwardtunnel.R

enum class Level { OK, WARN, FAIL, INFO }

class TestItem(@StringRes val title: Int, val level: Level, @StringRes val note: Int)

/** Runs the layered checks on demand for the "connection test" dialog and remembers the last result for the diagnostic report. */
object ConnectionTest {
    @Volatile
    private var last: List<CheckResult> = emptyList()

    @Volatile
    private var lastIpv6: Status = Status.SKIPPED

    @Volatile
    private var lastSame = false

    fun record(results: List<CheckResult>) {
        last = results
        lastSame = Probe.lastSameEgress
    }

    /** Blocking; call from a background thread. Returns null when the tunnel is not up. */
    fun run(ctx: Context): List<TestItem>? {
        val svc = TunnelService.instance
        if (svc == null || TunnelState.state.value !is ConnState.Connected) return null
        val cm = ctx.getSystemService(ConnectivityManager::class.java)
        val results = Probe.full(cm, svc.directNetwork())
        record(results)
        lastIpv6 = if (Probe.ipv6(4000)) Status.OK else Status.FAIL
        return items(results, lastIpv6, Probe.lastSameEgress)
    }

    fun items(results: List<CheckResult>, ipv6: Status, sameEgress: Boolean): List<TestItem> {
        fun st(c: Check) = results.firstOrNull { it.check == c }?.status ?: Status.SKIPPED
        val dnsOk = listOf(st(Check.DNS_1), st(Check.DNS_2)).count { it == Status.OK }
        return listOf(
            when (dnsOk) {
                2 -> TestItem(R.string.ct_dns, Level.OK, R.string.ct_ok)
                1 -> TestItem(R.string.ct_dns, Level.WARN, R.string.ct_dns_partial)
                else -> TestItem(R.string.ct_dns, Level.FAIL, R.string.ct_dns_fail)
            },
            https(R.string.ct_https_google, st(Check.HTTPS_GOOGLE)),
            https(R.string.ct_https_cloudflare, st(Check.HTTPS_CLOUDFLARE)),
            if (st(Check.UDP) == Status.OK) TestItem(R.string.ct_udp, Level.OK, R.string.ct_ok)
            else TestItem(R.string.ct_udp, Level.WARN, R.string.ct_udp_fail),
            when (ipv6) {
                Status.OK -> TestItem(R.string.ct_ipv6, Level.OK, R.string.ct_ok)
                else -> TestItem(R.string.ct_ipv6, Level.INFO, R.string.ct_ipv6_none)
            },
            when (st(Check.EGRESS)) {
                Status.OK -> if (sameEgress) TestItem(R.string.ct_egress, Level.INFO, R.string.ct_egress_same)
                else TestItem(R.string.ct_egress, Level.OK, R.string.ct_ok)
                Status.FAIL -> TestItem(R.string.ct_egress, Level.FAIL, R.string.ct_egress_fail)
                Status.SKIPPED -> TestItem(R.string.ct_egress, Level.INFO, R.string.ct_egress_skipped)
            },
        )
    }

    private fun https(@StringRes title: Int, s: Status) =
        if (s == Status.OK) TestItem(title, Level.OK, R.string.ct_ok) else TestItem(title, Level.FAIL, R.string.ct_https_fail)

    /** Plain text lines for the diagnostic report: check names and results only, no addresses. */
    fun reportLines(): List<String> {
        val svc = TunnelService.instance
        return buildList {
            add("state: " + when (val s = TunnelState.state.value) {
                is ConnState.Connected -> "connected" + if (s.limits.isNotEmpty()) " (limited: " + s.limits.joinToString { it.name.lowercase() } + ")" else ""
                is ConnState.Reconnecting -> "reconnecting"
                is ConnState.Connecting -> "connecting"
                is ConnState.Error -> "error"
                ConnState.Disconnected -> "disconnected"
            })
            add("automatic reconnects this session: ${svc?.reconnects ?: 0}")
            if (last.isEmpty()) add("last connection check: none yet")
            else {
                add("last connection check:")
                last.forEach { add("  ${it.check.name.lowercase()}: ${it.status.name.lowercase()}") }
                add("  ipv6: ${lastIpv6.name.lowercase()}")
                add("  egress address same with and without vpn: $lastSame")
            }
        }
    }
}
