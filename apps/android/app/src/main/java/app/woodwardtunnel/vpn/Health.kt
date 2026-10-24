package app.woodwardtunnel.vpn

/**
 * Pure logic of the "is the tunnel really working" checks. No Android dependency, covered by JVM unit tests.
 * The network part lives in [NetChecks]; this file only decides what its results mean.
 */
enum class Check { DNS_1, DNS_2, HTTPS_GOOGLE, HTTPS_CLOUDFLARE, UDP, IPV6, EGRESS }

enum class Status { OK, FAIL, SKIPPED }

data class CheckResult(val check: Check, val status: Status) {
    val ok: Boolean get() = status == Status.OK
}

/** Why a connection is "connected but limited". Order is the order they are reported in. */
enum class Limit { DNS_PARTIAL, HTTPS_PARTIAL, UDP, SAME_EGRESS, UNVERIFIED }

sealed interface Verdict {
    /** Everything that was checked works. */
    data object Healthy : Verdict

    /** The web works but something else does not; the app stays connected and shows one line. */
    data class Limited(val reasons: List<Limit>) : Verdict

    /** Neither DNS nor HTTPS works through the tunnel. */
    data object NoInternet : Verdict

    /** The direct (non-VPN) path works and traffic does not use the tunnel. */
    data object NotThroughVpn : Verdict
}

object Health {
    /**
     * Aggregates the layered check:
     *  - DNS: at least one of the two names must resolve.
     *  - HTTPS 204: at least one of the two targets must answer. Both must for Healthy.
     *  - UDP failing, or only one DNS name / HTTPS target working, makes the result Limited.
     *  - IPv6 is informational and never changes the verdict.
     *  - EGRESS FAIL means the direct path works and the OS does not route this app through the tunnel.
     */
    fun verdict(results: List<CheckResult>): Verdict {
        fun st(c: Check): Status = results.firstOrNull { it.check == c }?.status ?: Status.SKIPPED
        if (st(Check.EGRESS) == Status.FAIL) return Verdict.NotThroughVpn
        val dnsOk = listOf(st(Check.DNS_1), st(Check.DNS_2)).count { it == Status.OK }
        val httpsOk = listOf(st(Check.HTTPS_GOOGLE), st(Check.HTTPS_CLOUDFLARE)).count { it == Status.OK }
        if (httpsOk == 0) return Verdict.NoInternet
        val limits = buildList {
            if (dnsOk < 2) add(Limit.DNS_PARTIAL)
            if (httpsOk < 2) add(Limit.HTTPS_PARTIAL)
            if (st(Check.UDP) == Status.FAIL) add(Limit.UDP)
        }
        return if (limits.isEmpty()) Verdict.Healthy else Verdict.Limited(limits)
    }

    /** `ip=` line of Cloudflare's /cdn-cgi/trace, or null. The value is only compared, never shown or stored. */
    fun parseTraceIp(body: String?): String? {
        if (body == null) return null
        for (line in body.lineSequence()) {
            val l = line.trim()
            if (l.startsWith("ip=")) {
                val v = l.removePrefix("ip=").trim()
                if (v.isNotEmpty() && v.length <= 45 && v.all { it.isLetterOrDigit() || it == '.' || it == ':' }) return v
            }
        }
        return null
    }

    /**
     * Egress comparison. [vpnIp] is the address seen through the tunnel, [directIp] the one seen over the
     * real network (null when that path is blocked or unavailable, which skips the comparison).
     * Identical addresses are only a failure when the OS does not route this app into the VPN
     * ([osRoutesThroughVpn] false); when it does, the server simply shares the phone's public address.
     */
    fun egress(vpnIp: String?, directIp: String?, osRoutesThroughVpn: Boolean): EgressOutcome = when {
        vpnIp == null || directIp == null -> EgressOutcome(Status.SKIPPED, sameAddress = false)
        vpnIp != directIp -> EgressOutcome(Status.OK, sameAddress = false)
        osRoutesThroughVpn -> EgressOutcome(Status.OK, sameAddress = true)
        else -> EgressOutcome(Status.FAIL, sameAddress = true)
    }

    data class EgressOutcome(val status: Status, val sameAddress: Boolean)
}

/** Exponential backoff with jitter for automatic reconnects. */
object Backoff {
    const val BASE_MS = 2_000L
    const val CAP_MS = 60_000L

    /** [attempt] starts at 0; [random] is in [0,1). The result never exceeds [CAP_MS]. */
    fun delayMs(attempt: Int, random: Double): Long {
        val exp = BASE_MS shl attempt.coerceIn(0, 10)
        val capped = minOf(exp, CAP_MS)
        val jitter = 0.75 + 0.5 * random.coerceIn(0.0, 1.0)
        return minOf((capped * jitter).toLong(), CAP_MS)
    }
}

/**
 * Decides what the periodic health check does with each result: a first failure only schedules a quick
 * re-check; [threshold] consecutive failures mean "reconnect".
 */
class HealthMachine(private val threshold: Int = 2) {
    enum class Step { HEALTHY, SUSPECT, RECONNECT }

    var failures: Int = 0
        private set

    fun onCheck(ok: Boolean): Step {
        if (ok) {
            failures = 0
            return Step.HEALTHY
        }
        failures++
        return if (failures >= threshold) Step.RECONNECT else Step.SUSPECT
    }

    fun reset() {
        failures = 0
    }

    companion object {
        const val INTERVAL_MS = 20_000L
        const val INTERVAL_SCREEN_OFF_MS = 60_000L
        const val RECHECK_MS = 5_000L
        const val AFTER_NETWORK_CHANGE_MS = 3_000L

        /** Delay before the next check: quick re-check after a failure, slower while the screen is off. */
        fun nextDelayMs(failures: Int, screenOn: Boolean): Long = when {
            failures > 0 -> RECHECK_MS
            screenOn -> INTERVAL_MS
            else -> INTERVAL_SCREEN_OFF_MS
        }
    }
}
