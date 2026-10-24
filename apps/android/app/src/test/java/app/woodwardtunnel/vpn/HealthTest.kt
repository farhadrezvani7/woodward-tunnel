package app.woodwardtunnel.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class HealthTest {
    private fun r(vararg p: Pair<Check, Status>) = p.map { CheckResult(it.first, it.second) }

    private val allOk = r(
        Check.DNS_1 to Status.OK, Check.DNS_2 to Status.OK,
        Check.HTTPS_GOOGLE to Status.OK, Check.HTTPS_CLOUDFLARE to Status.OK,
        Check.UDP to Status.OK, Check.EGRESS to Status.OK,
    )

    @Test fun everythingOkIsHealthy() = assertEquals(Verdict.Healthy, Health.verdict(allOk))

    @Test fun bothHttpsFailingIsNoInternet() {
        val v = Health.verdict(
            r(Check.DNS_1 to Status.OK, Check.DNS_2 to Status.OK, Check.HTTPS_GOOGLE to Status.FAIL, Check.HTTPS_CLOUDFLARE to Status.FAIL),
        )
        assertEquals(Verdict.NoInternet, v)
    }

    @Test fun oneHttpsTargetIsLimitedNotFailed() {
        val v = Health.verdict(
            r(Check.DNS_1 to Status.OK, Check.DNS_2 to Status.OK, Check.HTTPS_GOOGLE to Status.FAIL, Check.HTTPS_CLOUDFLARE to Status.OK),
        )
        assertEquals(Verdict.Limited(listOf(Limit.HTTPS_PARTIAL)), v)
    }

    @Test fun udpFailureKeepsConnectedButLimited() {
        val v = Health.verdict(allOk.map { if (it.check == Check.UDP) it.copy(status = Status.FAIL) else it })
        assertEquals(Verdict.Limited(listOf(Limit.UDP)), v)
    }

    @Test fun ipv6NeverChangesTheVerdict() {
        assertEquals(Verdict.Healthy, Health.verdict(allOk + CheckResult(Check.IPV6, Status.FAIL)))
    }

    @Test fun egressFailureWinsOverEverything() {
        val v = Health.verdict(allOk.map { if (it.check == Check.EGRESS) it.copy(status = Status.FAIL) else it })
        assertEquals(Verdict.NotThroughVpn, v)
    }

    @Test fun reasonsComeInStableOrder() {
        val v = Health.verdict(
            r(
                Check.DNS_1 to Status.OK, Check.DNS_2 to Status.FAIL, Check.HTTPS_GOOGLE to Status.OK,
                Check.HTTPS_CLOUDFLARE to Status.FAIL, Check.UDP to Status.FAIL,
            ),
        ) as Verdict.Limited
        assertEquals(listOf(Limit.DNS_PARTIAL, Limit.HTTPS_PARTIAL, Limit.UDP), v.reasons)
    }

    @Test fun missingResultsCountAsNotWorking() = assertEquals(Verdict.NoInternet, Health.verdict(emptyList()))

    @Test fun traceParsing() {
        assertEquals("203.0.113.9", Health.parseTraceIp("fl=1\nip=203.0.113.9\nts=1\n"))
        assertEquals("2001:db8::1", Health.parseTraceIp("ip=2001:db8::1"))
        assertNull(Health.parseTraceIp("fl=1\nts=1"))
        assertNull(Health.parseTraceIp(null))
        assertNull(Health.parseTraceIp("ip=<script>"))
        assertNull(Health.parseTraceIp("ip=" + "1".repeat(100)))
    }

    @Test fun egressComparison() {
        assertEquals(Status.OK, Health.egress("1.1.1.1", "2.2.2.2", true).status)
        assertEquals(Status.SKIPPED, Health.egress("1.1.1.1", null, true).status)
        assertEquals(Status.SKIPPED, Health.egress(null, "2.2.2.2", false).status)
        // same address while the OS routes the app into the VPN: shared egress, not a leak
        val same = Health.egress("1.1.1.1", "1.1.1.1", true)
        assertEquals(Status.OK, same.status)
        assertTrue(same.sameAddress)
        // same address and the app is not routed through the VPN: traffic is not tunnelled
        assertEquals(Status.FAIL, Health.egress("1.1.1.1", "1.1.1.1", false).status)
    }

    @Test fun backoffGrowsAndIsCapped() {
        val mid = (0..8).map { Backoff.delayMs(it, 0.5) }
        assertEquals(2_000L, mid[0])
        assertEquals(4_000L, mid[1])
        assertEquals(8_000L, mid[2])
        assertEquals(60_000L, mid[8])
        assertTrue(mid.zipWithNext().all { (a, b) -> b >= a })
        for (attempt in 0..30) for (rnd in listOf(0.0, 0.5, 0.999, 1.0, -1.0, 2.0)) {
            val d = Backoff.delayMs(attempt, rnd)
            assertTrue("attempt=$attempt rnd=$rnd d=$d", d in 1_000L..60_000L)
        }
    }

    @Test fun backoffJitterRange() {
        assertEquals(1_500L, Backoff.delayMs(0, 0.0))
        assertEquals(2_500L, Backoff.delayMs(0, 1.0))
    }

    @Test fun machineNeedsTwoConsecutiveFailures() {
        val m = HealthMachine()
        assertEquals(HealthMachine.Step.HEALTHY, m.onCheck(true))
        assertEquals(HealthMachine.Step.SUSPECT, m.onCheck(false))
        assertEquals(HealthMachine.Step.HEALTHY, m.onCheck(true)) // a success resets the count
        assertEquals(HealthMachine.Step.SUSPECT, m.onCheck(false))
        assertEquals(HealthMachine.Step.RECONNECT, m.onCheck(false))
        m.reset()
        assertEquals(0, m.failures)
        assertEquals(HealthMachine.Step.SUSPECT, m.onCheck(false))
    }

    @Test fun nextDelayRules() {
        assertEquals(20_000L, HealthMachine.nextDelayMs(0, true))
        assertEquals(60_000L, HealthMachine.nextDelayMs(0, false))
        assertEquals(5_000L, HealthMachine.nextDelayMs(1, true))
        assertEquals(5_000L, HealthMachine.nextDelayMs(1, false)) // confirm a failure quickly even with the screen off
    }
}
