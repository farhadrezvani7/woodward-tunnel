package app.woodwardtunnel.vpn

import android.net.Network
import io.nekohasekai.libbox.ExchangeContext
import io.nekohasekai.libbox.LocalDNSTransport
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.UnknownHostException

/**
 * sing-box's "local" DNS server on Android: resolves through the device's real default network
 * (never the tunnel), which is what the VPN server's own hostname needs. Name lookups only
 * (A / AAAA); [raw] is false so libbox calls [lookup].
 */
class LocalResolver(private val network: () -> Network?) : LocalDNSTransport {
    override fun raw(): Boolean = false

    override fun exchange(ctx: ExchangeContext, message: ByteArray) {
        error("raw exchange not supported")
    }

    override fun lookup(ctx: ExchangeContext, network: String, domain: String) {
        val net = this.network()
        if (net == null) {
            ctx.errorCode(RCODE_SERVFAIL)
            return
        }
        val name = domain.trimEnd('.')
        try {
            val all = net.getAllByName(name).filter {
                when {
                    network.endsWith("4") -> it is Inet4Address
                    network.endsWith("6") -> it is Inet6Address
                    else -> true
                }
            }
            if (all.isEmpty()) ctx.errorCode(RCODE_NXDOMAIN)
            else ctx.success(all.mapNotNull { it.hostAddress }.joinToString("\n"))
        } catch (e: UnknownHostException) {
            ctx.errorCode(RCODE_NXDOMAIN)
        }
    }

    private companion object {
        const val RCODE_SERVFAIL = 2
        const val RCODE_NXDOMAIN = 3
    }
}
