package app.woodwardtunnel.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import io.nekohasekai.libbox.InterfaceUpdateListener
import java.net.NetworkInterface

/**
 * Tracks the device's real (non-VPN) default network and reports its interface to sing-box, which
 * binds its outbound sockets to it. NetworkRequest.Builder() starts with NOT_VPN, so the tunnel
 * itself is never reported as the default network.
 */
class NetworkMonitor(context: Context) {
    private val cm = context.getSystemService(ConnectivityManager::class.java)
    private val thread = HandlerThread("wt-network").apply { start() }
    private val handler = Handler(thread.looper)

    @Volatile
    private var current: Network? = null

    @Volatile
    private var listener: InterfaceUpdateListener? = null
    private var registered = false

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = update(network)
        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
            if (current == network) report(network)
        }

        override fun onLost(network: Network) {
            if (current == network) update(null)
        }
    }

    @Synchronized
    fun start() {
        if (registered) return
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
            .build()
        when {
            Build.VERSION.SDK_INT >= 31 -> cm.registerBestMatchingNetworkCallback(request, callback, handler)
            Build.VERSION.SDK_INT >= 28 -> cm.requestNetwork(request, callback, handler)
            Build.VERSION.SDK_INT >= 26 -> cm.registerDefaultNetworkCallback(callback, handler)
            else -> cm.registerDefaultNetworkCallback(callback)
        }
        registered = true
        current = cm.activeNetwork
    }

    @Synchronized
    fun stop() {
        if (registered) {
            runCatching { cm.unregisterNetworkCallback(callback) }
            registered = false
        }
        listener = null
        current = null
        thread.quitSafely()
    }

    fun setListener(l: InterfaceUpdateListener?) {
        listener = l
        if (l != null) handler.post { report(current) }
    }

    private fun update(network: Network?) {
        current = network
        report(network)
    }

    /** Runs on the handler thread: link properties can lag behind the callback, hence the retries. */
    private fun report(network: Network?) {
        val l = listener ?: return
        if (network == null) {
            l.updateDefaultInterface("", -1, false, false)
            return
        }
        repeat(10) {
            val name = cm.getLinkProperties(network)?.interfaceName
            val index = name?.let { runCatching { NetworkInterface.getByName(it)?.index }.getOrNull() }
            if (name != null && index != null) {
                l.updateDefaultInterface(name, index, false, false)
                return
            }
            Thread.sleep(100)
        }
    }
}
