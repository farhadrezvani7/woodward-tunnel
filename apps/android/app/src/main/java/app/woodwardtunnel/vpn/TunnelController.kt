package app.woodwardtunnel.vpn

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat

/** Thin entry points the UI uses to start and stop the tunnel service. */
object TunnelController {
    fun start(context: Context, profileId: String) {
        TunnelState.set(ConnState.Connecting)
        val intent = Intent(context, TunnelService::class.java)
            .setAction(TunnelService.ACTION_START)
            .putExtra(TunnelService.EXTRA_PROFILE_ID, profileId)
        ContextCompat.startForegroundService(context, intent)
    }

    fun stop(context: Context) {
        val svc = TunnelService.instance
        if (svc == null) {
            TunnelState.set(ConnState.Disconnected)
            // The service may be about to start (the start intent is already queued): tell it to stand down.
            runCatching { context.startService(Intent(context, TunnelService::class.java).setAction(TunnelService.ACTION_STOP)) }
            return
        }
        svc.requestStop()
    }
}
