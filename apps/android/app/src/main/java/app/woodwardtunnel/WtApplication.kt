package app.woodwardtunnel

import android.app.Application
import app.woodwardtunnel.bindings.Core
import app.woodwardtunnel.vpn.EngineRuntime

class WtApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        // Remove engine files a previous crash may have left behind.
        EngineRuntime.wipeSnapshots(this)
        try {
            Core.init(this)
        } catch (_: Core.CoreUnavailable) {
            // The UI shows a plain-language message and offers to retry on next launch.
        }
    }
}
