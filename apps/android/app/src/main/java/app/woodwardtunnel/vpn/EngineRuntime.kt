package app.woodwardtunnel.vpn

import android.content.Context
import android.os.Build
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.SetupOptions
import java.io.File

/** One-time setup of the embedded sing-box (libbox) and cleanup of files it writes. */
object EngineRuntime {
    private var done = false

    @Synchronized
    fun ensureSetup(context: Context) {
        if (done) return
        val base = File(context.filesDir, "engine").apply { mkdirs() }
        val tmp = File(context.cacheDir, "engine").apply { mkdirs() }
        Libbox.setup(
            SetupOptions().also {
                it.basePath = base.path
                it.workingPath = base.path
                it.tempPath = tmp.path
                // Workaround for Go issue 68760 on Android 7.0/7.1 and 9+.
                it.fixAndroidStack = Build.VERSION.SDK_INT >= 28 || Build.VERSION.SDK_INT in 24..25
                it.logMaxLines = 200
                it.debug = false
                it.crashReportSource = "app"
            },
        )
        done = true
        wipeSnapshots(context)
    }

    fun version(): String = runCatching { Libbox.version() }.getOrDefault("?")

    /**
     * libbox writes the running configuration (which contains server credentials) to
     * `configuration.json` in its base directory. The files stay in app-private storage, but we
     * remove them as soon as the engine has started and again on stop and on app start.
     */
    fun wipeSnapshots(context: Context) {
        val base = File(context.filesDir, "engine")
        base.resolve("crash_reports").deleteRecursively()
        blockSnapshot(base)
    }

    /**
     * libbox writes the running configuration with `os.WriteFile(<base>/configuration.json)` and ignores errors.
     * A directory with that name makes the write fail (EISDIR), so the credentials never touch the disk at all.
     */
    private fun blockSnapshot(base: File) {
        val f = File(base, "configuration.json")
        if (f.isDirectory) return
        f.delete()
        base.mkdirs()
        f.mkdir()
    }
}
