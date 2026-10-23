package app.woodwardtunnel.bindings

import android.content.Context
import app.woodwardtunnel.secrets.KeystoreSecretStore
import uniffi.wtcore.FfiException
import uniffi.wtcore.FfiProblem
import java.util.Locale
import uniffi.wtcore.WtApp
import java.io.File

/** Process-wide handle to the Rust core (UniFFI `WtApp`). */
object Core {
    @Volatile
    private var app: WtApp? = null

    /** Opens the core store. Safe to call repeatedly; throws [CoreUnavailable] when storage cannot be opened. */
    @Synchronized
    fun init(context: Context) {
        if (app != null) return
        val base = context.applicationContext.filesDir
        try {
            app = WtApp(File(base, "core").apply { mkdirs() }.path, KeystoreSecretStore(File(base, "secrets")))
        } catch (e: Throwable) {
            throw CoreUnavailable()
        }
    }

    fun get(): WtApp = app ?: throw CoreUnavailable()

    class CoreUnavailable : Exception("core not available")
}

private fun english(): Boolean = Locale.getDefault().language == "en"

/** The user-facing (already plain language) message carried by a core error, in the app language. */
fun Throwable.coreMessage(): String? =
    (this as? FfiException.Failed)?.let { if (english()) it.reasonEn else it.reason }

/** Import problem text in the app language. */
fun FfiProblem.text(): String = if (english()) messageEn else message
