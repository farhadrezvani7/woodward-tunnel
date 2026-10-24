package app.woodwardtunnel.ui

import android.app.Application
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import androidx.annotation.StringRes
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import app.woodwardtunnel.R
import app.woodwardtunnel.bindings.Core
import app.woodwardtunnel.bindings.coreMessage
import app.woodwardtunnel.bindings.text
import app.woodwardtunnel.vpn.ConnState
import app.woodwardtunnel.vpn.TunnelController
import app.woodwardtunnel.vpn.TunnelState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import uniffi.wtcore.FfiImportReport
import uniffi.wtcore.FfiLaunchPlan
import uniffi.wtcore.FfiProfile

class UiText(@StringRes val res: Int, val args: List<Any> = emptyList())

class ImportSummary(val added: Int, val duplicates: Int, val problems: List<String>)

/** Something received from another app that the user has not yet agreed to import. */
sealed interface ExternalImport {
    class Text(val text: String) : ExternalImport
}

class MainViewModel(app: Application) : AndroidViewModel(app) {
    private val ctx: Context get() = getApplication()

    private val _profiles = MutableStateFlow<List<FfiProfile>>(emptyList())
    val profiles: StateFlow<List<FfiProfile>> = _profiles

    private val _selectedId = MutableStateFlow(Prefs.selectedId(app))
    val selectedId: StateFlow<String?> = _selectedId

    private val _coreOk = MutableStateFlow(true)
    val coreOk: StateFlow<Boolean> = _coreOk

    private val _messages = MutableSharedFlow<UiText>(extraBufferCapacity = 8)
    val messages: SharedFlow<UiText> = _messages

    private val _vpnConsent = MutableSharedFlow<Intent>(extraBufferCapacity = 1)
    val vpnConsent: SharedFlow<Intent> = _vpnConsent

    private val _summary = MutableStateFlow<ImportSummary?>(null)
    val summary: StateFlow<ImportSummary?> = _summary

    private val _pendingExternal = MutableStateFlow<ExternalImport?>(null)
    val pendingExternal: StateFlow<ExternalImport?> = _pendingExternal

    /** Subscription URLs waiting for the user's OK, shown one at a time. */
    private val _pendingSubscriptions = MutableStateFlow<List<String>>(emptyList())
    val pendingSubscription: StateFlow<String?> =
        _pendingSubscriptions.map { it.firstOrNull() }.stateIn(viewModelScope, SharingStarted.Eagerly, null)

    init {
        refresh()
    }

    fun postMessage(@StringRes res: Int) = say(res)

    private fun say(@StringRes res: Int, vararg args: Any) {
        _messages.tryEmit(UiText(res, args.toList()))
    }

    fun refresh() {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                Core.init(ctx)
                _coreOk.value = true
                val list = Core.get().list()
                _profiles.value = list
                val sel = _selectedId.value
                if (sel == null || list.none { it.id == sel }) select(list.firstOrNull()?.id)
            } catch (e: Exception) {
                _coreOk.value = false
            }
        }
    }

    fun select(id: String?) {
        _selectedId.value = id
        Prefs.setSelectedId(ctx, id)
    }

    /** Set when the user picked another profile while connected: disconnect, then connect to the new one. */
    @Volatile
    private var reconnectAfterStop = false

    private val connectionActive: Boolean
        get() = TunnelState.state.value.let { it is ConnState.Connected || it is ConnState.Connecting || it is ConnState.Reconnecting }

    /** A tap on a profile row. While a tunnel is up this switches to the tapped profile instead of silently doing nothing. */
    fun choose(id: String) {
        if (id == _selectedId.value) return
        val active = connectionActive
        select(id)
        if (active) {
            reconnectAfterStop = true
            TunnelController.stop(ctx)
            say(R.string.switching_profile)
        }
    }

    /** Called by the activity when the tunnel reaches Disconnected. */
    fun onDisconnected() {
        if (reconnectAfterStop) {
            reconnectAfterStop = false
            connect()
        }
    }

    // ---- import ----

    fun importText(text: String, group: String = "") = launchImport { it.importText(text, group) }

    fun importBytes(bytes: ByteArray, group: String = "") = launchImport { it.importBytes(bytes, group) }

    fun importFromClipboard(text: String?) {
        if (text.isNullOrBlank()) say(R.string.clipboard_empty) else importText(text)
    }

    fun requestSubscription(url: String) {
        if (hostOf(url).isBlank()) {
            say(R.string.settings_subscription_invalid)
            return
        }
        if (_pendingSubscriptions.value.size >= MAX_PENDING_SUBSCRIPTIONS) return
        _pendingSubscriptions.value = _pendingSubscriptions.value + url
    }

    fun confirmSubscription() {
        val url = _pendingSubscriptions.value.firstOrNull() ?: return
        _pendingSubscriptions.value = _pendingSubscriptions.value.drop(1)
        launchImport { it.importSubscription(url, "") }
    }

    fun declineSubscription() {
        _pendingSubscriptions.value = _pendingSubscriptions.value.drop(1)
    }

    fun offerExternal(e: ExternalImport) {
        _pendingExternal.value = e
    }

    fun confirmExternal() {
        val e = _pendingExternal.value ?: return
        _pendingExternal.value = null
        when (e) {
            is ExternalImport.Text -> importText(e.text)
        }
    }

    fun declineExternal() {
        _pendingExternal.value = null
    }

    fun dismissSummary() {
        _summary.value = null
    }

    private fun launchImport(block: (uniffi.wtcore.WtApp) -> FfiImportReport) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                Core.init(ctx)
                val r = block(Core.get())
                _profiles.value = Core.get().list()
                if (_selectedId.value == null) select(r.added.firstOrNull()?.id ?: _profiles.value.firstOrNull()?.id)
                else if (r.added.isNotEmpty() && _profiles.value.none { it.id == _selectedId.value }) select(r.added.first().id)
                // A hostile text can carry hundreds of URLs; only a few are ever offered, one at a time.
                r.subscriptionUrls.filter { hostOf(it).isNotBlank() }.forEach { requestSubscription(it) }
                val added = r.added.size
                val dup = r.duplicates.toInt()
                when {
                    r.problems.isNotEmpty() ->
                        _summary.value = ImportSummary(added, dup, r.problems.map { p -> p.text().let { t -> if (p.label.isBlank()) t else "${p.label}: $t" } })
                    added > 0 -> say(R.string.import_added, added)
                    dup > 0 -> say(R.string.import_duplicates, dup)
                    r.subscriptionUrls.isEmpty() -> say(R.string.import_nothing)
                }
            } catch (e: Exception) {
                say(R.string.import_failed)
            }
        }
    }

    // ---- profile management ----

    fun rename(id: String, name: String) = mutate { it.rename(id, name.trim()) }
    fun setGroup(id: String, group: String) = mutate { it.setGroup(id, group.trim()) }
    fun delete(id: String) {
        // Deleting the profile that is running would leave a tunnel nobody can identify: disconnect first.
        if (id == _selectedId.value && connectionActive) TunnelController.stop(ctx)
        mutate {
            it.delete(id)
            if (_selectedId.value == id) select(null)
        }
    }

    private fun mutate(block: (uniffi.wtcore.WtApp) -> Unit) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                block(Core.get())
                _profiles.value = Core.get().list()
                if (_selectedId.value == null) select(_profiles.value.firstOrNull()?.id)
            } catch (e: Exception) {
                say(R.string.import_failed)
            }
        }
    }

    // ---- connection ----

    fun onConnectButton() {
        when (TunnelState.state.value) {
            is ConnState.Connected, is ConnState.Connecting, is ConnState.Reconnecting -> {
                reconnectAfterStop = false
                TunnelController.stop(ctx)
            }
            else -> connect()
        }
    }

    fun connect() {
        val id = _selectedId.value
        if (id == null) {
            say(R.string.select_profile_first)
            return
        }
        TunnelState.set(ConnState.Connecting)
        viewModelScope.launch(Dispatchers.IO) {
            val plan = try {
                Core.init(ctx)
                Core.get().launchPlan(id, Prefs.dnsServers(ctx))
            } catch (e: Exception) {
                TunnelState.set(ConnState.Error(R.string.err_core, e.coreMessage()))
                return@launch
            }
            if (plan is FfiLaunchPlan.OpenVpn) {
                TunnelState.set(ConnState.Error(R.string.err_unsupported_protocol))
                return@launch
            }
            val consent = VpnService.prepare(ctx)
            if (consent != null) _vpnConsent.emit(consent) else TunnelController.start(ctx, id)
        }
    }

    fun onVpnConsentResult(granted: Boolean) {
        val id = _selectedId.value
        // The user may have pressed the connect button again (cancel) while the system dialog was open.
        if (TunnelState.state.value !is ConnState.Connecting) return
        if (granted && id != null) TunnelController.start(ctx, id)
        else TunnelState.set(ConnState.Error(R.string.err_vpn_permission))
    }

    companion object {
        private const val MAX_PENDING_SUBSCRIPTIONS = 5
        fun hostOf(url: String): String = try { Uri.parse(url).host ?: "" } catch (e: Exception) { "" }
    }
}
