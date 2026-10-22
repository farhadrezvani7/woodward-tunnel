package app.woodwardtunnel.vpn

import androidx.annotation.StringRes
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** Connection state shown on the main screen. Process-wide; written by [TunnelService]. */
sealed interface ConnState {
    data object Disconnected : ConnState
    data object Connecting : ConnState

    /** [sinceElapsed] is SystemClock.elapsedRealtime() when the tunnel was verified. */
    data class Connected(val sinceElapsed: Long, val insecureTls: Boolean) : ConnState

    /** [message] is a plain-language string resource; technical text is kept apart (see [TunnelState.lastTechnical]). */
    data class Error(@StringRes val message: Int, val coreMessage: String? = null) : ConnState
}

object TunnelState {
    private val _state = MutableStateFlow<ConnState>(ConnState.Disconnected)
    val state: StateFlow<ConnState> = _state

    /** Last engine error text for the advanced screen. Memory only, never logged or persisted. */
    @Volatile
    var lastTechnical: String? = null
        private set

    fun set(s: ConnState, technical: String? = null) {
        if (s is ConnState.Error) lastTechnical = technical
        _state.value = s
    }
}
