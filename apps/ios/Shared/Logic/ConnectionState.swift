import Foundation

/// Mirror of `NEVPNStatus` so that the state logic does not depend on NetworkExtension.
public enum TunnelStatus: Equatable {
    case invalid
    case disconnected
    case connecting
    case connected
    case reasserting
    case disconnecting
}

/// Why a connection did not work, in terms a non-expert can act on.
public enum FailureKind: Equatable {
    case noProfile
    case configInvalid
    case permissionDenied
    case vpnDisabled
    case noNetwork
    case serverUnreachable
    case unsupportedEngine(UnsupportedEngine)
    case tunnelStartFailed
    case unknown

    /// Stable machine-readable code (used in the app-group status file).
    public var code: String {
        switch self {
        case .noProfile: return "no_profile"
        case .configInvalid: return "config_invalid"
        case .permissionDenied: return "permission_denied"
        case .vpnDisabled: return "vpn_disabled"
        case .noNetwork: return "no_network"
        case .serverUnreachable: return "server_unreachable"
        case .unsupportedEngine(let e): return "unsupported_" + e.rawValue
        case .tunnelStartFailed: return "tunnel_start_failed"
        case .unknown: return "unknown"
        }
    }

    public init?(code: String) {
        switch code {
        case "no_profile": self = .noProfile
        case "config_invalid": self = .configInvalid
        case "permission_denied": self = .permissionDenied
        case "vpn_disabled": self = .vpnDisabled
        case "no_network": self = .noNetwork
        case "server_unreachable": self = .serverUnreachable
        case "unsupported_amneziawg": self = .unsupportedEngine(.amneziaWg)
        case "unsupported_openvpn": self = .unsupportedEngine(.openVpn)
        case "tunnel_start_failed": self = .tunnelStartFailed
        case "unknown": self = .unknown
        default: return nil
        }
    }

    /// Localization key of the one-line title.
    public var titleKey: String { "failure." + code + ".title" }
    /// Localization key of the plain explanation.
    public var messageKey: String { "failure." + code + ".message" }

    /// Retrying cannot help for these; the user has to change something first.
    public var retryMakesSense: Bool {
        switch self {
        case .noProfile, .unsupportedEngine, .configInvalid: return false
        default: return true
        }
    }
}

/// Engines the core can describe but this platform build cannot run yet.
public enum UnsupportedEngine: String, Equatable {
    case amneziaWg = "amneziawg"
    case openVpn = "openvpn"
}

public enum ConnectionState: Equatable {
    case disconnected
    case connecting
    case connected(since: Date)
    case disconnecting
    case failed(FailureKind)

    public var isActive: Bool {
        switch self {
        case .connecting, .connected: return true
        default: return false
        }
    }

    public var isBusy: Bool {
        switch self {
        case .connecting, .disconnecting: return true
        default: return false
        }
    }

    /// Localization key for the short status line under the button.
    public var statusKey: String {
        switch self {
        case .disconnected: return "state.disconnected"
        case .connecting: return "state.connecting"
        case .connected: return "state.connected"
        case .disconnecting: return "state.disconnecting"
        case .failed: return "state.failed"
        }
    }
}

/// Pure reducer: system tunnel status in, user-facing state out.
public struct ConnectionStateMachine: Equatable {
    public private(set) var state: ConnectionState

    public init(state: ConnectionState = .disconnected) {
        self.state = state
    }

    public mutating func userRequestedConnect() {
        if state.isActive || state == .disconnecting { return }
        state = .connecting
    }

    public mutating func userRequestedDisconnect() {
        switch state {
        case .connecting, .connected: state = .disconnecting
        case .failed: state = .disconnected
        default: break
        }
    }

    /// Something failed before the system tunnel was involved (no profile, unsupported protocol...).
    public mutating func fail(_ kind: FailureKind) {
        state = .failed(kind)
    }

    /// `failure` is only consulted when the tunnel went down; pass the reason if one is known.
    public mutating func tunnelStatusChanged(_ status: TunnelStatus, now: Date, failure: FailureKind?) {
        switch status {
        case .connecting, .reasserting:
            if case .failed = state, status == .reasserting { return }
            state = .connecting
        case .connected:
            if case .connected = state { return }
            state = .connected(since: now)
        case .disconnecting:
            state = .disconnecting
        case .disconnected, .invalid:
            if let failure = failure {
                state = .failed(failure)
            } else if case .failed = state {
                // keep the explanation visible until the user acts
            } else {
                state = .disconnected
            }
        }
    }
}
