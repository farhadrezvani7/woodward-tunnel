import Foundation
import NetworkExtension

extension TunnelStatus {
    init(_ status: NEVPNStatus) {
        switch status {
        case .invalid: self = .invalid
        case .disconnected: self = .disconnected
        case .connecting: self = .connecting
        case .connected: self = .connected
        case .reasserting: self = .reasserting
        case .disconnecting: self = .disconnecting
        @unknown default: self = .invalid
        }
    }
}

/// Owns the single NETunnelProviderManager (the "VPN configuration" the user sees in Settings).
/// The sing-box config itself is NOT stored in it; see TunnelHandoff.
@MainActor
final class TunnelController {
    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?

    /// Called on the main actor for every system status change.
    var onStatusChange: ((TunnelStatus) -> Void)?

    var currentStatus: TunnelStatus {
        manager.map { TunnelStatus($0.connection.status) } ?? .disconnected
    }

    var connectedDate: Date? { manager?.connection.connectedDate }

    /// Loads the existing configuration, if any. Does not create one (no permission prompt).
    func load() async throws {
        let all = try await NETunnelProviderManager.loadAllFromPreferences()
        let ours = all.first { m in
            (m.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == AppConstants.tunnelBundleID
        }
        manager = ours
        observeStatus()
    }

    /// Creates / refreshes the configuration. The first save shows the system's
    /// "Add VPN Configurations" prompt; if the user declines this throws (NEVPNErrorDomain).
    func prepare() async throws {
        let m = manager ?? NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = AppConstants.tunnelBundleID
        // Shown in the system VPN settings; must be non-empty, is not a real address.
        proto.serverAddress = "Woodward Tunnel"
        proto.providerConfiguration = ["version": 1]
        m.protocolConfiguration = proto
        m.localizedDescription = "Woodward Tunnel"
        m.isEnabled = true
        try await m.saveToPreferences()
        // Required by Apple's docs after the first save, otherwise start can fail.
        try await m.loadFromPreferences()
        manager = m
        observeStatus()
    }

    func start() throws {
        guard let manager else { throw NSError(domain: FailureMapping.vpnErrorDomain, code: 1) }
        try manager.connection.startVPNTunnel()
    }

    func stop() {
        manager?.connection.stopVPNTunnel()
    }

    /// Removes the VPN configuration from system settings.
    func removeConfiguration() async throws {
        guard let manager else { return }
        try await manager.removeFromPreferences()
        self.manager = nil
        if let observer { NotificationCenter.default.removeObserver(observer) }
        observer = nil
    }

    /// Why the tunnel went down: the extension's own note first, then the system's last error.
    func resolveFailure(since: Date) async -> FailureKind? {
        if let handoff = TunnelHandoff.inAppGroup(AppConstants.appGroupID),
           let kind = handoff.lastFailure(since: since) {
            return kind
        }
        guard let connection = manager?.connection else { return nil }
        let error: Error? = await withCheckedContinuation { continuation in
            // UNVERIFIED: fetchLastDisconnectError(completionHandler:) is iOS 16+.
            connection.fetchLastDisconnectError { continuation.resume(returning: $0) }
        }
        return error.map { FailureMapping.kind(for: $0) }
    }

    private func observeStatus() {
        if let observer { NotificationCenter.default.removeObserver(observer) }
        guard let connection = manager?.connection else { return }
        observer = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: connection, queue: .main
        ) { [weak self] _ in
            // The closure runs on the main queue; hop explicitly for the actor checker.
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.onStatusChange?(self.currentStatus)
            }
        }
    }
}
