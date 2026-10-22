import Foundation
import Libbox
import NetworkExtension
import os

/// The packet tunnel extension: reads the sing-box config the app left in the app group,
/// starts libbox (sing-box) with the platform interface and keeps it alive until stopped.
///
/// Memory: extensions are killed by the system when they exceed a small memory limit
/// (commonly cited as about 50 MB for packet tunnels on iOS; UNVERIFIED, Apple does not
/// document an exact number). libbox applies its own Go memory limit and a lower GC percent
/// when `oomKillerEnabled` is set and it runs on iOS (see service/oomkiller in sing-box:
/// 50 MiB limit, GC percent 50, soft limit at 80 percent).
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private static let log = Logger(subsystem: "app.woodward.tunnel.PacketTunnel", category: "provider")

    private var commandServer: LibboxCommandServer?
    private lazy var platform = PlatformInterface(self)
    private var handoff: TunnelHandoff?

    override func startTunnel(options: [String: NSObject]?) async throws {
        let handoff = TunnelHandoff.inAppGroup(AppConstants.appGroupID)
        self.handoff = handoff
        do {
            try startCore(handoff: handoff)
        } catch {
            let kind = FailureMapping.kind(for: error)
            handoff?.recordFailure(kind == .unknown ? .tunnelStartFailed : kind)
            Self.log.error("start failed: \(String(describing: kind.code), privacy: .public)")
            stopCore()
            throw error
        }
    }

    private func startCore(handoff: TunnelHandoff?) throws {
        guard let handoff, let payload = try? handoff.readConfig() else {
            throw failure(.missingConfig, "missing config")
        }
        // The config contains credentials: keep it only in memory from here on.
        handoff.clearConfig()

        guard let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: AppConstants.appGroupID) else {
            throw failure(.missingConfig, "missing app group")
        }
        let base = container.appendingPathComponent("singbox", isDirectory: true)
        let working = base.appendingPathComponent("Working", isDirectory: true)
        let temp = base.appendingPathComponent("Temp", isDirectory: true)

        let setup = LibboxSetupOptions()
        setup.basePath = base.path
        setup.workingPath = working.path
        setup.tempPath = temp.path
        setup.logMaxLines = 500
        setup.debug = false
        setup.crashReportSource = "PacketTunnel"
        let info = Bundle.main.infoDictionary
        setup.appVersion = info?["CFBundleVersion"] as? String ?? ""
        setup.appMarketingVersion = info?["CFBundleShortVersionString"] as? String ?? ""
        setup.oomKillerEnabled = true   // turns on the Go memory limit and GC tuning on iOS
        setup.oomKillerDisabled = false
        setup.powerReportEnabled = false

        var setupError: NSError?
        LibboxSetup(setup, &setupError)
        if let setupError { throw failure(.coreSetupFailed, "setup: \(setupError.code)") }

        var serverError: NSError?
        guard let server = LibboxNewCommandServer(platform, platform, &serverError) else {
            throw failure(.coreSetupFailed, "command server: \(serverError?.code ?? 0)")
        }
        commandServer = server
        do {
            try server.start()
        } catch {
            throw failure(.coreSetupFailed, "command server start")
        }
        do {
            try server.startOrReloadService(payload.configJSON, options: LibboxOverrideOptions())
        } catch {
            // The text may name the server; keep it out of the logs and out of the app.
            throw failure(.coreStartFailed, "service start")
        }
    }

    private func failure(_ code: FailureMapping.ExtensionCode, _ note: String) -> NSError {
        Self.log.error("\(note, privacy: .public)")
        return NSError(domain: FailureMapping.extensionErrorDomain, code: code.rawValue)
    }

    private func stopCore() {
        try? commandServer?.closeService()
        platform.reset()
        commandServer?.close()
        commandServer = nil
    }

    override func stopTunnel(with reason: NEProviderStopReason) async {
        stopCore()
        handoff?.clearConfig()
    }

    override func sleep() async {
        commandServer?.pause()
    }

    override func wake() {
        commandServer?.wake()
    }
}
