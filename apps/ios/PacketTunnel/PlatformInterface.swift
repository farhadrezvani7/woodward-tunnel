import Foundation
import Libbox
import Network
import NetworkExtension
import os

/// Implements what libbox needs from the platform when it runs inside a packet tunnel
/// extension: create the TUN (by applying NEPacketTunnelNetworkSettings), report the default
/// network interface, and answer "not supported" for desktop-only features (SSH server,
/// bridges, shell, neighbor table).
///
/// The method list follows the gomobile header generated from sing-box v1.14.3
/// (experimental/libbox, `gobind -lang=objc`) and the behaviour follows SagerNet's open-source
/// sing-box-for-apple. UNVERIFIED: not compiled; if the pinned libbox changes, the protocol
/// conformance below breaks at compile time and must be re-synced.
final class PlatformInterface: NSObject, LibboxPlatformInterfaceProtocol, LibboxCommandServerHandlerProtocol {
    private static let log = Logger(subsystem: "app.woodward.tunnel.PacketTunnel", category: "platform")

    private weak var tunnel: PacketTunnelProvider?
    private var networkSettings: NEPacketTunnelNetworkSettings?
    private var monitor: NWPathMonitor?
    private var lastNetworkPath: String?

    init(_ tunnel: PacketTunnelProvider) {
        self.tunnel = tunnel
    }

    func reset() {
        networkSettings = nil
        monitor?.cancel()
        monitor = nil
        lastNetworkPath = nil
    }

    private func unsupported(_ what: String) -> NSError {
        NSError(domain: FailureMapping.extensionErrorDomain, code: 0,
                userInfo: [NSLocalizedDescriptionKey: "\(what) is not supported on iOS"])
    }

    // MARK: TUN

    func openTun(_ options: LibboxTunOptionsProtocol?, ret0_: UnsafeMutablePointer<Int32>?) throws {
        guard let options, let ret0_, let tunnel else {
            throw unsupported("openTun without options")
        }
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        if options.getAutoRoute() {
            settings.mtu = NSNumber(value: options.getMTU())

            var dnsSettings: NEDNSSettings?
            if let mode = options.getDNSMode(), mode.value != LibboxDNSModeDisabled {
                let servers = try options.getDNSServerAddress().drain()
                if !servers.isEmpty { dnsSettings = NEDNSSettings(servers: servers) }
            }

            // IPv4
            let v4 = options.getInet4Address()?.drain() ?? []
            let ipv4 = NEIPv4Settings(addresses: v4.map { $0.address() }, subnetMasks: v4.map { $0.mask() })
            let v4Routes = options.getInet4RouteAddress()?.drain() ?? []
            ipv4.includedRoutes = v4Routes.isEmpty
                ? [NEIPv4Route.default()]
                : v4Routes.map { NEIPv4Route(destinationAddress: $0.address(), subnetMask: $0.mask()) }
            ipv4.excludedRoutes = (options.getInet4RouteExcludeAddress()?.drain() ?? [])
                .map { NEIPv4Route(destinationAddress: $0.address(), subnetMask: $0.mask()) }
            settings.ipv4Settings = ipv4

            // IPv6
            let v6 = options.getInet6Address()?.drain() ?? []
            let ipv6 = NEIPv6Settings(addresses: v6.map { $0.address() },
                                      networkPrefixLengths: v6.map { NSNumber(value: $0.prefix()) })
            let v6Routes = options.getInet6RouteAddress()?.drain() ?? []
            ipv6.includedRoutes = v6Routes.isEmpty
                ? [NEIPv6Route.default()]
                : v6Routes.map { NEIPv6Route(destinationAddress: $0.address(), networkPrefixLength: NSNumber(value: $0.prefix())) }
            ipv6.excludedRoutes = (options.getInet6RouteExcludeAddress()?.drain() ?? [])
                .map { NEIPv6Route(destinationAddress: $0.address(), networkPrefixLength: NSNumber(value: $0.prefix())) }
            settings.ipv6Settings = ipv6

            settings.dnsSettings = dnsSettings
        }
        // platform.http_proxy (system proxy through NEProxySettings) is not used by the configs
        // the core generates, so it is not implemented here.

        networkSettings = settings
        let done = DispatchSemaphore(value: 0)
        var applyError: Error?
        tunnel.setTunnelNetworkSettings(settings) { error in
            applyError = error
            done.signal()
        }
        done.wait()
        if let applyError { throw applyError }

        let fd = LibboxGetTunnelFileDescriptor()
        guard fd != -1 else { throw unsupported("finding the tunnel file descriptor") }
        ret0_.pointee = fd
    }

    func usePlatformAutoDetectInterfaceControl() -> Bool { false }

    func autoDetectInterfaceControl(_ fd: Int32) throws {}

    func underNetworkExtension() -> Bool { true }

    func includeAllNetworks() -> Bool { false }

    func clearDNSCache() {
        guard let tunnel, let settings = networkSettings else { return }
        let done = DispatchSemaphore(value: 0)
        tunnel.reasserting = true
        tunnel.setTunnelNetworkSettings(nil) { _ in
            tunnel.setTunnelNetworkSettings(settings) { _ in
                tunnel.reasserting = false
                done.signal()
            }
        }
        done.wait()
    }

    // MARK: network monitoring

    func startDefaultInterfaceMonitor(_ listener: LibboxInterfaceUpdateListenerProtocol?) throws {
        guard let listener else { return }
        let monitor = NWPathMonitor()
        self.monitor = monitor
        let first = DispatchSemaphore(value: 0)
        monitor.pathUpdateHandler = { [weak self] path in
            self?.deliver(path, to: listener)
            first.signal()
            monitor.pathUpdateHandler = { [weak self] path in self?.deliver(path, to: listener) }
        }
        monitor.start(queue: DispatchQueue.global())
        first.wait() // libbox expects the initial state before this call returns
    }

    private func deliver(_ path: NWPath, to listener: LibboxInterfaceUpdateListenerProtocol) {
        let description = describe(path)
        listener.updateNetworkPath(description)
        if description == lastNetworkPath { return }
        lastNetworkPath = description
        guard path.status != .unsatisfied, let first = path.availableInterfaces.first else {
            listener.updateDefaultInterface("", interfaceIndex: -1, isExpensive: false, isConstrained: false)
            return
        }
        listener.updateDefaultInterface(first.name, interfaceIndex: Int32(first.index),
                                        isExpensive: path.isExpensive, isConstrained: path.isConstrained)
    }

    private func describe(_ path: NWPath) -> String {
        var parts = ["\(path.status)"]
        parts.append(contentsOf: path.availableInterfaces.map { "\($0.name)#\($0.index)/\($0.type)" })
        if path.supportsIPv4 { parts.append("ipv4") }
        if path.supportsIPv6 { parts.append("ipv6") }
        if path.isExpensive { parts.append("expensive") }
        if path.isConstrained { parts.append("constrained") }
        return parts.joined(separator: " ")
    }

    func closeDefaultInterfaceMonitor(_ listener: LibboxInterfaceUpdateListenerProtocol?) throws {
        monitor?.cancel()
        monitor = nil
        lastNetworkPath = nil
    }

    func getInterfaces() throws -> any LibboxNetworkInterfaceIteratorProtocol {
        guard let monitor else { throw unsupported("interface list before the monitor started") }
        let path = monitor.currentPath
        if path.status == .unsatisfied { return NetworkInterfaceList([]) }
        let list: [LibboxNetworkInterface] = path.availableInterfaces.map { nw in
            let item = LibboxNetworkInterface()
            item.name = nw.name
            item.index = Int32(nw.index)
            switch nw.type {
            case .wifi: item.type = LibboxInterfaceTypeWIFI
            case .cellular: item.type = LibboxInterfaceTypeCellular
            case .wiredEthernet: item.type = LibboxInterfaceTypeEthernet
            default: item.type = LibboxInterfaceTypeOther
            }
            return item
        }
        return NetworkInterfaceList(list)
    }

    func startNeighborMonitor(_ listener: LibboxNeighborUpdateListenerProtocol?) throws {}
    func closeNeighborMonitor(_ listener: LibboxNeighborUpdateListenerProtocol?) throws {}
    func registerMyInterface(_ name: String?) {}

    // MARK: features that do not exist on iOS

    func localDNSTransport() -> (any LibboxLocalDNSTransportProtocol)? { nil }
    func useProcFS() -> Bool { false }

    func findConnectionOwner(_ ipProtocol: Int32, sourceAddress: String?, sourcePort: Int32,
                             destinationAddress: String?, destinationPort: Int32) throws -> LibboxConnectionOwner {
        throw unsupported("process lookup")
    }

    func readWIFIState() -> LibboxWIFIState? { nil }

    func sendNotification(_ notification: LibboxNotification?) throws {}
    func cancelNotification(_ identifier: String?, typeID: Int32) throws {}

    func usePlatformShell() -> Bool { false }
    func checkPlatformShell() throws { throw unsupported("shell") }

    func openShellSession(_ user: LibboxPlatformUser?, command: String?, environ: (any LibboxStringIteratorProtocol)?,
                          term: String?, rows: Int32, cols: Int32) throws -> any LibboxShellSessionProtocol {
        throw unsupported("shell")
    }

    func lookupUser(_ username: String?) throws -> LibboxPlatformUser { throw unsupported("user lookup") }

    func lookupSFTPServer(_ error: NSErrorPointer) -> String {
        error?.pointee = unsupported("SFTP")
        return ""
    }

    func readSystemSSHHostKey(_ error: NSErrorPointer) -> String {
        error?.pointee = unsupported("SSH host key")
        return ""
    }

    func tailscaleHostname() -> String { "" }

    func usePlatformBridge() -> Bool { false }

    func createBridge(_ options: LibboxBridgeOptions?) throws -> any LibboxBridgeSessionProtocol {
        throw unsupported("bridge")
    }

    // MARK: command server callbacks

    func connectSSHAgent(_ ret0_: UnsafeMutablePointer<Int32>?) throws { throw unsupported("SSH agent") }

    func getSystemProxyStatus() throws -> LibboxSystemProxyStatus {
        LibboxSystemProxyStatus() // available = false
    }

    func setSystemProxyEnabled(_ enabled: Bool) throws {}

    func serviceStop() throws {
        tunnel?.cancelTunnelWithError(nil)
    }

    func serviceReload() throws {
        // Reload is not used; a changed config means a new connection started by the app.
    }

    func triggerNativeCrash() throws {}

    func writeDebugMessage(_ message: String?) {
        // Deliberately dropped: debug text can contain server names.
    }
}
