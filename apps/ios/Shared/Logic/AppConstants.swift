import Foundation

/// Identifiers shared by the app and the extension. The real values live in project.yml build
/// settings and reach the code through Info.plist keys, so they exist in exactly one place.
public enum AppConstants {
    private static func plist(_ key: String, fallback: String) -> String {
        if let v = Bundle.main.object(forInfoDictionaryKey: key) as? String, !v.isEmpty, !v.hasPrefix("$(") {
            return v
        }
        return fallback
    }

    /// App group shared by the app and the packet tunnel extension.
    public static var appGroupID: String { plist("WTAppGroupID", fallback: "group.app.woodward.tunnel") }

    /// Keychain access group (team prefix + shared name). Empty means: use the default group of the app.
    public static var keychainAccessGroup: String { plist("WTKeychainGroup", fallback: "") }

    /// Bundle identifier of the packet tunnel extension.
    public static var tunnelBundleID: String { plist("WTTunnelBundleID", fallback: "app.woodward.tunnel.PacketTunnel") }

    public static let keychainService = "app.woodward.tunnel.secrets"

    /// UserDefaults keys.
    public enum DefaultsKey {
        public static let selectedProfileID = "selectedProfileID"
        public static let dnsServers = "dnsServers"
    }

    public static let defaultDNS = ["1.1.1.1", "8.8.8.8"]
}
