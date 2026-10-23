import Foundation

/// Maps system errors to `FailureKind`. Works on (domain, code) pairs so it can be tested
/// without NetworkExtension. The numeric codes come from NEVPNError / NEVPNConnectionError
/// in Apple's headers as remembered by the author.
/// UNVERIFIED: re-check the numbers against the iOS SDK headers on a Mac.
public enum FailureMapping {
    public static let vpnErrorDomain = "NEVPNErrorDomain"
    public static let connectionErrorDomain = "NEVPNConnectionErrorDomainPlugin"
    public static let extensionErrorDomain = "WoodwardTunnel.PacketTunnel"

    /// Error codes the packet tunnel extension itself throws.
    public enum ExtensionCode: Int {
        case missingConfig = 1
        case coreSetupFailed = 2
        case coreStartFailed = 3
        case tunnelSettingsFailed = 4
        case helperStartFailed = 5
    }

    public static func kind(domain: String, code: Int) -> FailureKind {
        switch domain {
        case vpnErrorDomain:
            // NEVPNError.Code: configurationInvalid 1, configurationDisabled 2, connectionFailed 3,
            // configurationStale 4, configurationReadWriteFailed 5, configurationUnknown 6
            switch code {
            case 1: return .configInvalid
            case 2: return .vpnDisabled
            case 3: return .serverUnreachable
            case 5: return .permissionDenied
            default: return .unknown
            }
        case connectionErrorDomain:
            // overslept 1, noNetworkAvailable 2, unrecoverableNetworkChange 3, configurationFailed 4,
            // serverAddressResolutionFailed 5, serverNotResponding 6, serverDead 7, ... pluginFailed 12,
            // configurationNotFound 13, pluginDisabled 14, ... serverDisconnected 16
            switch code {
            case 2, 3: return .noNetwork
            case 4, 13: return .configInvalid
            case 5, 6, 7, 16: return .serverUnreachable
            case 12, 14: return .tunnelStartFailed
            default: return .unknown
            }
        case extensionErrorDomain:
            switch ExtensionCode(rawValue: code) {
            case .missingConfig?: return .configInvalid
            case .coreSetupFailed?, .coreStartFailed?, .tunnelSettingsFailed?: return .tunnelStartFailed
            case .helperStartFailed?: return .helperStartFailed
            case nil: return .unknown
            }
        default:
            return .unknown
        }
    }

    public static func kind(for error: Error) -> FailureKind {
        let ns = error as NSError
        return kind(domain: ns.domain, code: ns.code)
    }
}
