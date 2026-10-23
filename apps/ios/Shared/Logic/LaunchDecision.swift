import Foundation

/// What the app does with the core's launch plan. The FFI enum is mapped to this in one place
/// (App/Core/CoreService.swift) so that the rest of the code, and the tests, stay FFI-free.
public enum LaunchDecision: Equatable {
    case runSingBox(configJSON: String, insecureTLS: Bool)
    /// Start the AmneziaWG helper (SOCKS on loopback) first, then sing-box using `singboxConfigJSON`.
    case runAmneziaWG(helperJSON: String, singboxConfigJSON: String)
    case unsupported(UnsupportedEngine)
}
