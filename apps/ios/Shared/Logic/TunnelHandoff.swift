import Foundation

/// The app hands the sing-box config to the packet tunnel extension through a file in the app
/// group container. It is never put into providerConfiguration (which the system stores in the
/// VPN preferences), never passed through logs, and is deleted when the tunnel stops.
///
/// The extension reports why it failed through a second small file that contains only a
/// failure code, never config text.
public struct TunnelHandoff {
    public struct Payload: Codable, Equatable {
        public var version: Int
        public var configJSON: String
        public var insecureTLS: Bool
        public var profileName: String
        public var createdAt: Date

        public init(configJSON: String, insecureTLS: Bool, profileName: String, createdAt: Date = Date()) {
            self.version = 1
            self.configJSON = configJSON
            self.insecureTLS = insecureTLS
            self.profileName = profileName
            self.createdAt = createdAt
        }
    }

    private struct FailureFile: Codable {
        var code: String
        var at: Date
    }

    public enum HandoffError: Error, Equatable {
        case emptyConfig
        case missing
        case unreadable
    }

    public let directory: URL

    public init(directory: URL) {
        self.directory = directory
    }

    /// `<app group>/tunnel`
    public static func inAppGroup(_ groupID: String) -> TunnelHandoff? {
        #if os(Linux)
        _ = groupID
        return nil   // app groups do not exist on Linux (only reachable from the logic tests)
        #else
        guard let base = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: groupID) else {
            return nil
        }
        return TunnelHandoff(directory: base.appendingPathComponent("tunnel", isDirectory: true))
        #endif
    }

    var configURL: URL { directory.appendingPathComponent("config.json") }
    var failureURL: URL { directory.appendingPathComponent("last_failure.json") }

    private func ensureDirectory() throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    private func write(_ data: Data, to url: URL) throws {
        try ensureDirectory()
        #if os(iOS)
        try data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        #else
        try data.write(to: url, options: [.atomic])
        #endif
    }

    public func writeConfig(_ payload: Payload) throws {
        guard !payload.configJSON.isEmpty else { throw HandoffError.emptyConfig }
        let enc = JSONEncoder()
        enc.dateEncodingStrategy = .iso8601
        try write(try enc.encode(payload), to: configURL)
        try? FileManager.default.removeItem(at: failureURL)
    }

    public func readConfig() throws -> Payload {
        guard FileManager.default.fileExists(atPath: configURL.path) else { throw HandoffError.missing }
        guard let data = try? Data(contentsOf: configURL) else { throw HandoffError.unreadable }
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        guard let p = try? dec.decode(Payload.self, from: data), !p.configJSON.isEmpty else {
            throw HandoffError.unreadable
        }
        return p
    }

    public func clearConfig() {
        try? FileManager.default.removeItem(at: configURL)
    }

    public func recordFailure(_ kind: FailureKind, at date: Date = Date()) {
        let enc = JSONEncoder()
        enc.dateEncodingStrategy = .iso8601
        if let data = try? enc.encode(FailureFile(code: kind.code, at: date)) {
            try? write(data, to: failureURL)
        }
    }

    /// The failure the extension recorded, if it is newer than `since`.
    public func lastFailure(since: Date) -> FailureKind? {
        guard let data = try? Data(contentsOf: failureURL) else { return nil }
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        guard let f = try? dec.decode(FailureFile.self, from: data), f.at >= since else { return nil }
        return FailureKind(code: f.code)
    }

    public func clearFailure() {
        try? FileManager.default.removeItem(at: failureURL)
    }
}
