import Foundation

/// Thin async wrapper around the UniFFI-generated `WtApp`. The Rust calls are blocking
/// (SQLite, subscription download), so they run on a private serial queue.
/// Everything the UI needs comes out as the FFI-free types from Shared/Logic.
final class CoreService {
    struct CoreFailure: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    private let app: WtApp
    private let queue = DispatchQueue(label: "app.woodward.tunnel.core", qos: .userInitiated)

    init() throws {
        let dir = try CoreService.prepareDataDirectory()
        do {
            app = try WtApp(dataDir: dir.path, secrets: AppSecretCallbacks.makeDefault())
        } catch let FfiError.Failed(message) {
            throw CoreFailure(message: message)
        }
    }

    /// Application Support/WoodwardTunnel: profile database (no secrets inside; those are in the
    /// Keychain). Excluded from backups, because secrets are device-bound and a restored copy of
    /// the database on another device would point to secrets that do not exist there.
    private static func prepareDataDirectory() throws -> URL {
        var url = try FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true
        ).appendingPathComponent("WoodwardTunnel", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? url.setResourceValues(values)
        try? FileManager.default.setAttributes(
            [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
            ofItemAtPath: url.path
        )
        return url
    }

    private func run<T>(_ work: @escaping () throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                do {
                    continuation.resume(returning: try work())
                } catch let FfiError.Failed(message) {
                    continuation.resume(throwing: CoreFailure(message: message))
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    // MARK: mapping

    private static func item(_ p: FfiProfile) -> ProfileItem {
        ProfileItem(id: p.id, name: p.name, protocolId: p.protocolId, protocolName: p.protocolName,
                    host: p.host, port: p.port, group: p.group, createdAt: p.createdAt)
    }

    private static func outcome(_ r: FfiImportReport) -> ImportOutcome {
        ImportOutcome(
            addedCount: r.added.count,
            duplicates: Int(r.duplicates),
            problems: r.problems.map { ImportOutcome.Problem(label: $0.label, message: $0.message) },
            subscriptionURLs: r.subscriptionUrls
        )
    }

    // MARK: API

    func list() async throws -> [ProfileItem] {
        try await run { [app] in try app.list().map(CoreService.item) }
    }

    func importText(_ text: String, group: String = "") async throws -> ImportOutcome {
        try await run { [app] in CoreService.outcome(try app.importText(text: text, group: group)) }
    }

    func importBytes(_ data: Data, group: String = "") async throws -> ImportOutcome {
        try await run { [app] in CoreService.outcome(try app.importBytes(bytes: data, group: group)) }
    }

    /// Call only after the user agreed to download this subscription.
    func importSubscription(url: String, group: String) async throws -> ImportOutcome {
        try await run { [app] in CoreService.outcome(try app.importSubscription(url: url, group: group)) }
    }

    func rename(id: String, name: String) async throws {
        try await run { [app] in try app.rename(id: id, name: name) }
    }

    func setGroup(id: String, group: String) async throws {
        try await run { [app] in try app.setGroup(id: id, group: group) }
    }

    func delete(id: String) async throws {
        try await run { [app] in try app.delete(id: id) }
    }

    func launchDecision(profileID: String, dns: [String]) async throws -> LaunchDecision {
        try await run { [app] in
            switch try app.launchPlan(id: profileID, dns: dns) {
            case .singBox(let configJson, let insecureTls):
                return .runSingBox(configJSON: configJson, insecureTLS: insecureTls)
            case .amneziaWg:
                return .unsupported(.amneziaWg)
            case .openVpn:
                return .unsupported(.openVpn)
            }
        }
    }
}
