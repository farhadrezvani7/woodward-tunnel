import SwiftUI
import UIKit

struct Banner: Identifiable, Equatable {
    enum Kind { case success, warning, error }
    let id = UUID()
    let kind: Kind
    let text: String
}

/// Single source of truth for the UI. All state changes happen on the main actor; the Rust core
/// and the system tunnel are reached through `CoreService` and `TunnelController`.
@MainActor
final class AppModel: ObservableObject {
    // MARK: published state
    @Published private(set) var profiles: [ProfileItem] = []
    @Published var selectedID: String? {
        didSet { UserDefaults.standard.set(selectedID, forKey: AppConstants.DefaultsKey.selectedProfileID) }
    }
    @Published private(set) var connection: ConnectionState = .disconnected
    @Published private(set) var connectedWithInsecureTLS = false
    @Published private(set) var isWorking = false
    @Published private(set) var coreError: String?
    @Published var banner: Banner?
    @Published var pendingSubscriptions: [String] = []
    @Published var dnsServers: [String]

    // presentation flags driven from several places
    @Published var showFileImporter = false
    @Published var showScanner = false
    @Published var showPhotoPicker = false
    @Published var showAdvanced = false

    // MARK: private
    private var core: CoreService?
    private let tunnel = TunnelController()
    private var machine = ConnectionStateMachine()
    private var userStopped = false
    private var isPreparing = false
    private var connectRequestedAt = Date()
    private var started = false

    init() {
        let saved = UserDefaults.standard.stringArray(forKey: AppConstants.DefaultsKey.dnsServers)
        dnsServers = (saved?.isEmpty == false) ? saved! : AppConstants.defaultDNS
        selectedID = UserDefaults.standard.string(forKey: AppConstants.DefaultsKey.selectedProfileID)
    }

    var selectedProfile: ProfileItem? {
        profiles.first { $0.id == selectedID }
    }

    // MARK: lifecycle

    func start() async {
        guard !started else { return }
        started = true
        do {
            core = try CoreService()
        } catch {
            coreError = error.localizedDescription
            return
        }
        await reload()
        tunnel.onStatusChange = { [weak self] status in self?.handleTunnelStatus(status) }
        do {
            try await tunnel.load()
        } catch {
            // No configuration yet, or the system refused to list it: both mean "disconnected".
        }
        syncInitialStatus()
    }

    private func syncInitialStatus() {
        let status = tunnel.currentStatus
        if status == .connected || status == .connecting || status == .reasserting {
            // The extension survived an app relaunch.
            userStopped = false
            connectRequestedAt = Date()
            machine = ConnectionStateMachine(state: status == .connected
                ? .connected(since: tunnel.connectedDate ?? Date()) : .connecting)
            connection = machine.state
        }
    }

    // MARK: profiles

    func reload() async {
        guard let core else { return }
        do {
            profiles = try await core.list()
            if selectedProfile == nil { selectedID = profiles.first?.id }
        } catch {
            show(.error, error.localizedDescription)
        }
    }

    func rename(_ profile: ProfileItem, to name: String) {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let core, !trimmed.isEmpty else { return }
        Task {
            do {
                try await core.rename(id: profile.id, name: trimmed)
                await reload()
            } catch {
                show(.error, error.localizedDescription)
            }
        }
    }

    func setGroup(_ profile: ProfileItem, to group: String) {
        guard let core else { return }
        let trimmed = group.trimmingCharacters(in: .whitespacesAndNewlines)
        Task {
            do {
                try await core.setGroup(id: profile.id, group: trimmed)
                await reload()
            } catch {
                show(.error, error.localizedDescription)
            }
        }
    }

    func delete(_ profile: ProfileItem) {
        guard let core else { return }
        if profile.id == selectedID, connection.isActive { disconnect() }
        Task {
            do {
                try await core.delete(id: profile.id)
                await reload()
            } catch {
                show(.error, error.localizedDescription)
            }
        }
    }

    // MARK: import

    func importText(_ text: String) {
        runImport { try await $0.importText(text) }
    }

    func importData(_ data: Data) {
        runImport { try await $0.importBytes(data) }
    }

    func importFromClipboard() {
        guard let text = UIPasteboard.general.string, !text.isEmpty else {
            show(.warning, L("import.clipboard.empty"))
            return
        }
        importText(text)
    }

    func confirmNextSubscription() {
        guard let url = pendingSubscriptions.first else { return }
        pendingSubscriptions.removeFirst()
        runImport { try await $0.importSubscription(url: url, group: SubscriptionDisplay.hostOnly(url)) }
    }

    func declineNextSubscription() {
        if !pendingSubscriptions.isEmpty { pendingSubscriptions.removeFirst() }
    }

    private func runImport(_ op: @escaping (CoreService) async throws -> ImportOutcome) {
        guard let core else { return }
        isWorking = true
        Task {
            defer { isWorking = false }
            do {
                let outcome = try await op(core)
                await reload()
                present(outcome)
            } catch {
                show(.error, error.localizedDescription)
            }
        }
    }

    private func present(_ outcome: ImportOutcome) {
        if !outcome.subscriptionURLs.isEmpty {
            pendingSubscriptions.append(contentsOf: outcome.subscriptionURLs)
        }
        switch outcome.headline {
        case .added(let n):
            if let newest = profiles.max(by: { $0.createdAt < $1.createdAt }), selectedID == nil {
                selectedID = newest.id
            }
            show(.success, L("import.added", n))
        case .onlyDuplicates:
            show(.warning, L("import.duplicates"))
        case .failed:
            show(.error, outcome.problems.first?.text(persian: uiIsPersian) ?? L("import.failed"))
        case .needsSubscriptionDecision:
            break // the confirmation dialog is the feedback
        case .nothingFound:
            show(.warning, L("import.nothing"))
        }
    }

    // MARK: connection

    func connectButtonTapped() {
        switch connection {
        case .connected, .connecting: disconnect()
        case .disconnecting: break
        case .disconnected, .failed: connect()
        }
    }

    func connect() {
        guard let core else { return }
        guard let profile = selectedProfile else {
            apply { $0.fail(.noProfile) }
            return
        }
        userStopped = false
        isPreparing = true
        connectRequestedAt = Date()
        apply { $0.userRequestedConnect() }
        Task {
            defer { isPreparing = false }
            do {
                let decision = try await core.launchDecision(profileID: profile.id, dns: dnsServers)
                switch decision {
                case .unsupported(let engine):
                    apply { $0.fail(.unsupportedEngine(engine)) }
                case .runSingBox(let json, let insecure):
                    try await launch(handoffPayload: .init(configJSON: json, insecureTLS: insecure, profileName: profile.name))
                case .runAmneziaWG(let helper, let json):
                    try await launch(handoffPayload: .init(configJSON: json, helperJSON: helper, insecureTLS: false, profileName: profile.name))
                }
            } catch is CoreService.CoreFailure {
                // launchPlan refused: the stored profile is not usable as it is.
                apply { $0.fail(.configInvalid) }
            } catch {
                apply { $0.fail(FailureMapping.kind(for: error)) }
            }
        }
    }

    private func launch(handoffPayload: TunnelHandoff.Payload) async throws {
        guard let handoff = TunnelHandoff.inAppGroup(AppConstants.appGroupID) else {
            apply { $0.fail(.tunnelStartFailed) }
            return
        }
        try handoff.writeConfig(handoffPayload)
        connectedWithInsecureTLS = handoffPayload.insecureTLS
        try await tunnel.prepare()
        guard !userStopped else {
            handoff.clearConfig()
            return
        }
        try tunnel.start()
    }

    func disconnect() {
        userStopped = true
        apply { $0.userRequestedDisconnect() }
        tunnel.stop()
        if !isPreparing, tunnel.currentStatus == .disconnected || tunnel.currentStatus == .invalid {
            apply { $0.tunnelStatusChanged(.disconnected, now: Date(), failure: nil) }
        }
    }

    func resetVPNConfiguration() {
        Task {
            do {
                try await tunnel.removeConfiguration()
                apply { $0.tunnelStatusChanged(.disconnected, now: Date(), failure: nil) }
                show(.success, L("advanced.reset.done"))
            } catch {
                show(.error, error.localizedDescription)
            }
        }
    }

    private func handleTunnelStatus(_ status: TunnelStatus) {
        switch status {
        case .disconnected, .invalid:
            if isPreparing { return } // events caused by saving the configuration
            TunnelHandoff.inAppGroup(AppConstants.appGroupID)?.clearConfig()
            let wasRunning = machine.state.isActive || machine.state == .disconnecting
            if wasRunning && !userStopped {
                let since = connectRequestedAt
                Task {
                    let kind = await tunnel.resolveFailure(since: since) ?? .unknown
                    apply { $0.tunnelStatusChanged(.disconnected, now: Date(), failure: kind) }
                }
            } else {
                apply { $0.tunnelStatusChanged(status, now: Date(), failure: nil) }
            }
        default:
            apply { $0.tunnelStatusChanged(status, now: Date(), failure: nil) }
        }
    }

    private func apply(_ change: (inout ConnectionStateMachine) -> Void) {
        change(&machine)
        connection = machine.state
        if case .failed = machine.state {
            UIAccessibility.post(notification: .announcement, argument: L("state.failed"))
        }
    }

    // MARK: settings

    /// Returns false when the text contains something that is not an IP address.
    func saveDNS(_ text: String) -> Bool {
        guard let list = DNSInput.parse(text) else { return false }
        dnsServers = list
        UserDefaults.standard.set(list, forKey: AppConstants.DefaultsKey.dnsServers)
        return true
    }

    func resetDNS() {
        dnsServers = AppConstants.defaultDNS
        UserDefaults.standard.removeObject(forKey: AppConstants.DefaultsKey.dnsServers)
    }

    // MARK: banners

    func show(_ kind: Banner.Kind, _ text: String) {
        let b = Banner(kind: kind, text: text)
        banner = b
        UIAccessibility.post(notification: .announcement, argument: text)
        Task {
            try? await Task.sleep(nanoseconds: 4_000_000_000)
            if banner?.id == b.id { banner = nil }
        }
    }

    /// Redacted text the user can copy and send to support: no profile names, hosts or secrets.
    var diagnosticsText: String {
        let info = Bundle.main.infoDictionary
        let version = info?["CFBundleShortVersionString"] as? String ?? "?"
        let build = info?["CFBundleVersion"] as? String ?? "?"
        return [
            "Woodward Tunnel \(version) (\(build))",
            "iOS \(UIDevice.current.systemVersion)",
            "state: \(connection.statusKey)",
            "profiles: \(profiles.count)",
        ].joined(separator: "\n")
    }
}
