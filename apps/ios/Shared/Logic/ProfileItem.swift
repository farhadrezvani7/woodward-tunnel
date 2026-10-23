import Foundation

/// UI-side copy of the core's profile summary. Never contains secrets.
public struct ProfileItem: Identifiable, Equatable, Hashable {
    public let id: String
    public var name: String
    public var protocolId: String
    public var protocolName: String
    public var host: String
    public var port: UInt16
    public var group: String
    public var createdAt: Int64

    public init(id: String, name: String, protocolId: String, protocolName: String,
                host: String, port: UInt16, group: String, createdAt: Int64) {
        self.id = id
        self.name = name
        self.protocolId = protocolId
        self.protocolName = protocolName
        self.host = host
        self.port = port
        self.group = group
        self.createdAt = createdAt
    }

    /// Short text for the protocol badge.
    public var badge: String { protocolName.isEmpty ? protocolId.uppercased() : protocolName }

    /// True when this build of the app has an engine for the protocol (sing-box only for now).
    public var runsOnThisPlatform: Bool { ProfileItem.unsupportedProtocolIds.contains(protocolId) == false }

    public static let unsupportedProtocolIds: Set<String> = ["openvpn"]

    public var endpointText: String { host.isEmpty ? "" : "\(host):\(port)" }
}

public struct ProfileSection: Identifiable, Equatable {
    public let title: String   // empty = ungrouped
    public let items: [ProfileItem]
    public var id: String { title }
}

public enum ProfileGrouping {
    /// Ungrouped profiles first, then groups by name; inside a section newest first.
    public static func sections(_ items: [ProfileItem]) -> [ProfileSection] {
        let byGroup = Dictionary(grouping: items, by: { $0.group.trimmingCharacters(in: .whitespacesAndNewlines) })
        let names = byGroup.keys.sorted { a, b in
            if a.isEmpty != b.isEmpty { return a.isEmpty }
            return a.localizedCaseInsensitiveCompare(b) == .orderedAscending
        }
        return names.map { name in
            let sorted = (byGroup[name] ?? []).sorted { l, r in
                if l.createdAt != r.createdAt { return l.createdAt > r.createdAt }
                return l.name < r.name
            }
            return ProfileSection(title: name, items: sorted)
        }
    }

    /// Group names already in use (for the "move to group" picker).
    public static func groupNames(_ items: [ProfileItem]) -> [String] {
        Array(Set(items.map { $0.group }.filter { !$0.isEmpty })).sorted()
    }
}
