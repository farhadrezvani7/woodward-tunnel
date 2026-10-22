import Foundation

/// UI-side summary of one import call.
public struct ImportOutcome: Equatable {
    public struct Problem: Equatable {
        public let label: String
        public let message: String
        public init(label: String, message: String) {
            self.label = label
            self.message = message
        }
    }

    public var addedCount: Int
    public var duplicates: Int
    public var problems: [Problem]
    public var subscriptionURLs: [String]

    public init(addedCount: Int, duplicates: Int, problems: [Problem], subscriptionURLs: [String]) {
        self.addedCount = addedCount
        self.duplicates = duplicates
        self.problems = problems
        self.subscriptionURLs = subscriptionURLs
    }

    public var isEmpty: Bool {
        addedCount == 0 && duplicates == 0 && problems.isEmpty && subscriptionURLs.isEmpty
    }

    /// What the banner after an import should say.
    public enum Headline: Equatable {
        case added(Int)
        case onlyDuplicates
        case failed
        case needsSubscriptionDecision
        case nothingFound
    }

    public var headline: Headline {
        if addedCount > 0 { return .added(addedCount) }
        if !subscriptionURLs.isEmpty { return .needsSubscriptionDecision }
        if duplicates > 0 { return .onlyDuplicates }
        if !problems.isEmpty { return .failed }
        return .nothingFound
    }
}

/// A subscription link is a credential (it usually carries a token), so the confirmation
/// dialog shows only the host, never the full URL.
public enum SubscriptionDisplay {
    public static func hostOnly(_ urlString: String) -> String {
        guard let comps = URLComponents(string: urlString), let host = comps.host, !host.isEmpty else {
            return ""
        }
        return host
    }
}
