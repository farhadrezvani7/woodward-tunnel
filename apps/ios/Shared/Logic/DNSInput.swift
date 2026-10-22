import Foundation

/// Parsing for the DNS field under "Advanced settings".
public enum DNSInput {
    /// Accepts IPv4 / IPv6 literals separated by spaces, commas or newlines. Returns nil when
    /// something is not an IP address, so a typo is never silently dropped.
    public static func parse(_ text: String) -> [String]? {
        let parts = text.split(whereSeparator: { " ,;\n\t،".contains($0) }).map(String.init)
        if parts.isEmpty { return nil }
        for p in parts where !isIPLiteral(p) { return nil }
        return parts
    }

    public static func isIPLiteral(_ s: String) -> Bool {
        isIPv4(s) || isIPv6(s)
    }

    static func isIPv4(_ s: String) -> Bool {
        let octets = s.split(separator: ".", omittingEmptySubsequences: false)
        guard octets.count == 4 else { return false }
        for o in octets {
            guard !o.isEmpty, o.count <= 3, o.allSatisfy({ $0.isASCII && $0.isNumber }),
                  let v = Int(o), v <= 255 else { return false }
        }
        return true
    }

    static func isIPv6(_ s: String) -> Bool {
        guard s.contains(":"), s.count <= 45 else { return false }
        let allowed = Set("0123456789abcdefABCDEF:.")
        guard s.allSatisfy({ allowed.contains($0) }) else { return false }
        let doubleColons = s.components(separatedBy: "::").count - 1
        if doubleColons > 1 { return false }
        let groups = s.split(separator: ":", omittingEmptySubsequences: false)
        if groups.count > 8 + 1 { return false }
        return groups.allSatisfy { $0.count <= 4 || $0.contains(".") }
    }
}
