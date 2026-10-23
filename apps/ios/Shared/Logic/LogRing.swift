import Foundation

/// Second-layer redaction for the few log lines the app and the extension keep for the
/// diagnostic report. The Rust core redacts again before building the report. Lines are
/// written by our own code (state names, failure codes), never raw engine output, so this
/// is defence in depth.
public enum LogRedactor {
    public static let maxLineLength = 300

    public static func redact(_ line: String) -> String {
        var out = line.replacingOccurrences(of: "\n", with: " ").replacingOccurrences(of: "\r", with: " ")
        // URLs
        out = replace(out, pattern: "[A-Za-z][A-Za-z0-9+.-]*://[^\\s]+", with: "<url>")
        // IPv4 (optionally with port)
        out = replace(out, pattern: "\\b\\d{1,3}(?:\\.\\d{1,3}){3}(?::\\d{1,5})?\\b", with: "<ip>")
        // IPv6-looking runs
        out = replace(out, pattern: "\\b[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}\\b", with: "<ip>")
        // long opaque tokens (keys, uuids, base64)
        out = replace(out, pattern: "[A-Za-z0-9+/_-]{24,}={0,2}", with: "<token>")
        out = replace(out, pattern: "\\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\\b", with: "<id>")
        if out.count > maxLineLength { out = String(out.prefix(maxLineLength)) }
        return out
    }

    private static func replace(_ s: String, pattern: String, with template: String) -> String {
        guard let re = try? NSRegularExpression(pattern: pattern) else { return s }
        let range = NSRange(s.startIndex..., in: s)
        return re.stringByReplacingMatches(in: s, options: [], range: range, withTemplate: template)
    }
}

/// Small ring buffer of redacted lines in a file inside the shared app-group directory, so the
/// extension can write and the app can read. Not a log of traffic: only lifecycle events.
public struct LogRing {
    public let url: URL
    public let capacity: Int

    public init(directory: URL, capacity: Int = 200) {
        self.url = directory.appendingPathComponent("log_tail.txt")
        self.capacity = capacity
    }

    public func append(_ line: String, now: Date = Date()) {
        let stamp = ISO8601DateFormatter().string(from: now)
        var lines = tail()
        lines.append(stamp + " " + LogRedactor.redact(line))
        if lines.count > capacity { lines.removeFirst(lines.count - capacity) }
        write(lines)
    }

    public func tail(max: Int = 200) -> [String] {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        let lines = text.split(separator: "\n", omittingEmptySubsequences: true).map(String.init)
        return Array(lines.suffix(max))
    }

    public func clear() {
        try? FileManager.default.removeItem(at: url)
    }

    private func write(_ lines: [String]) {
        let dir = url.deletingLastPathComponent()
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let data = Data((lines.joined(separator: "\n") + "\n").utf8)
        #if os(iOS)
        try? data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        #else
        try? data.write(to: url, options: [.atomic])
        #endif
    }
}

extension TunnelHandoff {
    public var log: LogRing { LogRing(directory: directory) }
}
