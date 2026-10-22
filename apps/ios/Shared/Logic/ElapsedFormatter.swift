import Foundation

public enum ElapsedFormatter {
    /// "mm:ss" below one hour, "h:mm:ss" above. Negative values are clamped to zero.
    public static func string(from start: Date, to now: Date, persianDigits: Bool) -> String {
        string(seconds: Int(max(0, now.timeIntervalSince(start))), persianDigits: persianDigits)
    }

    public static func string(seconds total: Int, persianDigits: Bool) -> String {
        let t = max(0, total)
        let h = t / 3600
        let m = (t % 3600) / 60
        let s = t % 60
        var out: String
        if h > 0 {
            out = "\(h):" + two(m) + ":" + two(s)
        } else {
            out = two(m) + ":" + two(s)
        }
        if persianDigits { out = toPersianDigits(out) }
        return out
    }

    private static func two(_ v: Int) -> String { v < 10 ? "0\(v)" : "\(v)" }

    public static func toPersianDigits(_ text: String) -> String {
        let map: [Character: Character] = [
            "0": "۰", "1": "۱", "2": "۲", "3": "۳", "4": "۴",
            "5": "۵", "6": "۶", "7": "۷", "8": "۸", "9": "۹",
        ]
        return String(text.map { map[$0] ?? $0 })
    }
}
