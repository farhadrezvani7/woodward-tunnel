import Foundation

/// Looks up a localized string by key (Persian is the development language, English the second).
func L(_ key: String) -> String {
    NSLocalizedString(key, comment: "")
}

func L(_ key: String, _ args: CVarArg...) -> String {
    String(format: NSLocalizedString(key, comment: ""), locale: Locale.current, arguments: args)
}

/// True when the UI is shown in Persian (used for digit shaping in the timer).
var uiIsPersian: Bool {
    (Bundle.main.preferredLocalizations.first ?? "").hasPrefix("fa")
}
