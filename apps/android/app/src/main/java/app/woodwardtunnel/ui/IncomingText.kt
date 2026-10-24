package app.woodwardtunnel.ui

/**
 * Pure helpers for text that arrives from other apps or from the user's own data. Everything here is
 * hostile-input handling and has no Android dependency, so it is covered by JVM unit tests.
 */
object Incoming {
    const val MAX_TEXT = 200_000

    /** Schemes the manifest accepts for VIEW intents. Anything else is ignored even if it somehow arrives. */
    val SCHEMES = setOf(
        "vless", "vmess", "trojan", "ss", "hysteria", "hysteria2", "hy2", "tuic", "anytls", "wireguard", "vpn",
    )

    /**
     * The text another app asked us to import, or null when the intent should be ignored. The caller must
     * still ask the user before importing anything.
     */
    fun extract(action: String?, dataScheme: String?, dataString: String?, extraText: CharSequence?): String? {
        val text = when (action) {
            "android.intent.action.VIEW" ->
                if (dataScheme != null && dataScheme.lowercase() in SCHEMES) dataString else null
            "android.intent.action.SEND" -> extraText?.toString()
            else -> null
        }
        if (text.isNullOrBlank() || text.length > MAX_TEXT) return null
        return text
    }

    class Preview(val links: Int, val schemes: List<String>)

    /** What a pending import contains, without echoing any secret part of it. */
    fun preview(text: String): Preview {
        val schemes = LinkedHashSet<String>()
        var links = 0
        for (token in text.split(Regex("\\s+"))) {
            val i = token.indexOf("://")
            if (i in 1..16) {
                val s = token.substring(0, i).lowercase()
                if (s.all { it in 'a'..'z' || it in '0'..'9' || it == '+' || it == '-' || it == '.' }) {
                    links++
                    if (schemes.size < 5) schemes += s
                }
            }
        }
        return Preview(links, schemes.toList())
    }
}

object DisplayText {
    private const val FSI = '⁨'
    private const val PDI = '⁩'

    private fun hidden(c: Char): Boolean = when {
        c == '‌' || c == '‍' -> false // Persian needs ZWNJ; ZWJ joins emoji
        c.code < 0x20 || c.code in 0x7F..0x9F -> true
        c in '​'..'‏' -> true
        c in '‪'..'‮' -> true
        c in '⁠'..'⁩' -> true
        c == '؜' || c == '﻿' || c == ' ' || c == ' ' -> true
        else -> false
    }

    /** A name without invisible direction controls or line breaks, shortened to [max] characters. */
    fun clean(name: String, max: Int = 80): String {
        val sb = StringBuilder(name.length)
        var lastSpace = true
        for (c in name) {
            if (hidden(c)) { if (c.code < 0x20 || c == ' ' || c == ' ') { if (!lastSpace) sb.append(' '); lastSpace = true }; continue }
            if (c.isWhitespace()) { if (!lastSpace) sb.append(' '); lastSpace = true } else { sb.append(c); lastSpace = false }
        }
        var s = sb.toString().trim()
        if (s.length > max) {
            var cut = max
            if (Character.isHighSurrogate(s[cut - 1])) cut--
            s = s.substring(0, cut).trimEnd() + "…"
        }
        return s
    }

    /** [clean] plus a bidi isolate, so a name in one script cannot reorder the text around it. */
    fun isolated(name: String, max: Int = 80): String = FSI + clean(name, max) + PDI
}
