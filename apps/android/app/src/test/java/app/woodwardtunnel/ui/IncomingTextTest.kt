package app.woodwardtunnel.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class IncomingTextTest {
    private val view = "android.intent.action.VIEW"
    private val send = "android.intent.action.SEND"

    @Test fun viewWithKnownSchemeIsOffered() {
        assertEquals("ss://abc", Incoming.extract(view, "ss", "ss://abc", null))
        assertEquals("VLESS://x", Incoming.extract(view, "VLESS", "VLESS://x", null))
    }

    @Test fun viewWithOtherSchemesIsIgnored() {
        for (s in listOf("file", "content", "http", "https", "javascript", "intent", "")) {
            assertNull(s, Incoming.extract(view, s, "$s://x", null))
        }
        assertNull(Incoming.extract(view, null, "x", null))
    }

    @Test fun sendTakesExtraTextOnly() {
        assertEquals("hello", Incoming.extract(send, null, "ss://ignored", "hello"))
        assertNull(Incoming.extract(send, null, null, null))
    }

    @Test fun unknownActionAndBlankAreIgnored() {
        assertNull(Incoming.extract("android.intent.action.MAIN", "ss", "ss://x", "x"))
        assertNull(Incoming.extract(send, null, null, "   \n"))
    }

    @Test fun oversizedTextIsIgnored() {
        assertNull(Incoming.extract(send, null, null, "a".repeat(Incoming.MAX_TEXT + 1)))
        assertEquals(Incoming.MAX_TEXT, Incoming.extract(send, null, null, "a".repeat(Incoming.MAX_TEXT))!!.length)
    }

    @Test fun previewCountsLinksWithoutEchoingSecrets() {
        val p = Incoming.preview("ss://secret@host:1\nvless://uuid@h:2#x trojan://pw@h:3 not a link")
        assertEquals(3, p.links)
        assertEquals(listOf("ss", "vless", "trojan"), p.schemes)
        assertEquals(0, Incoming.preview("hello world").links)
    }

    @Test fun previewRejectsNonsenseSchemes() {
        assertEquals(0, Incoming.preview("<script>://x").links)
        assertEquals(0, Incoming.preview("://x").links)
    }
}

class DisplayTextTest {
    @Test fun bidiOverridesAreRemoved() {
        val evil = "\u202Egpj.exe \u2066x\u2069"
        val c = DisplayText.clean(evil)
        assertFalse(c.any { it in '\u202A'..'\u202E' || it in '\u2066'..'\u2069' })
    }

    @Test fun persianZwnjIsKept() {
        assertEquals("می\u200Cخواهم", DisplayText.clean("می\u200Cخواهم"))
    }

    @Test fun newlinesAndControlsBecomeSingleSpaces() {
        assertEquals("a b c", DisplayText.clean("a\n\n b\t\u0000c"))
    }

    @Test fun longNamesAreCutOnCodePointBoundaries() {
        val name = "\uD83D\uDE00".repeat(100)
        val c = DisplayText.clean(name, 11)
        assertTrue(c.endsWith("\u2026"))
        // no lone surrogate before the ellipsis
        assertFalse(Character.isHighSurrogate(c[c.length - 2]))
    }

    @Test fun isolatedWrapsInFsiPdi() {
        val s = DisplayText.isolated("abc")
        assertEquals('\u2068', s.first())
        assertEquals('\u2069', s.last())
    }

    @Test fun injectionTextIsPlainData() {
        val s = "'; DROP TABLE x;-- <b>\${jndi:ldap://x}</b>"
        assertEquals(s, DisplayText.clean(s))
    }
}
