package app.woodwardtunnel.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PrefsDnsTest {
    @Test fun blankMeansDefault() = assertEquals(emptyList<String>(), Prefs.parseDns("  "))

    @Test fun acceptsIpsAndUrls() {
        assertEquals(listOf("1.1.1.1", "8.8.8.8"), Prefs.parseDns("1.1.1.1, 8.8.8.8"))
        assertEquals(listOf("https://dns.google/dns-query"), Prefs.parseDns("https://dns.google/dns-query"))
        assertEquals(listOf("tls://one.one.one.one"), Prefs.parseDns("tls://one.one.one.one"))
        assertEquals(listOf("2606:4700:4700::1111"), Prefs.parseDns("2606:4700:4700::1111"))
    }

    @Test fun rejectsEverythingElse() {
        assertNull(Prefs.parseDns("999.1.1.1"))
        assertNull(Prefs.parseDns("dns.google"))
        assertNull(Prefs.parseDns("http://dns.google/dns-query"))
        assertNull(Prefs.parseDns("https://user:pw@dns.google/"))
        assertNull(Prefs.parseDns("https://dns.google/a b"))
        assertNull(Prefs.parseDns("tls://dns.google/path"))
        assertNull(Prefs.parseDns("1.1.1.1,1.1.1.2,1.1.1.3,1.1.1.4,1.1.1.5"))
    }
}
