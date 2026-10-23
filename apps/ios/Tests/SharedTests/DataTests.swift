import XCTest
@testable import WTSharedLogic

final class DataTests: XCTestCase {
    func testVaultRoundTrip() {
        let backend = InMemorySecretBackend()
        let v = SecretVault(backend: backend)
        XCTAssertNil(v.get(id: "a"))
        XCTAssertTrue(v.put(id: "a", value: "پسورد-1"))
        XCTAssertEqual(v.get(id: "a"), "پسورد-1")
        XCTAssertTrue(v.put(id: "a", value: "two"))
        XCTAssertEqual(v.get(id: "a"), "two")
        XCTAssertTrue(v.delete(id: "a"))
        XCTAssertNil(v.get(id: "a"))
        XCTAssertTrue(v.delete(id: "a"))
        XCTAssertFalse(v.put(id: "", value: "x"))
        backend.failWrites = true
        XCTAssertFalse(v.put(id: "b", value: "x"))
    }

    func testHandoffRoundTripAndFailure() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("wt-handoff-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let h = TunnelHandoff(directory: dir)
        XCTAssertThrowsError(try h.readConfig())
        XCTAssertThrowsError(try h.writeConfig(.init(configJSON: "", insecureTLS: false, profileName: "x")))
        try h.writeConfig(.init(configJSON: "{\"log\":{}}", insecureTLS: true, profileName: "سرور"))
        let p = try h.readConfig()
        XCTAssertEqual(p.configJSON, "{\"log\":{}}")
        XCTAssertTrue(p.insecureTLS)
        XCTAssertEqual(p.profileName, "سرور")

        let before = Date(timeIntervalSinceNow: -10)
        h.recordFailure(.tunnelStartFailed)
        XCTAssertEqual(h.lastFailure(since: before), .tunnelStartFailed)
        h.recordFailure(.helperStartFailed)
        XCTAssertEqual(h.lastFailure(since: before), .helperStartFailed)
        XCTAssertNil(h.lastFailure(since: Date(timeIntervalSinceNow: 10)))
        // writing a new config clears the stale failure
        try h.writeConfig(.init(configJSON: "{}", insecureTLS: false, profileName: "y"))
        XCTAssertNil(h.lastFailure(since: before))
        h.clearConfig()
        XCTAssertThrowsError(try h.readConfig())
    }

    func testHandoffCarriesHelperConfig() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("wt-handoff-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let h = TunnelHandoff(directory: dir)
        try h.writeConfig(.init(configJSON: "{}", helperJSON: "{\"awg\":1}", insecureTLS: false, profileName: "a"))
        XCTAssertEqual(try h.readConfig().helperJSON, "{\"awg\":1}")
        try h.writeConfig(.init(configJSON: "{}", insecureTLS: false, profileName: "b"))
        XCTAssertNil(try h.readConfig().helperJSON)
    }

    func testProblemLanguage() {
        let p = ImportOutcome.Problem(label: "l", message: "فارسی", messageEn: "english", code: "c")
        XCTAssertEqual(p.text(persian: true), "فارسی")
        XCTAssertEqual(p.text(persian: false), "english")
        let q = ImportOutcome.Problem(label: "l", message: "فارسی")
        XCTAssertEqual(q.text(persian: false), "فارسی")
    }

    func testGrouping() {
        func item(_ id: String, _ group: String, _ created: Int64) -> ProfileItem {
            ProfileItem(id: id, name: id, protocolId: "vless", protocolName: "VLESS", host: "h", port: 443, group: group, createdAt: created)
        }
        let s = ProfileGrouping.sections([item("a", "B", 1), item("b", "", 2), item("c", "A", 3), item("d", "", 5)])
        XCTAssertEqual(s.map { $0.title }, ["", "A", "B"])
        XCTAssertEqual(s[0].items.map { $0.id }, ["d", "b"])
        XCTAssertEqual(ProfileGrouping.groupNames([item("a", "B", 1), item("b", "", 2)]), ["B"])
    }

    func testUnsupportedBadge() {
        let p = ProfileItem(id: "1", name: "n", protocolId: "openvpn", protocolName: "OpenVPN", host: "", port: 0, group: "", createdAt: 0)
        XCTAssertFalse(p.runsOnThisPlatform)
        XCTAssertEqual(p.endpointText, "")
    }

    func testImportHeadline() {
        func o(_ a: Int, _ d: Int, _ p: Int, _ s: Int) -> ImportOutcome {
            ImportOutcome(addedCount: a, duplicates: d,
                          problems: (0..<p).map { _ in .init(label: "l", message: "m") },
                          subscriptionURLs: (0..<s).map { _ in "https://x.example/sub?token=1" })
        }
        XCTAssertEqual(o(2, 0, 1, 0).headline, .added(2))
        XCTAssertEqual(o(0, 0, 0, 1).headline, .needsSubscriptionDecision)
        XCTAssertEqual(o(0, 1, 0, 0).headline, .onlyDuplicates)
        XCTAssertEqual(o(0, 0, 1, 0).headline, .failed)
        XCTAssertEqual(o(0, 0, 0, 0).headline, .nothingFound)
        XCTAssertEqual(SubscriptionDisplay.hostOnly("https://sub.example.org/a/b?token=secret"), "sub.example.org")
        XCTAssertEqual(SubscriptionDisplay.hostOnly("not a url"), "")
    }

    func testDNSParsing() {
        XCTAssertEqual(DNSInput.parse("1.1.1.1, 8.8.8.8"), ["1.1.1.1", "8.8.8.8"])
        XCTAssertEqual(DNSInput.parse("2606:4700:4700::1111\n9.9.9.9"), ["2606:4700:4700::1111", "9.9.9.9"])
        XCTAssertNil(DNSInput.parse("dns.google"))
        XCTAssertNil(DNSInput.parse("1.1.1.256"))
        XCTAssertNil(DNSInput.parse("  "))
        XCTAssertNil(DNSInput.parse("1.1.1.1 oops"))
    }
}

final class SnifferTests: XCTestCase {
    func testSniff() {
        XCTAssertEqual(ImageSniffer.sniff(Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0])), .png)
        XCTAssertEqual(ImageSniffer.sniff(Data([0xFF, 0xD8, 0xFF, 0xE0])), .jpeg)
        XCTAssertEqual(ImageSniffer.sniff(Data("ftypheic".utf8)), .other)
        XCTAssertEqual(ImageSniffer.sniff(Data()), .other)
    }
}

final class LogRingTests: XCTestCase {
    func testRedaction() {
        let r = LogRedactor.redact("connect to 203.0.113.7:443 via https://sub.example.org/x?token=abc key AbCdEfGhIjKlMnOpQrStUvWxYz012345 id 123e4567-e89b-12d3-a456-426614174000 v6 2001:db8::1")
        XCTAssertFalse(r.contains("203.0.113.7"))
        XCTAssertFalse(r.contains("example.org"))
        XCTAssertFalse(r.contains("AbCdEf"))
        XCTAssertFalse(r.contains("2001:db8"))
        XCTAssertFalse(r.contains("123e4567"))
        XCTAssertEqual(LogRedactor.redact("state=connected code=tunnel_start_failed"), "state=connected code=tunnel_start_failed")
        XCTAssertLessThanOrEqual(LogRedactor.redact(String(repeating: "a b ", count: 200)).count, 300)
    }

    func testRingKeepsNewestAndSurvivesMissingFile() {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("wt-ring-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let ring = LogRing(directory: dir, capacity: 3)
        XCTAssertEqual(ring.tail(), [])
        for i in 1...5 { ring.append("line \(i)") }
        let t = ring.tail()
        XCTAssertEqual(t.count, 3)
        XCTAssertTrue(t[0].hasSuffix("line 3"))
        XCTAssertTrue(t[2].hasSuffix("line 5"))
        ring.clear()
        XCTAssertEqual(ring.tail(), [])
    }
}
