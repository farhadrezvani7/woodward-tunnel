import XCTest
@testable import WTSharedLogic

final class ConnectionStateTests: XCTestCase {
    private let t0 = Date(timeIntervalSince1970: 1_000)

    func testHappyPath() {
        var m = ConnectionStateMachine()
        m.userRequestedConnect()
        XCTAssertEqual(m.state, .connecting)
        m.tunnelStatusChanged(.connecting, now: t0, failure: nil)
        XCTAssertEqual(m.state, .connecting)
        m.tunnelStatusChanged(.connected, now: t0, failure: nil)
        XCTAssertEqual(m.state, .connected(since: t0))
        // a repeated "connected" must not reset the timer
        m.tunnelStatusChanged(.connected, now: t0.addingTimeInterval(50), failure: nil)
        XCTAssertEqual(m.state, .connected(since: t0))
        m.userRequestedDisconnect()
        XCTAssertEqual(m.state, .disconnecting)
        m.tunnelStatusChanged(.disconnected, now: t0, failure: nil)
        XCTAssertEqual(m.state, .disconnected)
    }

    func testFailureIsKeptUntilUserActs() {
        var m = ConnectionStateMachine()
        m.userRequestedConnect()
        m.tunnelStatusChanged(.disconnected, now: t0, failure: .serverUnreachable)
        XCTAssertEqual(m.state, .failed(.serverUnreachable))
        m.tunnelStatusChanged(.disconnected, now: t0, failure: nil)
        XCTAssertEqual(m.state, .failed(.serverUnreachable))
        m.userRequestedConnect()
        XCTAssertEqual(m.state, .connecting)
    }

    func testReassertingShowsConnecting() {
        var m = ConnectionStateMachine(state: .connected(since: t0))
        m.tunnelStatusChanged(.reasserting, now: t0, failure: nil)
        XCTAssertEqual(m.state, .connecting)
        m.tunnelStatusChanged(.connected, now: t0.addingTimeInterval(5), failure: nil)
        XCTAssertEqual(m.state, .connected(since: t0.addingTimeInterval(5)))
    }

    func testConnectIgnoredWhileActive() {
        var m = ConnectionStateMachine(state: .connected(since: t0))
        m.userRequestedConnect()
        XCTAssertEqual(m.state, .connected(since: t0))
    }

    func testFailureCodesRoundTrip() {
        let all: [FailureKind] = [.noProfile, .configInvalid, .permissionDenied, .vpnDisabled, .noNetwork,
                                  .serverUnreachable, .unsupportedEngine(.amneziaWg),
                                  .unsupportedEngine(.openVpn), .tunnelStartFailed, .helperStartFailed, .unknown]
        for k in all {
            XCTAssertEqual(FailureKind(code: k.code), k)
            XCTAssertTrue(k.titleKey.hasPrefix("failure."))
        }
        XCTAssertNil(FailureKind(code: "bogus"))
    }

    func testErrorMapping() {
        XCTAssertEqual(FailureMapping.kind(domain: "NEVPNErrorDomain", code: 5), .permissionDenied)
        XCTAssertEqual(FailureMapping.kind(domain: "NEVPNErrorDomain", code: 2), .vpnDisabled)
        XCTAssertEqual(FailureMapping.kind(domain: FailureMapping.extensionErrorDomain,
                                           code: FailureMapping.ExtensionCode.missingConfig.rawValue), .configInvalid)
        XCTAssertEqual(FailureMapping.kind(domain: "x", code: 1), .unknown)
    }

    func testElapsed() {
        XCTAssertEqual(ElapsedFormatter.string(seconds: 65, persianDigits: false), "01:05")
        XCTAssertEqual(ElapsedFormatter.string(seconds: 3725, persianDigits: false), "1:02:05")
        XCTAssertEqual(ElapsedFormatter.string(seconds: -4, persianDigits: false), "00:00")
        XCTAssertEqual(ElapsedFormatter.string(seconds: 65, persianDigits: true), "۰۱:۰۵")
    }
}
