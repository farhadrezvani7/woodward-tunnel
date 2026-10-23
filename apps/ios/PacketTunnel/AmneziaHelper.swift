import Foundation
#if WT_AWG
import Libbox
#endif

/// The AmneziaWG userspace peer (engines/awg-socks/mobile, Go package `awgmobile`).
///
/// It is NOT a separate framework: build-ios.sh binds it into the same gomobile framework as
/// sing-box (Libbox.xcframework), because two gomobile frameworks cannot share one process (two Go
/// runtimes, duplicate symbols). gomobile names the exported functions `AwgmobileStart` and
/// `AwgmobileStop`; the signatures below come from `gobind -lang=objc` output
/// (`NSString* AwgmobileStart(NSString*, NSError**)`, `void AwgmobileStop(void)`).
/// UNVERIFIED: whether the framework's umbrella header exposes both packages through `import Libbox`.
///
/// Memory: peer and sing-box share one Go heap inside the extension, whose memory limit is small
/// (about 50 MB is commonly cited; unverified). AmneziaWG profiles are the most likely to be killed
/// by the system; measure on a device.
enum AmneziaHelper {
    struct HelperError: Error {}

    static func start(configJSON: String) throws {
        #if WT_AWG
        var error: NSError?
        let address = AwgmobileStart(configJSON, &error)
        if error != nil || address.isEmpty { throw HelperError() }
        #else
        throw HelperError() // built without the helper package
        #endif
    }

    static func stop() {
        #if WT_AWG
        AwgmobileStop()
        #endif
    }
}
