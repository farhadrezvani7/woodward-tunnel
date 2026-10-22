import Foundation
import Libbox

// Small adapters between gomobile iterator protocols and Swift arrays.

extension LibboxStringIteratorProtocol {
    func drain() -> [String] {
        var out: [String] = []
        while hasNext() { out.append(next()) }
        return out
    }
}

extension LibboxRoutePrefixIteratorProtocol {
    func drain() -> [LibboxRoutePrefix] {
        var out: [LibboxRoutePrefix] = []
        while hasNext() {
            if let p = next() { out.append(p) }
        }
        return out
    }
}

/// Iterator handed back to Go for `getInterfaces()`.
final class NetworkInterfaceList: NSObject, LibboxNetworkInterfaceIteratorProtocol {
    private var items: [LibboxNetworkInterface]
    private var index = 0

    init(_ items: [LibboxNetworkInterface]) {
        self.items = items
    }

    func hasNext() -> Bool { index < items.count }

    func next() -> LibboxNetworkInterface? {
        guard index < items.count else { return nil }
        defer { index += 1 }
        return items[index]
    }
}
