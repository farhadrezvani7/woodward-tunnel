#if canImport(Security) && !os(Linux)
import Foundation
import Security

/// Keychain-backed `SecretBackend` (kSecClassGenericPassword).
///
/// Items are readable after the first unlock and never leave this device (no iCloud sync, no
/// backup restore to another device): kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly.
/// When `accessGroup` is non-empty it is used so that the packet tunnel extension could read the
/// same items; it must be listed in the keychain-access-groups entitlement.
/// UNVERIFIED: compiled and exercised only on a Mac. Without signing (CI simulator build)
/// SecItem calls with an access group fail with errSecMissingEntitlement; that path is not built or run in CI.
public final class SystemKeychainBackend: SecretBackend {
    private let service: String
    private let accessGroup: String

    public init(service: String, accessGroup: String) {
        self.service = service
        self.accessGroup = accessGroup
    }

    private func baseQuery(_ account: String) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        if !accessGroup.isEmpty {
            q[kSecAttrAccessGroup as String] = accessGroup
        }
        return q
    }

    public func write(account: String, data: Data) -> Bool {
        let query = baseQuery(account)
        let update: [String: Any] = [kSecValueData as String: data]
        let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if status == errSecSuccess { return true }
        if status != errSecItemNotFound { return false }
        var add = query
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
    }

    public func read(account: String) -> Data? {
        var query = baseQuery(account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { return nil }
        return result as? Data
    }

    public func remove(account: String) -> Bool {
        let status = SecItemDelete(baseQuery(account) as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }
}
#endif
