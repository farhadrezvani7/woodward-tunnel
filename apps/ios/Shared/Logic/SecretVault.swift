import Foundation

/// Storage primitive: opaque bytes by account name. The system implementation uses the Keychain
/// (Shared/Platform/SystemKeychainBackend.swift); tests use the in-memory one.
public protocol SecretBackend: AnyObject {
    func write(account: String, data: Data) -> Bool
    func read(account: String) -> Data?
    /// Deleting something that does not exist counts as success.
    func remove(account: String) -> Bool
}

/// String-valued secret storage with the semantics the Rust core expects from its
/// `SecretCallbacks`: put/get/delete by id, `get` returns nil when absent.
public final class SecretVault {
    private let backend: SecretBackend

    public init(backend: SecretBackend) {
        self.backend = backend
    }

    public func put(id: String, value: String) -> Bool {
        guard !id.isEmpty, let data = value.data(using: .utf8) else { return false }
        return backend.write(account: id, data: data)
    }

    public func get(id: String) -> String? {
        guard !id.isEmpty, let data = backend.read(account: id) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    public func delete(id: String) -> Bool {
        guard !id.isEmpty else { return false }
        return backend.remove(account: id)
    }
}

public final class InMemorySecretBackend: SecretBackend {
    private var items: [String: Data] = [:]
    private let lock = NSLock()
    public var failWrites = false

    public init() {}

    public func write(account: String, data: Data) -> Bool {
        lock.lock(); defer { lock.unlock() }
        if failWrites { return false }
        items[account] = data
        return true
    }

    public func read(account: String) -> Data? {
        lock.lock(); defer { lock.unlock() }
        return items[account]
    }

    public func remove(account: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        items.removeValue(forKey: account)
        return true
    }
}
