import Foundation

public class CipherState: @unchecked Sendable {
    private let cipher: CipherFunction
    private var k: Data?
    private var n: UInt64 = 0
    private var invalidated = false
    private let lock = NSLock()

    init(cipher: CipherFunction, key: Data? = nil) {
        self.cipher = cipher
        self.k = key.map { Data($0) }
    }

    public func hasKey() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return k != nil
    }

    func setKey(_ key: Data) {
        lock.lock()
        defer { lock.unlock() }
        self.k = Data(key)
        self.n = 0
    }

    public func encryptWithAd(_ ad: Data, plaintext: Data) throws -> Data {
        lock.lock()
        defer { lock.unlock() }
        if invalidated { throw NoiseError.sessionInvalidated }
        guard let key = k else { return plaintext }
        if n == UInt64.max { throw NoiseError.nonceExhausted }
        let ciphertext = try cipher.encrypt(key: key, nonce: n, ad: ad, plaintext: plaintext)
        n += 1
        if n == UInt64.max { rekey() }
        return ciphertext
    }

    public func decryptWithAd(_ ad: Data, ciphertext: Data) throws -> Data {
        lock.lock()
        defer { lock.unlock() }
        if invalidated { throw NoiseError.sessionInvalidated }
        guard let key = k else { return ciphertext }
        if n == UInt64.max { throw NoiseError.nonceExhausted }
        do {
            let plaintext = try cipher.decrypt(key: key, nonce: n, ad: ad, ciphertext: ciphertext)
            n += 1
            if n == UInt64.max { rekey() }
            return plaintext
        } catch {
            invalidated = true
            throw NoiseError.decryptionFailed
        }
    }

    private func rekey() {
        let maxNonce = UInt64.max
        var newKey = try! cipher.encrypt(key: k!, nonce: maxNonce, ad: Data(), plaintext: Data(count: 32))
        if newKey.count > 32 { newKey = newKey.prefix(32) }
        k = newKey
        n = 0
    }

    func setNonceForTesting(_ nonce: UInt64) {
        lock.lock()
        defer { lock.unlock() }
        n = nonce
    }
}
