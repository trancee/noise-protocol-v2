import Foundation

/// Manages symmetric encryption state for a single direction of a Noise Protocol session.
///
/// `CipherState` tracks a cipher key and a nonce counter, providing authenticated
/// encryption with associated data (AEAD). It is thread-safe via an internal lock.
///
/// After the handshake completes, each party holds two `CipherState` instances:
/// one for sending and one for receiving. The nonce auto-increments with each
/// operation and triggers automatic rekeying when approaching exhaustion.
public class CipherState: @unchecked Sendable {
    private let cipher: CipherFunction
    private var k: Data?
    private var n: UInt64 = 0
    private var invalidated = false
    private let lock = NSLock()

    /// Creates a new cipher state with the specified cipher function and optional key.
    ///
    /// - Parameters:
    ///   - cipher: The AEAD cipher function to use (e.g., ChaChaPoly or AESGCM).
    ///   - key: An optional initial encryption key. If `nil`, the state starts without a key.
    init(cipher: CipherFunction, key: Data? = nil) {
        self.cipher = cipher
        self.k = key.map { Data($0) }
    }

    /// Returns whether this cipher state has an encryption key set.
    ///
    /// - Returns: `true` if a key is set and encryption/decryption will be performed;
    ///   `false` if data will pass through unmodified.
    public func hasKey() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return k != nil
    }

    /// Sets the encryption key and resets the nonce counter to zero.
    ///
    /// - Parameter key: The new 32-byte encryption key.
    func setKey(_ key: Data) {
        lock.lock()
        defer { lock.unlock() }
        self.k = Data(key)
        self.n = 0
    }

    /// Encrypts plaintext with associated data using the current key and nonce.
    ///
    /// If no key is set, the plaintext is returned unmodified. The nonce is automatically
    /// incremented after each successful encryption. If the nonce reaches `UInt64.max`,
    /// an automatic rekey is performed.
    ///
    /// - Parameters:
    ///   - ad: Associated data to authenticate but not encrypt.
    ///   - plaintext: The data to encrypt.
    /// - Returns: The ciphertext with appended authentication tag, or unmodified plaintext if no key is set.
    /// - Throws: ``NoiseError/sessionInvalidated`` if the session was invalidated,
    ///   ``NoiseError/nonceExhausted`` if the nonce counter has been exhausted.
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

    /// Decrypts ciphertext with associated data using the current key and nonce.
    ///
    /// If no key is set, the ciphertext is returned unmodified. On successful decryption,
    /// the nonce is incremented. On failure, the session is permanently invalidated.
    ///
    /// - Parameters:
    ///   - ad: The associated data that was used during encryption.
    ///   - ciphertext: The ciphertext with appended authentication tag to decrypt.
    /// - Returns: The decrypted plaintext, or unmodified ciphertext if no key is set.
    /// - Throws: ``NoiseError/sessionInvalidated`` if the session was invalidated,
    ///   ``NoiseError/nonceExhausted`` if the nonce counter has been exhausted,
    ///   ``NoiseError/decryptionFailed`` if authentication fails.
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
