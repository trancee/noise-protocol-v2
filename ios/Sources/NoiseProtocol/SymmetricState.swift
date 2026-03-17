import Foundation

/// Manages the symmetric cryptographic state during a Noise Protocol handshake.
///
/// `SymmetricState` tracks the chaining key (`ck`) and handshake hash (`h`), providing
/// methods to mix in key material and data as the handshake progresses. It wraps a
/// ``CipherState`` that provides AEAD encryption once a key has been established via `mixKey`.
///
/// This class implements the `SymmetricState` object from Section 5.2 of the
/// [Noise Protocol specification](https://noiseprotocol.org/noise.html).
class SymmetricState {
    private var ck: Data
    private var h: Data
    private let cipher: CipherFunction
    private let hashFn: HashFunction
    private let cipherState: CipherState

    /// Creates a new symmetric state initialized with the given protocol name.
    ///
    /// The protocol name is hashed (or padded) to produce the initial handshake hash,
    /// which is also used as the initial chaining key.
    ///
    /// - Parameters:
    ///   - protocolName: The full Noise protocol name (e.g., `"Noise_XX_25519_ChaChaPoly_SHA256"`).
    ///   - cipher: The AEAD cipher function to use.
    ///   - hash: The hash function to use.
    init(protocolName: String, cipher: CipherFunction, hash: HashFunction) {
        self.cipher = cipher
        self.hashFn = hash
        self.cipherState = CipherState(cipher: cipher)

        let protocolBytes = Data(protocolName.utf8)
        if protocolBytes.count <= hash.hashLen {
            var padded = protocolBytes
            padded.append(Data(count: hash.hashLen - protocolBytes.count))
            self.h = padded
        } else {
            self.h = hash.hash(protocolBytes)
        }
        self.ck = Data(h)
    }

    /// Returns whether the underlying cipher state has an encryption key set.
    func hasKey() -> Bool { cipherState.hasKey() }

    /// Mixes input key material into the chaining key and sets a new cipher key.
    ///
    /// Performs HKDF with 2 outputs: the first updates the chaining key, the second
    /// becomes the new cipher key (truncated to 32 bytes if necessary).
    ///
    /// - Parameter inputKeyMaterial: The key material to mix in (e.g., a DH shared secret).
    func mixKey(_ inputKeyMaterial: Data) {
        let outputs = hashFn.hkdf(chainingKey: ck, inputKeyMaterial: inputKeyMaterial, numOutputs: 2)
        ck = outputs[0]
        cipherState.setKey(truncateKey(outputs[1]))
    }

    /// Mixes data into the handshake hash.
    ///
    /// Updates `h = HASH(h || data)`.
    ///
    /// - Parameter data: The data to mix into the hash (e.g., a public key or ciphertext).
    func mixHash(_ data: Data) {
        h = hashFn.hash(h + data)
    }

    /// Encrypts plaintext using the current handshake hash as associated data, then mixes the ciphertext into the hash.
    ///
    /// If no cipher key is set, the plaintext passes through unmodified but is still mixed into the hash.
    ///
    /// - Parameter plaintext: The data to encrypt.
    /// - Returns: The ciphertext (or unmodified plaintext if no key is set).
    /// - Throws: Rethrows any error from the underlying ``CipherState``.
    func encryptAndHash(_ plaintext: Data) throws -> Data {
        let ciphertext = try cipherState.encryptWithAd(h, plaintext: plaintext)
        mixHash(ciphertext)
        return ciphertext
    }

    /// Decrypts ciphertext using the current handshake hash as associated data, then mixes the ciphertext into the hash.
    ///
    /// If no cipher key is set, the ciphertext passes through unmodified but is still mixed into the hash.
    ///
    /// - Parameter ciphertext: The data to decrypt.
    /// - Returns: The decrypted plaintext (or unmodified ciphertext if no key is set).
    /// - Throws: Rethrows any error from the underlying ``CipherState``.
    func decryptAndHash(_ ciphertext: Data) throws -> Data {
        let plaintext = try cipherState.decryptWithAd(h, ciphertext: ciphertext)
        mixHash(ciphertext)
        return plaintext
    }

    /// Returns the current chaining key.
    ///
    /// - Returns: The chaining key data.
    func getChainingKey() -> Data {
        return ck
    }

    /// Splits the symmetric state into two ``CipherState`` instances for transport-phase encryption.
    ///
    /// Derives two independent cipher keys from the chaining key using HKDF, then securely
    /// zeroes the chaining key and intermediate key material.
    ///
    /// - Returns: A tuple of two `CipherState` instances: the first for the initiator's sending
    ///   direction, the second for the responder's sending direction.
    func split() -> (CipherState, CipherState) {
        var outputs = hashFn.hkdf(chainingKey: ck, inputKeyMaterial: Data(), numOutputs: 2)
        let c1 = CipherState(cipher: cipher)
        c1.setKey(truncateKey(outputs[0]))
        let c2 = CipherState(cipher: cipher)
        c2.setKey(truncateKey(outputs[1]))
        // Zero chaining key and intermediates
        for i in ck.indices { ck[i] = 0 }
        for i in outputs[0].indices { outputs[0][i] = 0 }
        for i in outputs[1].indices { outputs[1][i] = 0 }
        return (c1, c2)
    }

    /// Mixes input key material into the chaining key, handshake hash, and cipher key (3-output HKDF).
    ///
    /// Used by modern `psk` token processing. Output 1 updates `ck`, output 2 is mixed into
    /// `h`, and output 3 becomes the new cipher key.
    ///
    /// - Parameter inputKeyMaterial: The key material to mix in (typically a PSK).
    func mixKeyAndHash(_ inputKeyMaterial: Data) {
        let outputs = hashFn.hkdf(chainingKey: ck, inputKeyMaterial: inputKeyMaterial, numOutputs: 3)
        ck = outputs[0]
        mixHash(outputs[1])
        let truncatedK = outputs[2].count > 32 ? Data(outputs[2].prefix(32)) : outputs[2]
        cipherState.setKey(truncatedK)
    }

    /// Mixes a pre-shared key using the old `NoisePSK_` convention (2-output HKDF).
    ///
    /// Updates the chaining key and mixes the second output into the handshake hash,
    /// but does **not** set a cipher key. This follows the legacy `NoisePSK_` prefix convention.
    ///
    /// - Parameter psk: The pre-shared key to mix in.
    // Old NoisePSK_ convention: 2-output HKDF, updates ck + MixHash, no cipher key
    func mixPsk(_ psk: Data) {
        let outputs = hashFn.hkdf(chainingKey: ck, inputKeyMaterial: psk, numOutputs: 2)
        ck = outputs[0]
        mixHash(outputs[1])
    }

    private func truncateKey(_ key: Data) -> Data {
        key.count > 32 ? Data(key.prefix(32)) : key
    }
}
