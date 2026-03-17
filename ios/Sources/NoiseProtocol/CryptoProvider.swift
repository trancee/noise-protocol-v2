import Foundation
import CryptoKit
import Security

/// A protocol for Diffie-Hellman key agreement functions used by the Noise Protocol.
///
/// Conforming types provide key generation and shared secret computation for a specific
/// elliptic curve (e.g., Curve25519 or X448).
public protocol DH: Sendable {
    /// The length in bytes of a public key and DH output for this function.
    var dhLen: Int { get }

    /// Generates a new random key pair.
    ///
    /// - Returns: A ``KeyPair`` containing the generated private and public keys.
    func generateKeyPair() -> KeyPair

    /// Performs a Diffie-Hellman key agreement operation.
    ///
    /// - Parameters:
    ///   - keyPair: The local key pair (private key is used).
    ///   - publicKey: The remote party's public key.
    /// - Returns: The shared secret as raw bytes.
    /// - Throws: An error if the keys are invalid.
    func dh(keyPair: KeyPair, publicKey: Data) throws -> Data
}

/// A protocol for AEAD cipher functions used by the Noise Protocol.
///
/// Conforming types provide authenticated encryption with associated data (AEAD)
/// using a 32-byte key and 8-byte nonce (formatted as 12 bytes per the Noise spec).
public protocol CipherFunction: Sendable {
    /// Encrypts plaintext with an AEAD cipher.
    ///
    /// - Parameters:
    ///   - key: The 32-byte encryption key.
    ///   - nonce: The 64-bit nonce value.
    ///   - ad: Associated data to authenticate but not encrypt.
    ///   - plaintext: The data to encrypt.
    /// - Returns: The ciphertext with appended 16-byte authentication tag.
    /// - Throws: An error if encryption fails.
    func encrypt(key: Data, nonce: UInt64, ad: Data, plaintext: Data) throws -> Data

    /// Decrypts ciphertext with an AEAD cipher.
    ///
    /// - Parameters:
    ///   - key: The 32-byte encryption key.
    ///   - nonce: The 64-bit nonce value.
    ///   - ad: Associated data that was authenticated during encryption.
    ///   - ciphertext: The ciphertext with appended 16-byte authentication tag.
    /// - Returns: The decrypted plaintext.
    /// - Throws: An error if decryption or authentication fails.
    func decrypt(key: Data, nonce: UInt64, ad: Data, ciphertext: Data) throws -> Data
}

/// A protocol for hash functions used by the Noise Protocol.
///
/// Conforming types provide cryptographic hashing and HMAC operations.
/// The Noise spec requires `HASH`, `HMAC-HASH`, and `HKDF` operations; the
/// `hmacHash` and `hkdf` methods have default implementations via the protocol extension.
public protocol HashFunction: Sendable {
    /// The output length of the hash function in bytes (e.g., 32 for SHA-256, 64 for SHA-512).
    var hashLen: Int { get }

    /// The internal block length of the hash function in bytes (e.g., 64 for SHA-256, 128 for SHA-512).
    var blockLen: Int { get }

    /// Computes the cryptographic hash of the given data.
    ///
    /// - Parameter data: The input data to hash.
    /// - Returns: The hash digest.
    func hash(_ data: Data) -> Data

    /// Computes HMAC using this hash function.
    ///
    /// - Parameters:
    ///   - key: The HMAC key.
    ///   - data: The data to authenticate.
    /// - Returns: The HMAC authentication code.
    func hmacHash(key: Data, data: Data) -> Data
}

extension HashFunction {
    /// Default HMAC implementation using the hash function per RFC 2104.
    ///
    /// - Parameters:
    ///   - key: The HMAC key. If longer than `blockLen`, it is first hashed.
    ///   - data: The data to authenticate.
    /// - Returns: The HMAC authentication code.
    public func hmacHash(key: Data, data: Data) -> Data {
        let paddedKey = key.count > blockLen ? hash(key) : key
        var ipad = Data(count: blockLen)
        var opad = Data(count: blockLen)
        for i in 0..<blockLen {
            let k: UInt8 = i < paddedKey.count ? paddedKey[paddedKey.startIndex + i] : 0
            ipad[i] = k ^ 0x36
            opad[i] = k ^ 0x5c
        }
        return hash(opad + hash(ipad + data))
    }

    /// Derives keys using HKDF as specified by the Noise Protocol.
    ///
    /// - Parameters:
    ///   - chainingKey: The current chaining key.
    ///   - inputKeyMaterial: The input key material (e.g., a DH shared secret).
    ///   - numOutputs: The number of output keys to derive (2 or 3).
    /// - Returns: An array of derived key data.
    public func hkdf(chainingKey: Data, inputKeyMaterial: Data, numOutputs: Int) -> [Data] {
        let tempKey = hmacHash(key: chainingKey, data: inputKeyMaterial)
        let output1 = hmacHash(key: tempKey, data: Data([0x01]))
        if numOutputs == 2 {
            let output2 = hmacHash(key: tempKey, data: output1 + Data([0x02]))
            return [output1, output2]
        }
        let output2 = hmacHash(key: tempKey, data: output1 + Data([0x02]))
        let output3 = hmacHash(key: tempKey, data: output2 + Data([0x03]))
        return [output1, output2, output3]
    }
}

// Noise spec: 4 bytes zeros + 8 bytes little-endian nonce = 12 bytes
private func nonceToBytes(_ nonce: UInt64) -> Data {
    var bytes = Data(count: 12)
    var n = nonce
    for i in 4..<12 {
        bytes[i] = UInt8(n & 0xFF)
        n >>= 8
    }
    return bytes
}

/// Curve25519 Diffie-Hellman key agreement using Apple CryptoKit.
///
/// Implements the `25519` DH function from the Noise Protocol specification.
/// Public keys and shared secrets are 32 bytes.
public struct Curve25519DH: DH {
    /// The DH output length: 32 bytes.
    public let dhLen = 32

    /// Creates a new Curve25519 DH function instance.
    public init() {}

    /// Generates a new random Curve25519 key pair.
    ///
    /// - Returns: A ``KeyPair`` with 32-byte private and public keys.
    public func generateKeyPair() -> KeyPair {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        return KeyPair(
            privateKey: privateKey.rawRepresentation,
            publicKey: privateKey.publicKey.rawRepresentation
        )
    }

    /// Derives the public key from a raw private key.
    ///
    /// - Parameter privateKey: The 32-byte raw private key.
    /// - Returns: The corresponding 32-byte public key.
    public func generatePublicKey(privateKey: Data) -> Data {
        let signingKey = try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
        return Data(signingKey.publicKey.rawRepresentation)
    }

    /// Performs a Curve25519 Diffie-Hellman key agreement.
    ///
    /// - Parameters:
    ///   - keyPair: The local key pair.
    ///   - publicKey: The remote party's 32-byte public key.
    /// - Returns: The 32-byte shared secret.
    /// - Throws: An error if either key is invalid.
    public func dh(keyPair: KeyPair, publicKey: Data) throws -> Data {
        let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: keyPair.privateKey)
        let pubKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey)
        let shared = try privateKey.sharedSecretFromKeyAgreement(with: pubKey)
        return shared.withUnsafeBytes { Data($0) }
    }
}

/// X448 Diffie-Hellman key agreement using a pure-Swift implementation.
///
/// Implements the `448` DH function from the Noise Protocol specification (RFC 7748).
/// Public keys and shared secrets are 56 bytes.
///
/// > Note: The trailing underscore in `X448DH_` avoids a name collision with
/// > potential platform types. This is a convention used throughout this library
/// > for types that shadow CryptoKit or system names.
public struct X448DH_: DH {
    /// The DH output length: 56 bytes.
    public let dhLen = 56

    /// Creates a new X448 DH function instance.
    public init() {}

    /// Generates a new random X448 key pair.
    ///
    /// - Returns: A ``KeyPair`` with 56-byte private and public keys.
    public func generateKeyPair() -> KeyPair {
        var privateKey = Data(count: 56)
        _ = privateKey.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 56, $0.baseAddress!) }
        var basePoint = Data(count: 56)
        basePoint[0] = 5
        let publicKey = X448_.scalarMult(k: privateKey, u: basePoint)
        return KeyPair(privateKey: privateKey, publicKey: publicKey)
    }

    /// Performs an X448 Diffie-Hellman key agreement.
    ///
    /// - Parameters:
    ///   - keyPair: The local key pair.
    ///   - publicKey: The remote party's 56-byte public key.
    /// - Returns: The 56-byte shared secret.
    /// - Throws: An error if the keys are invalid.
    public func dh(keyPair: KeyPair, publicKey: Data) throws -> Data {
        return X448_.scalarMult(k: keyPair.privateKey, u: publicKey)
    }
}

/// ChaCha20-Poly1305 AEAD cipher using Apple CryptoKit.
///
/// Implements the `ChaChaPoly` cipher function from the Noise Protocol specification.
///
/// > Note: The trailing underscore in `ChaChaPoly_` avoids a name collision with
/// > `CryptoKit.ChaChaPoly`.
public struct ChaChaPoly_: CipherFunction {
    /// Creates a new ChaChaPoly cipher instance.
    public init() {}

    /// Encrypts plaintext using ChaCha20-Poly1305.
    ///
    /// - Parameters:
    ///   - key: The 32-byte encryption key.
    ///   - nonce: The 64-bit nonce (padded to 12 bytes per Noise spec: 4 zero bytes + 8 LE bytes).
    ///   - ad: Associated data to authenticate.
    ///   - plaintext: The data to encrypt.
    /// - Returns: Ciphertext concatenated with the 16-byte Poly1305 tag.
    /// - Throws: A CryptoKit error if encryption fails.
    public func encrypt(key: Data, nonce: UInt64, ad: Data, plaintext: Data) throws -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let cryptoNonce = try ChaChaPoly.Nonce(data: nonceToBytes(nonce))
        let sealed = try ChaChaPoly.seal(plaintext, using: symmetricKey, nonce: cryptoNonce, authenticating: ad)
        return sealed.ciphertext + sealed.tag
    }

    /// Decrypts ciphertext using ChaCha20-Poly1305.
    ///
    /// - Parameters:
    ///   - key: The 32-byte encryption key.
    ///   - nonce: The 64-bit nonce used during encryption.
    ///   - ad: The associated data used during encryption.
    ///   - ciphertext: The ciphertext with appended 16-byte Poly1305 tag.
    /// - Returns: The decrypted plaintext.
    /// - Throws: A CryptoKit error if decryption or authentication fails.
    public func decrypt(key: Data, nonce: UInt64, ad: Data, ciphertext: Data) throws -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let cryptoNonce = try ChaChaPoly.Nonce(data: nonceToBytes(nonce))
        let tagStart = ciphertext.count - 16
        let ct = Data(ciphertext.prefix(tagStart))
        let tag = Data(ciphertext.suffix(16))
        let sealedBox = try ChaChaPoly.SealedBox(nonce: cryptoNonce, ciphertext: ct, tag: tag)
        return try ChaChaPoly.open(sealedBox, using: symmetricKey, authenticating: ad)
    }
}

/// AES-256-GCM AEAD cipher using Apple CryptoKit.
///
/// Implements the `AESGCM` cipher function from the Noise Protocol specification.
///
/// > Note: The trailing underscore in `AESGCM_` avoids a name collision with
/// > `CryptoKit.AES.GCM`.
public struct AESGCM_: CipherFunction {
    /// Creates a new AES-GCM cipher instance.
    public init() {}

    /// Encrypts plaintext using AES-256-GCM.
    ///
    /// - Parameters:
    ///   - key: The 32-byte encryption key.
    ///   - nonce: The 64-bit nonce (padded to 12 bytes per Noise spec).
    ///   - ad: Associated data to authenticate.
    ///   - plaintext: The data to encrypt.
    /// - Returns: Ciphertext concatenated with the 16-byte GCM tag.
    /// - Throws: A CryptoKit error if encryption fails.
    public func encrypt(key: Data, nonce: UInt64, ad: Data, plaintext: Data) throws -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let cryptoNonce = try AES.GCM.Nonce(data: nonceToBytes(nonce))
        let sealed = try AES.GCM.seal(plaintext, using: symmetricKey, nonce: cryptoNonce, authenticating: ad)
        return sealed.ciphertext + sealed.tag
    }

    /// Decrypts ciphertext using AES-256-GCM.
    ///
    /// - Parameters:
    ///   - key: The 32-byte encryption key.
    ///   - nonce: The 64-bit nonce used during encryption.
    ///   - ad: The associated data used during encryption.
    ///   - ciphertext: The ciphertext with appended 16-byte GCM tag.
    /// - Returns: The decrypted plaintext.
    /// - Throws: A CryptoKit error if decryption or authentication fails.
    public func decrypt(key: Data, nonce: UInt64, ad: Data, ciphertext: Data) throws -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let cryptoNonce = try AES.GCM.Nonce(data: nonceToBytes(nonce))
        let tagStart = ciphertext.count - 16
        let ct = Data(ciphertext.prefix(tagStart))
        let tag = Data(ciphertext.suffix(16))
        let sealedBox = try AES.GCM.SealedBox(nonce: cryptoNonce, ciphertext: ct, tag: tag)
        return try AES.GCM.open(sealedBox, using: symmetricKey, authenticating: ad)
    }
}

/// SHA-256 hash function using Apple CryptoKit.
///
/// Implements the `SHA256` hash function from the Noise Protocol specification.
/// Produces 32-byte digests with a 64-byte block size.
///
/// > Note: The trailing underscore in `SHA256Hash_` avoids a name collision with
/// > `CryptoKit.SHA256`.
public struct SHA256Hash_: HashFunction {
    /// The hash output length: 32 bytes.
    public let hashLen = 32
    /// The internal block length: 64 bytes.
    public let blockLen = 64

    /// Creates a new SHA-256 hash function instance.
    public init() {}

    /// Computes the SHA-256 hash of the given data.
    ///
    /// - Parameter data: The input data to hash.
    /// - Returns: A 32-byte hash digest.
    public func hash(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    /// Computes HMAC-SHA256 using Apple CryptoKit for optimal performance.
    ///
    /// - Parameters:
    ///   - key: The HMAC key.
    ///   - data: The data to authenticate.
    /// - Returns: A 32-byte authentication code.
    public func hmacHash(key: Data, data: Data) -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let mac = HMAC<SHA256>.authenticationCode(for: data, using: symmetricKey)
        return Data(mac)
    }
}

/// SHA-512 hash function using Apple CryptoKit.
///
/// Implements the `SHA512` hash function from the Noise Protocol specification.
/// Produces 64-byte digests with a 128-byte block size.
///
/// > Note: The trailing underscore in `SHA512Hash_` avoids a name collision with
/// > `CryptoKit.SHA512`.
public struct SHA512Hash_: HashFunction {
    /// The hash output length: 64 bytes.
    public let hashLen = 64
    /// The internal block length: 128 bytes.
    public let blockLen = 128

    /// Creates a new SHA-512 hash function instance.
    public init() {}

    /// Computes the SHA-512 hash of the given data.
    ///
    /// - Parameter data: The input data to hash.
    /// - Returns: A 64-byte hash digest.
    public func hash(_ data: Data) -> Data {
        Data(SHA512.hash(data: data))
    }

    /// Computes HMAC-SHA512 using Apple CryptoKit for optimal performance.
    ///
    /// - Parameters:
    ///   - key: The HMAC key.
    ///   - data: The data to authenticate.
    /// - Returns: A 64-byte authentication code.
    public func hmacHash(key: Data, data: Data) -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let mac = HMAC<SHA512>.authenticationCode(for: data, using: symmetricKey)
        return Data(mac)
    }
}

/// BLAKE2b hash function with a pure-Swift implementation.
///
/// Implements the `BLAKE2b` hash function from the Noise Protocol specification (RFC 7693).
/// Produces 64-byte digests with a 128-byte block size. Uses 12 rounds of the BLAKE2b
/// compression function with the standard IV and sigma permutation tables.
///
/// > Note: The trailing underscore in `Blake2bHash_` avoids potential name collisions
/// > with third-party BLAKE2 implementations.
public struct Blake2bHash_: HashFunction {
    /// The hash output length: 64 bytes.
    public let hashLen = 64
    /// The internal block length: 128 bytes.
    public let blockLen = 128

    /// Creates a new BLAKE2b hash function instance.
    public init() {}

    private static let iv: [UInt64] = [
        0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
        0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
    ]

    private static let sigma: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3]
    ]

    /// Computes the BLAKE2b hash of the given data.
    ///
    /// - Parameter data: The input data to hash.
    /// - Returns: A 64-byte hash digest.
    public func hash(_ data: Data) -> Data {
        var h = Self.iv
        h[0] ^= 0x01010000 ^ 64 // parameter block: depth=1, fanout=1, nn=64

        let dd = data.isEmpty ? 1 : (data.count + blockLen - 1) / blockLen
        var padded = Data(count: dd * blockLen)
        padded.replaceSubrange(0..<data.count, with: data)

        for i in 0..<dd {
            let block = getWordsLE64(padded, offset: i * blockLen, count: 16)
            let t: UInt64 = i < dd - 1 ? UInt64((i + 1) * blockLen) : UInt64(data.count)
            let last = i == dd - 1
            compress(&h, m: block, t: t, last: last)
        }

        return wordsToLE64(h)
    }

    private func compress(_ h: inout [UInt64], m: [UInt64], t: UInt64, last: Bool) {
        var v = [UInt64](repeating: 0, count: 16)
        for i in 0...7 { v[i] = h[i]; v[i + 8] = Self.iv[i] }
        v[12] ^= t
        if last { v[14] ^= UInt64.max }

        for i in 0...11 {
            let s = Self.sigma[i]
            g(&v, 0, 4, 8, 12, m[s[0]], m[s[1]])
            g(&v, 1, 5, 9, 13, m[s[2]], m[s[3]])
            g(&v, 2, 6, 10, 14, m[s[4]], m[s[5]])
            g(&v, 3, 7, 11, 15, m[s[6]], m[s[7]])
            g(&v, 0, 5, 10, 15, m[s[8]], m[s[9]])
            g(&v, 1, 6, 11, 12, m[s[10]], m[s[11]])
            g(&v, 2, 7, 8, 13, m[s[12]], m[s[13]])
            g(&v, 3, 4, 9, 14, m[s[14]], m[s[15]])
        }

        for i in 0...7 { h[i] ^= v[i] ^ v[i + 8] }
    }

    private func g(_ v: inout [UInt64], _ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt64, _ y: UInt64) {
        v[a] = v[a] &+ v[b] &+ x
        v[d] = (v[d] ^ v[a]).rotateRight(32)
        v[c] = v[c] &+ v[d]
        v[b] = (v[b] ^ v[c]).rotateRight(24)
        v[a] = v[a] &+ v[b] &+ y
        v[d] = (v[d] ^ v[a]).rotateRight(16)
        v[c] = v[c] &+ v[d]
        v[b] = (v[b] ^ v[c]).rotateRight(63)
    }

    private func getWordsLE64(_ data: Data, offset: Int, count: Int) -> [UInt64] {
        var words = [UInt64](repeating: 0, count: count)
        for i in 0..<count {
            var w: UInt64 = 0
            for j in 0...7 { w |= UInt64(data[data.startIndex + offset + i * 8 + j]) << (j * 8) }
            words[i] = w
        }
        return words
    }

    private func wordsToLE64(_ words: [UInt64]) -> Data {
        var bytes = Data(count: words.count * 8)
        for i in words.indices {
            for j in 0...7 { bytes[i * 8 + j] = UInt8(truncatingIfNeeded: words[i] >> (j * 8)) }
        }
        return bytes
    }
}

/// BLAKE2s hash function with a pure-Swift implementation.
///
/// Implements the `BLAKE2s` hash function from the Noise Protocol specification (RFC 7693).
/// Produces 32-byte digests with a 64-byte block size. Uses 10 rounds of the BLAKE2s
/// compression function with 32-bit words.
///
/// > Note: The trailing underscore in `Blake2sHash_` avoids potential name collisions
/// > with third-party BLAKE2 implementations.
public struct Blake2sHash_: HashFunction {
    /// The hash output length: 32 bytes.
    public let hashLen = 32
    /// The internal block length: 64 bytes.
    public let blockLen = 64

    /// Creates a new BLAKE2s hash function instance.
    public init() {}

    private static let iv: [UInt32] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    ]

    private static let sigma: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]
    ]

    /// Computes the BLAKE2s hash of the given data.
    ///
    /// - Parameter data: The input data to hash.
    /// - Returns: A 32-byte hash digest.
    public func hash(_ data: Data) -> Data {
        var h = Self.iv
        h[0] ^= 0x01010000 ^ 32

        let dd = data.isEmpty ? 1 : (data.count + blockLen - 1) / blockLen
        var padded = Data(count: dd * blockLen)
        padded.replaceSubrange(0..<data.count, with: data)

        for i in 0..<dd {
            let block = getWordsLE32(padded, offset: i * blockLen, count: 16)
            let t: UInt32 = i < dd - 1 ? UInt32((i + 1) * blockLen) : UInt32(data.count)
            let last = i == dd - 1
            compress(&h, m: block, t: t, last: last)
        }

        return wordsToLE32(h)
    }

    private func compress(_ h: inout [UInt32], m: [UInt32], t: UInt32, last: Bool) {
        var v = [UInt32](repeating: 0, count: 16)
        for i in 0...7 { v[i] = h[i]; v[i + 8] = Self.iv[i] }
        v[12] ^= t
        if last { v[14] ^= UInt32.max }

        for i in 0...9 {
            let s = Self.sigma[i]
            g(&v, 0, 4, 8, 12, m[s[0]], m[s[1]])
            g(&v, 1, 5, 9, 13, m[s[2]], m[s[3]])
            g(&v, 2, 6, 10, 14, m[s[4]], m[s[5]])
            g(&v, 3, 7, 11, 15, m[s[6]], m[s[7]])
            g(&v, 0, 5, 10, 15, m[s[8]], m[s[9]])
            g(&v, 1, 6, 11, 12, m[s[10]], m[s[11]])
            g(&v, 2, 7, 8, 13, m[s[12]], m[s[13]])
            g(&v, 3, 4, 9, 14, m[s[14]], m[s[15]])
        }

        for i in 0...7 { h[i] ^= v[i] ^ v[i + 8] }
    }

    private func g(_ v: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt32, _ y: UInt32) {
        v[a] = v[a] &+ v[b] &+ x
        v[d] = (v[d] ^ v[a]).rotateRight(16)
        v[c] = v[c] &+ v[d]
        v[b] = (v[b] ^ v[c]).rotateRight(12)
        v[a] = v[a] &+ v[b] &+ y
        v[d] = (v[d] ^ v[a]).rotateRight(8)
        v[c] = v[c] &+ v[d]
        v[b] = (v[b] ^ v[c]).rotateRight(7)
    }

    private func getWordsLE32(_ data: Data, offset: Int, count: Int) -> [UInt32] {
        var words = [UInt32](repeating: 0, count: count)
        for i in 0..<count {
            var w: UInt32 = 0
            for j in 0...3 { w |= UInt32(data[data.startIndex + offset + i * 4 + j]) << (j * 8) }
            words[i] = w
        }
        return words
    }

    private func wordsToLE32(_ words: [UInt32]) -> Data {
        var bytes = Data(count: words.count * 4)
        for i in words.indices {
            for j in 0...3 { bytes[i * 4 + j] = UInt8(truncatingIfNeeded: words[i] >> (j * 8)) }
        }
        return bytes
    }
}

private extension UInt64 {
    func rotateRight(_ n: Int) -> UInt64 { (self >> n) | (self << (64 - n)) }
}

private extension UInt32 {
    func rotateRight(_ n: Int) -> UInt32 { (self >> n) | (self << (32 - n)) }
}
