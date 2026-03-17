import Foundation
import CryptoKit
import Security

public protocol DH: Sendable {
    var dhLen: Int { get }
    func generateKeyPair() -> KeyPair
    func dh(keyPair: KeyPair, publicKey: Data) throws -> Data
}

public protocol CipherFunction: Sendable {
    func encrypt(key: Data, nonce: UInt64, ad: Data, plaintext: Data) throws -> Data
    func decrypt(key: Data, nonce: UInt64, ad: Data, ciphertext: Data) throws -> Data
}

public protocol HashFunction: Sendable {
    var hashLen: Int { get }
    var blockLen: Int { get }
    func hash(_ data: Data) -> Data
    func hmacHash(key: Data, data: Data) -> Data
}

extension HashFunction {
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

public struct Curve25519DH: DH {
    public let dhLen = 32

    public init() {}

    public func generateKeyPair() -> KeyPair {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        return KeyPair(
            privateKey: privateKey.rawRepresentation,
            publicKey: privateKey.publicKey.rawRepresentation
        )
    }

    public func dh(keyPair: KeyPair, publicKey: Data) throws -> Data {
        let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: keyPair.privateKey)
        let pubKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey)
        let shared = try privateKey.sharedSecretFromKeyAgreement(with: pubKey)
        return shared.withUnsafeBytes { Data($0) }
    }
}

public struct X448DH_: DH {
    public let dhLen = 56

    public init() {}

    public func generateKeyPair() -> KeyPair {
        var privateKey = Data(count: 56)
        _ = privateKey.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 56, $0.baseAddress!) }
        var basePoint = Data(count: 56)
        basePoint[0] = 5
        let publicKey = X448_.scalarMult(k: privateKey, u: basePoint)
        return KeyPair(privateKey: privateKey, publicKey: publicKey)
    }

    public func dh(keyPair: KeyPair, publicKey: Data) throws -> Data {
        return X448_.scalarMult(k: keyPair.privateKey, u: publicKey)
    }
}

public struct ChaChaPoly_: CipherFunction {
    public init() {}

    public func encrypt(key: Data, nonce: UInt64, ad: Data, plaintext: Data) throws -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let cryptoNonce = try ChaChaPoly.Nonce(data: nonceToBytes(nonce))
        let sealed = try ChaChaPoly.seal(plaintext, using: symmetricKey, nonce: cryptoNonce, authenticating: ad)
        return sealed.ciphertext + sealed.tag
    }

    public func decrypt(key: Data, nonce: UInt64, ad: Data, ciphertext: Data) throws -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let cryptoNonce = try ChaChaPoly.Nonce(data: nonceToBytes(nonce))
        let tagStart = ciphertext.count - 16
        let ct = ciphertext.prefix(tagStart)
        let tag = ciphertext.suffix(16)
        let sealedBox = try ChaChaPoly.SealedBox(nonce: cryptoNonce, ciphertext: ct, tag: tag)
        return try ChaChaPoly.open(sealedBox, using: symmetricKey, authenticating: ad)
    }
}

public struct AESGCM_: CipherFunction {
    public init() {}

    public func encrypt(key: Data, nonce: UInt64, ad: Data, plaintext: Data) throws -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let cryptoNonce = try AES.GCM.Nonce(data: nonceToBytes(nonce))
        let sealed = try AES.GCM.seal(plaintext, using: symmetricKey, nonce: cryptoNonce, authenticating: ad)
        return sealed.ciphertext + sealed.tag
    }

    public func decrypt(key: Data, nonce: UInt64, ad: Data, ciphertext: Data) throws -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let cryptoNonce = try AES.GCM.Nonce(data: nonceToBytes(nonce))
        let tagStart = ciphertext.count - 16
        let ct = ciphertext.prefix(tagStart)
        let tag = ciphertext.suffix(16)
        let sealedBox = try AES.GCM.SealedBox(nonce: cryptoNonce, ciphertext: ct, tag: tag)
        return try AES.GCM.open(sealedBox, using: symmetricKey, authenticating: ad)
    }
}

public struct SHA256Hash_: HashFunction {
    public let hashLen = 32
    public let blockLen = 64

    public init() {}

    public func hash(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    public func hmacHash(key: Data, data: Data) -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let mac = HMAC<SHA256>.authenticationCode(for: data, using: symmetricKey)
        return Data(mac)
    }
}

public struct SHA512Hash_: HashFunction {
    public let hashLen = 64
    public let blockLen = 128

    public init() {}

    public func hash(_ data: Data) -> Data {
        Data(SHA512.hash(data: data))
    }

    public func hmacHash(key: Data, data: Data) -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let mac = HMAC<SHA512>.authenticationCode(for: data, using: symmetricKey)
        return Data(mac)
    }
}

public struct Blake2bHash_: HashFunction {
    public let hashLen = 64
    public let blockLen = 128

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

public struct Blake2sHash_: HashFunction {
    public let hashLen = 32
    public let blockLen = 64

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
