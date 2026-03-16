import Foundation
import CryptoKit

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
    func hkdf(chainingKey: Data, inputKeyMaterial: Data, numOutputs: Int) -> [Data]
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

public struct ChaChaPoly_: CipherFunction {
    public init() {}

    public func encrypt(key: Data, nonce: UInt64, ad: Data, plaintext: Data) throws -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let nonceBytes = nonceToBytes(nonce)
        let cryptoNonce = try ChaChaPoly.Nonce(data: nonceBytes)
        let sealed = try ChaChaPoly.seal(plaintext, using: symmetricKey, nonce: cryptoNonce, authenticating: ad)
        return sealed.ciphertext + sealed.tag
    }

    public func decrypt(key: Data, nonce: UInt64, ad: Data, ciphertext: Data) throws -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let nonceBytes = nonceToBytes(nonce)
        let cryptoNonce = try ChaChaPoly.Nonce(data: nonceBytes)
        let tagStart = ciphertext.count - 16
        let ct = ciphertext.prefix(tagStart)
        let tag = ciphertext.suffix(16)
        let sealedBox = try ChaChaPoly.SealedBox(nonce: cryptoNonce, ciphertext: ct, tag: tag)
        return try ChaChaPoly.open(sealedBox, using: symmetricKey, authenticating: ad)
    }

    private func nonceToBytes(_ nonce: UInt64) -> Data {
        // Noise spec: 4 bytes zeros + 8 bytes little-endian nonce = 12 bytes
        var bytes = Data(count: 12)
        var n = nonce
        for i in 4..<12 {
            bytes[i] = UInt8(n & 0xFF)
            n >>= 8
        }
        return bytes
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
