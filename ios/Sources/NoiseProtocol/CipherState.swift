import Foundation

public class CipherState {
    private let cipher: CipherFunction
    private var k: Data?
    private var n: UInt64 = 0

    init(cipher: CipherFunction, key: Data? = nil) {
        self.cipher = cipher
        self.k = key.map { Data($0) }
    }

    public func hasKey() -> Bool { k != nil }

    func setKey(_ key: Data) {
        self.k = Data(key)
        self.n = 0
    }

    public func encryptWithAd(_ ad: Data, plaintext: Data) throws -> Data {
        guard let key = k else { return plaintext }
        let ciphertext = try cipher.encrypt(key: key, nonce: n, ad: ad, plaintext: plaintext)
        n += 1
        return ciphertext
    }

    public func decryptWithAd(_ ad: Data, ciphertext: Data) throws -> Data {
        guard let key = k else { return ciphertext }
        let plaintext: Data
        do {
            plaintext = try cipher.decrypt(key: key, nonce: n, ad: ad, ciphertext: ciphertext)
        } catch {
            throw NoiseError.decryptionFailed
        }
        n += 1
        return plaintext
    }
}
