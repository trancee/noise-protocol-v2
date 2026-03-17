import Foundation

class SymmetricState {
    private var ck: Data
    private var h: Data
    private let cipher: CipherFunction
    private let hashFn: HashFunction
    private let cipherState: CipherState

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

    func hasKey() -> Bool { cipherState.hasKey() }

    func mixKey(_ inputKeyMaterial: Data) {
        let outputs = hashFn.hkdf(chainingKey: ck, inputKeyMaterial: inputKeyMaterial, numOutputs: 2)
        ck = outputs[0]
        cipherState.setKey(truncateKey(outputs[1]))
    }

    func mixHash(_ data: Data) {
        h = hashFn.hash(h + data)
    }

    func encryptAndHash(_ plaintext: Data) throws -> Data {
        let ciphertext = try cipherState.encryptWithAd(h, plaintext: plaintext)
        mixHash(ciphertext)
        return ciphertext
    }

    func decryptAndHash(_ ciphertext: Data) throws -> Data {
        let plaintext = try cipherState.decryptWithAd(h, ciphertext: ciphertext)
        mixHash(ciphertext)
        return plaintext
    }

    func split() -> (CipherState, CipherState) {
        let outputs = hashFn.hkdf(chainingKey: ck, inputKeyMaterial: Data(), numOutputs: 2)
        let c1 = CipherState(cipher: cipher)
        c1.setKey(truncateKey(outputs[0]))
        let c2 = CipherState(cipher: cipher)
        c2.setKey(truncateKey(outputs[1]))
        return (c1, c2)
    }

    func mixKeyAndHash(_ inputKeyMaterial: Data) {
        let outputs = hashFn.hkdf(chainingKey: ck, inputKeyMaterial: inputKeyMaterial, numOutputs: 3)
        ck = outputs[0]
        mixHash(outputs[1])
        let truncatedK = outputs[2].count > 32 ? Data(outputs[2].prefix(32)) : outputs[2]
        cipherState.setKey(truncatedK)
    }

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
