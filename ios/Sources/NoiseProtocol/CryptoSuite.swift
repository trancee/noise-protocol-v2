import Foundation

/// Groups the three resolved cryptographic primitives needed by a Noise handshake.
public struct CryptoSuite {
    public let dh: DH
    public let cipher: CipherFunction
    public let hash: HashFunction
}
