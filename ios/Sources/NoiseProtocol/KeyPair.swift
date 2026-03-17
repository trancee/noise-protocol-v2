import Foundation

/// A cryptographic key pair consisting of a private key and its corresponding public key.
///
/// Used throughout the Noise Protocol for Diffie-Hellman operations. The key sizes depend
/// on the DH function in use (e.g., 32 bytes for Curve25519, 56 bytes for X448).
public struct KeyPair: Sendable {
    /// The private (secret) key material. Must be kept confidential.
    public let privateKey: Data
    /// The public key derived from the private key. Safe to share with peers.
    public let publicKey: Data

    /// Creates a new key pair from raw key data.
    ///
    /// - Parameters:
    ///   - privateKey: The raw private key bytes.
    ///   - publicKey: The raw public key bytes corresponding to the private key.
    public init(privateKey: Data, publicKey: Data) {
        self.privateKey = privateKey
        self.publicKey = publicKey
    }
}
