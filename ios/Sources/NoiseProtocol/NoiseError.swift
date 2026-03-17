import Foundation

/// Errors that can occur during Noise Protocol operations.
///
/// These errors cover the full lifecycle of a Noise session, from handshake setup
/// through transport-phase encryption and decryption.
public enum NoiseError: Error, Sendable, Equatable {
    /// The handshake has not yet completed; transport operations are not available.
    case handshakeNotComplete
    /// The handshake has already completed; no further handshake messages can be sent or received.
    case handshakeAlreadyComplete
    /// AEAD decryption failed, indicating corrupted or tampered ciphertext.
    case decryptionFailed
    /// A required key is missing or invalid. The associated value describes which key.
    case invalidKey(String)
    /// The protocol name string could not be parsed or references an unsupported algorithm.
    case invalidPattern(String)
    /// The session is in an unexpected state for the requested operation.
    case invalidState(String)
    /// The nonce counter has reached its maximum value (`UInt64.max`), preventing further encryption.
    case nonceExhausted
    /// The session has been permanently invalidated (e.g., after a decryption failure).
    case sessionInvalidated
}
