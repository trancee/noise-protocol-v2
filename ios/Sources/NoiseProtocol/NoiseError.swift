import Foundation

public enum NoiseError: Error, Sendable, Equatable {
    case handshakeNotComplete
    case handshakeAlreadyComplete
    case decryptionFailed
    case invalidKey(String)
    case invalidPattern(String)
    case invalidState(String)
    case nonceExhausted
    case sessionInvalidated
}
