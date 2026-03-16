import Foundation

public enum NoiseError: Error, Sendable {
    case handshakeNotComplete
    case handshakeAlreadyComplete
    case decryptionFailed
    case invalidKey
    case invalidPattern
}
