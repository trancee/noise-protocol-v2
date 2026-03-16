import Foundation

public class NoiseSession {
    private let handshakeState: HandshakeState
    private let role: Role

    public var isHandshakeComplete: Bool { handshakeState.isHandshakeComplete }

    public init(protocolName: String, role: Role,
                staticKeyPair: KeyPair? = nil,
                remoteStaticKey: Data? = nil,
                prologue: Data = Data(),
                localEphemeral: KeyPair? = nil) throws {
        self.role = role
        self.handshakeState = HandshakeState(
            protocolName: protocolName,
            role: role,
            dh: Curve25519DH(),
            cipher: ChaChaPoly_(),
            hash: SHA256Hash_(),
            staticKeyPair: staticKeyPair,
            remoteStaticKey: remoteStaticKey,
            prologue: prologue,
            localEphemeral: localEphemeral
        )
    }

    @discardableResult
    public func writeMessage(_ payload: Data = Data()) throws -> Data {
        guard !isHandshakeComplete else { throw NoiseError.handshakeAlreadyComplete }
        return try handshakeState.writeMessage(payload: payload)
    }

    @discardableResult
    public func readMessage(_ message: Data) throws -> Data {
        guard !isHandshakeComplete else { throw NoiseError.handshakeAlreadyComplete }
        return try handshakeState.readMessage(message)
    }

    public func split() throws -> TransportSession {
        let (c1, c2) = try handshakeState.split()
        return role == .initiator
            ? TransportSession(sender: c1, receiver: c2)
            : TransportSession(sender: c2, receiver: c1)
    }
}

public struct TransportSession {
    public let sender: CipherState
    public let receiver: CipherState
}
