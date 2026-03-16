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

        let descriptor = try PatternParser.parse(protocolName)

        self.handshakeState = HandshakeState(
            protocolName: protocolName,
            role: role,
            dh: Self.resolveDH(descriptor.dhFunction),
            cipher: Self.resolveCipher(descriptor.cipherFunction),
            hash: Self.resolveHash(descriptor.hashFunction),
            descriptor: descriptor,
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

    static func resolveDH(_ name: String) -> DH {
        switch name {
        case "25519": return Curve25519DH()
        default: fatalError("Unsupported DH: \(name)")
        }
    }

    static func resolveCipher(_ name: String) -> CipherFunction {
        switch name {
        case "ChaChaPoly": return ChaChaPoly_()
        default: fatalError("Unsupported cipher: \(name)")
        }
    }

    static func resolveHash(_ name: String) -> HashFunction {
        switch name {
        case "SHA256": return SHA256Hash_()
        default: fatalError("Unsupported hash: \(name)")
        }
    }
}

public struct TransportSession {
    public let sender: CipherState
    public let receiver: CipherState
}
