import Foundation

public class NoiseSession {
    private let handshakeState: HandshakeState
    private let role: Role
    private let isOneWay: Bool

    public var isHandshakeComplete: Bool { handshakeState.isHandshakeComplete }

    public init(protocolName: String, role: Role,
                staticKeyPair: KeyPair? = nil,
                remoteStaticKey: Data? = nil,
                prologue: Data = Data(),
                localEphemeral: KeyPair? = nil,
                remoteEphemeral: Data? = nil,
                psks: [Data] = []) throws {
        self.role = role

        let descriptor = try PatternParser.parse(protocolName)
        self.isOneWay = descriptor.messagePatterns.count == 1

        self.handshakeState = try HandshakeState(
            protocolName: protocolName,
            role: role,
            dh: Self.resolveDH(descriptor.dhFunction),
            cipher: Self.resolveCipher(descriptor.cipherFunction),
            hash: Self.resolveHash(descriptor.hashFunction),
            descriptor: descriptor,
            staticKeyPair: staticKeyPair,
            remoteStaticKey: remoteStaticKey,
            prologue: prologue,
            localEphemeral: localEphemeral,
            remoteEphemeral: remoteEphemeral,
            psks: psks
        )
    }

    public func getLocalEphemeralPrivateKey() -> Data? {
        return handshakeState.getLocalEphemeralPrivateKey()
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
        let disabled = DisabledCipherState()
        if role == .initiator {
            return TransportSession(sender: c1, receiver: isOneWay ? disabled : c2)
        } else {
            return TransportSession(sender: isOneWay ? disabled : c2, receiver: c1)
        }
    }

    static func resolveDH(_ name: String) -> DH {
        switch name {
        case "25519": return Curve25519DH()
        case "448": return X448DH_()
        default: fatalError("Unsupported DH: \(name)")
        }
    }

    static func resolveCipher(_ name: String) -> CipherFunction {
        switch name {
        case "ChaChaPoly": return ChaChaPoly_()
        case "AESGCM": return AESGCM_()
        default: fatalError("Unsupported cipher: \(name)")
        }
    }

    static func resolveHash(_ name: String) -> HashFunction {
        switch name {
        case "SHA256": return SHA256Hash_()
        case "SHA512": return SHA512Hash_()
        case "BLAKE2b": return Blake2bHash_()
        case "BLAKE2s": return Blake2sHash_()
        default: fatalError("Unsupported hash: \(name)")
        }
    }
}

public struct TransportSession {
    public let sender: CipherState
    public let receiver: CipherState
}

public class DisabledCipherState: CipherState {
    init() {
        super.init(cipher: ChaChaPoly_())
    }
    public override func encryptWithAd(_ ad: Data, plaintext: Data) throws -> Data {
        throw NoiseError.invalidState("Cannot send on a one-way pattern receive-only channel")
    }
    public override func decryptWithAd(_ ad: Data, ciphertext: Data) throws -> Data {
        throw NoiseError.invalidState("Cannot receive on a one-way pattern send-only channel")
    }
}
