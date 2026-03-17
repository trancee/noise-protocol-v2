import Foundation

/// Immutable configuration for a HandshakeState session.
public struct HandshakeConfig {
    public let protocolName: String
    public let role: Role
    public let dh: DH
    public let cipher: CipherFunction
    public let hash: HashFunction
    public let descriptor: HandshakeDescriptor
    public var staticKeyPair: KeyPair? = nil
    public var remoteStaticKey: Data? = nil
    public var prologue: Data = Data()
    public var localEphemeral: KeyPair? = nil
    public var remoteEphemeral: Data? = nil
    public var psks: [Data] = []

    public init(protocolName: String, role: Role, dh: DH, cipher: CipherFunction,
                hash: HashFunction, descriptor: HandshakeDescriptor,
                staticKeyPair: KeyPair? = nil, remoteStaticKey: Data? = nil,
                prologue: Data = Data(), localEphemeral: KeyPair? = nil,
                remoteEphemeral: Data? = nil, psks: [Data] = []) {
        self.protocolName = protocolName
        self.role = role
        self.dh = dh
        self.cipher = cipher
        self.hash = hash
        self.descriptor = descriptor
        self.staticKeyPair = staticKeyPair
        self.remoteStaticKey = remoteStaticKey
        self.prologue = prologue
        self.localEphemeral = localEphemeral
        self.remoteEphemeral = remoteEphemeral
        self.psks = psks
    }
}
