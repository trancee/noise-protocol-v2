import Foundation

/// The main public API for conducting a Noise Protocol handshake.
///
/// `NoiseSession` parses a Noise protocol name string, resolves the cryptographic primitives,
/// and drives the handshake state machine. After the handshake completes, call ``split()`` to
/// obtain a ``TransportSession`` for encrypted communication.
///
/// ## Usage Example
///
/// ```swift
/// // Initiator side
/// let initiator = try NoiseSession(
///     protocolName: "Noise_XX_25519_ChaChaPoly_SHA256",
///     role: .initiator,
///     staticKeyPair: initiatorKeys
/// )
///
/// // Responder side
/// let responder = try NoiseSession(
///     protocolName: "Noise_XX_25519_ChaChaPoly_SHA256",
///     role: .responder,
///     staticKeyPair: responderKeys
/// )
///
/// // Perform handshake (XX pattern has 3 messages)
/// let msg1 = try initiator.writeMessage()
/// let _ = try responder.readMessage(msg1)
/// let msg2 = try responder.writeMessage()
/// let _ = try initiator.readMessage(msg2)
/// let msg3 = try initiator.writeMessage()
/// let _ = try responder.readMessage(msg3)
///
/// // Split into transport sessions
/// let iTransport = try initiator.split()
/// let rTransport = try responder.split()
///
/// // Encrypt and decrypt application data
/// let ciphertext = try iTransport.sender.encryptWithAd(Data(), plaintext: message)
/// let plaintext = try rTransport.receiver.decryptWithAd(Data(), ciphertext: ciphertext)
/// ```
///
/// ## Supported Algorithms
///
/// - **DH**: `25519` (Curve25519), `448` (X448)
/// - **Cipher**: `ChaChaPoly` (ChaCha20-Poly1305), `AESGCM` (AES-256-GCM)
/// - **Hash**: `SHA256`, `SHA512`, `BLAKE2b`, `BLAKE2s`
public class NoiseSession {
    private let handshakeState: HandshakeState
    private let role: Role
    private let isOneWay: Bool

    /// Whether the handshake phase has completed. Once `true`, call ``split()`` to get transport cipher states.
    public var isHandshakeComplete: Bool { handshakeState.isHandshakeComplete }

    /// Creates a new Noise Protocol session.
    ///
    /// Parses the protocol name to determine the handshake pattern, DH function, cipher,
    /// and hash, then initializes the internal handshake state machine.
    ///
    /// - Parameters:
    ///   - protocolName: The full Noise protocol name (e.g., `"Noise_XX_25519_ChaChaPoly_SHA256"`).
    ///   - role: Whether this party is the ``Role/initiator`` or ``Role/responder``.
    ///   - staticKeyPair: The local static key pair, if required by the pattern.
    ///   - remoteStaticKey: The remote party's static public key, if known in advance.
    ///   - prologue: Application-specific prologue data bound into the handshake hash (default: empty).
    ///   - localEphemeral: A fixed local ephemeral key pair (primarily for testing).
    ///   - remoteEphemeral: The remote ephemeral public key, if known from a pre-message.
    ///   - psks: Pre-shared keys for PSK handshake patterns.
    ///   - crypto: A ``CryptoResolver`` used to look up DH, cipher, and hash implementations
    ///     by name. Defaults to ``DefaultCryptoResolver/default`` which supports all standard algorithms.
    /// - Throws: ``NoiseError/invalidPattern(_:)`` if the protocol name is malformed,
    ///   ``NoiseError/invalidKey(_:)`` if required keys are missing.
    public init(protocolName: String, role: Role,
                staticKeyPair: KeyPair? = nil,
                remoteStaticKey: Data? = nil,
                prologue: Data = Data(),
                localEphemeral: KeyPair? = nil,
                remoteEphemeral: Data? = nil,
                psks: [Data] = [],
                crypto: CryptoResolver = DefaultCryptoResolver.default) throws {
        self.role = role

        let descriptor = try PatternParser.parse(protocolName)
        self.isOneWay = descriptor.messagePatterns.count == 1

        let suite = try crypto.resolve(
            dhName: descriptor.dhFunction,
            cipherName: descriptor.cipherFunction,
            hashName: descriptor.hashFunction
        )

        self.handshakeState = try HandshakeState(
            protocolName: protocolName,
            role: role,
            dh: suite.dh,
            cipher: suite.cipher,
            hash: suite.hash,
            descriptor: descriptor,
            staticKeyPair: staticKeyPair,
            remoteStaticKey: remoteStaticKey,
            prologue: prologue,
            localEphemeral: localEphemeral,
            remoteEphemeral: remoteEphemeral,
            psks: psks
        )
    }

    /// Returns the local ephemeral private key, if one has been generated during the handshake.
    ///
    /// - Returns: The ephemeral private key data, or `nil` if not yet generated.
    public func getLocalEphemeralPrivateKey() -> Data? {
        return handshakeState.getLocalEphemeralPrivateKey()
    }

    /// Returns the current chaining key from the handshake state.
    ///
    /// - Returns: The chaining key data, useful for deriving additional keys.
    public func getChainingKey() -> Data? {
        return handshakeState.getChainingKey()
    }

    /// Constructs and sends the next handshake message, optionally including a payload.
    ///
    /// Must be called only during the handshake phase. The handshake pattern determines
    /// which party sends each message.
    ///
    /// - Parameter payload: Optional application data to include in the handshake message (default: empty).
    /// - Returns: The serialized handshake message to send to the peer.
    /// - Throws: ``NoiseError/handshakeAlreadyComplete`` if the handshake is already done.
    @discardableResult
    public func writeMessage(_ payload: Data = Data()) throws -> Data {
        guard !isHandshakeComplete else { throw NoiseError.handshakeAlreadyComplete }
        return try handshakeState.writeMessage(payload: payload)
    }

    /// Processes a received handshake message and extracts its payload.
    ///
    /// Must be called only during the handshake phase.
    ///
    /// - Parameter message: The raw handshake message bytes received from the peer.
    /// - Returns: The decrypted payload contained in the message.
    /// - Throws: ``NoiseError/handshakeAlreadyComplete`` if the handshake is already done,
    ///   ``NoiseError/decryptionFailed`` if message authentication fails.
    @discardableResult
    public func readMessage(_ message: Data) throws -> Data {
        guard !isHandshakeComplete else { throw NoiseError.handshakeAlreadyComplete }
        return try handshakeState.readMessage(message)
    }

    /// Splits the completed handshake into a transport session for encrypted communication.
    ///
    /// Returns a ``TransportSession`` with separate sender and receiver ``CipherState`` instances.
    /// For one-way patterns, the unused direction uses a ``DisabledCipherState`` that throws on use.
    ///
    /// - Returns: A ``TransportSession`` ready for application data encryption/decryption.
    /// - Throws: ``NoiseError/handshakeNotComplete`` if the handshake has not finished.
    public func split() throws -> TransportSession {
        let (c1, c2) = try handshakeState.split()
        let disabled = DisabledCipherState()
        if role == .initiator {
            return TransportSession(sender: c1, receiver: isOneWay ? disabled : c2)
        } else {
            return TransportSession(sender: isOneWay ? disabled : c2, receiver: c1)
        }
    }

}

/// Holds the two cipher states for post-handshake encrypted communication.
///
/// After a successful handshake, `sender` is used to encrypt outgoing messages and
/// `receiver` is used to decrypt incoming messages. For one-way patterns, one of these
/// will be a ``DisabledCipherState`` that throws on use.
public struct TransportSession {
    /// The cipher state for encrypting outgoing messages.
    public let sender: CipherState
    /// The cipher state for decrypting incoming messages.
    public let receiver: CipherState
}

/// A cipher state that always throws, used for the disabled direction in one-way patterns.
///
/// In one-way Noise patterns (N, K, X), only the initiator sends encrypted data.
/// The responder's send channel and the initiator's receive channel are disabled
/// using this subclass, which throws ``NoiseError/invalidState(_:)`` on any operation.
public class DisabledCipherState: CipherState {
    /// Creates a disabled cipher state. No key is set; all operations will throw.
    init() {
        super.init(cipher: ChaChaPoly_())
    }
    /// Always throws ``NoiseError/invalidState(_:)``. Sending is not allowed on a one-way receive channel.
    ///
    /// - Throws: ``NoiseError/invalidState(_:)`` unconditionally.
    public override func encryptWithAd(_ ad: Data, plaintext: Data) throws -> Data {
        throw NoiseError.invalidState("Cannot send on a one-way pattern receive-only channel")
    }
    /// Always throws ``NoiseError/invalidState(_:)``. Receiving is not allowed on a one-way send channel.
    ///
    /// - Throws: ``NoiseError/invalidState(_:)`` unconditionally.
    public override func decryptWithAd(_ ad: Data, ciphertext: Data) throws -> Data {
        throw NoiseError.invalidState("Cannot receive on a one-way pattern send-only channel")
    }
}
