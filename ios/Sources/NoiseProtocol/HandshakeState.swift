import Foundation

/// Manages the state machine for a Noise Protocol handshake.
///
/// `HandshakeState` processes handshake message patterns token by token, performing
/// DH operations, key mixing, and encryption/decryption as dictated by the chosen
/// Noise pattern. After all message patterns are processed, it produces two
/// ``CipherState`` instances for transport-phase communication.
///
/// This class implements the `HandshakeState` object from Section 5.3 of the
/// [Noise Protocol specification](https://noiseprotocol.org/noise.html).
class HandshakeState {
    private let role: Role
    private let dhFn: DH
    private let symmetricState: SymmetricState
    private var s: KeyPair?
    private var e: KeyPair?
    private var rs: Data?
    private var re: Data?
    private var messageIndex = 0
    private let messagePatterns: [[String]]
    private(set) var isHandshakeComplete = false
    private var cipherStatePair: (CipherState, CipherState)?
    private var eSecure: SecureBuffer?
    private let fixedEphemeral: KeyPair?
    private let pskList: [Data]
    private var pskIndex = 0
    private let isNoisePSK: Bool
    private let isPskHandshake: Bool

    /// Creates a new handshake state for the given protocol configuration.
    ///
    /// Initializes the symmetric state with the protocol name, processes pre-message
    /// patterns (mixing known public keys into the handshake hash), and handles legacy
    /// `NoisePSK_` prefix conventions.
    ///
    /// - Parameters:
    ///   - protocolName: The full Noise protocol name (e.g., `"Noise_XX_25519_ChaChaPoly_SHA256"`).
    ///   - role: Whether this party is the initiator or responder.
    ///   - dh: The Diffie-Hellman function to use.
    ///   - cipher: The AEAD cipher function to use.
    ///   - hash: The hash function to use.
    ///   - descriptor: The parsed handshake pattern descriptor.
    ///   - staticKeyPair: The local static key pair, if required by the pattern.
    ///   - remoteStaticKey: The remote party's static public key, if known in advance.
    ///   - prologue: Application-specific prologue data mixed into the handshake hash.
    ///   - localEphemeral: A fixed local ephemeral key pair (for testing or pre-message patterns).
    ///   - remoteEphemeral: The remote ephemeral public key, if known from a pre-message.
    ///   - psks: Pre-shared keys for PSK handshake patterns, in order of use.
    /// - Throws: ``NoiseError/invalidKey(_:)`` if required keys are missing for the pattern.
    init(protocolName: String, role: Role, dh: DH, cipher: CipherFunction,
         hash: HashFunction, descriptor: HandshakeDescriptor,
         staticKeyPair: KeyPair? = nil,
         remoteStaticKey: Data? = nil, prologue: Data = Data(),
         localEphemeral: KeyPair? = nil,
         remoteEphemeral: Data? = nil,
         psks: [Data] = []) throws {
        self.role = role
        self.dhFn = dh
        self.fixedEphemeral = localEphemeral
        self.s = staticKeyPair
        self.rs = remoteStaticKey
        self.pskList = psks
        self.isNoisePSK = descriptor.isNoisePSK
        self.isPskHandshake = descriptor.isNoisePSK || !descriptor.pskPositions.isEmpty
        self.symmetricState = SymmetricState(protocolName: protocolName, cipher: cipher, hash: hash)
        self.messagePatterns = descriptor.messagePatterns

        symmetricState.mixHash(prologue)

        // Old NoisePSK_ convention: mix PSK before pre-messages
        if isNoisePSK {
            guard !pskList.isEmpty else {
                throw NoiseError.invalidKey("PSK required for NoisePSK_ protocol")
            }
            symmetricState.mixPsk(pskList[0])
        }

        // Process pre-messages: mix known public keys into handshake hash
        for token in descriptor.initiatorPreMessages {
            if token == "s" {
                guard let key = (role == .initiator ? s?.publicKey : rs) else {
                    throw NoiseError.invalidKey(role == .initiator
                        ? "Initiator static key required for \(descriptor.pattern) pattern"
                        : "Remote static key required for \(descriptor.pattern) pattern")
                }
                symmetricState.mixHash(key)
            } else if token == "e" {
                if role == .initiator {
                    guard let localEph = localEphemeral else {
                        throw NoiseError.invalidKey("Initiator ephemeral key required for \(descriptor.pattern) pattern")
                    }
                    self.e = localEph
                    symmetricState.mixHash(localEph.publicKey)
                } else {
                    guard let remEph = remoteEphemeral else {
                        throw NoiseError.invalidKey("Remote ephemeral key required for \(descriptor.pattern) pattern")
                    }
                    self.re = remEph
                    symmetricState.mixHash(remEph)
                }
            }
        }
        for token in descriptor.responderPreMessages {
            if token == "s" {
                guard let key = (role == .responder ? s?.publicKey : rs) else {
                    throw NoiseError.invalidKey(role == .responder
                        ? "Responder static key required for \(descriptor.pattern) pattern"
                        : "Remote static key required for \(descriptor.pattern) pattern")
                }
                symmetricState.mixHash(key)
            } else if token == "e" {
                if role == .responder {
                    guard let localEph = localEphemeral else {
                        throw NoiseError.invalidKey("Responder ephemeral key required for \(descriptor.pattern) pattern")
                    }
                    self.e = localEph
                    symmetricState.mixHash(localEph.publicKey)
                } else {
                    guard let remEph = remoteEphemeral else {
                        throw NoiseError.invalidKey("Remote ephemeral key required for \(descriptor.pattern) pattern")
                    }
                    self.re = remEph
                    symmetricState.mixHash(remEph)
                }
            }
        }
    }

    /// Returns the local ephemeral private key, if one has been generated.
    ///
    /// - Returns: The ephemeral private key data, or `nil` if not yet generated.
    func getLocalEphemeralPrivateKey() -> Data? {
        return e?.privateKey
    }

    /// Constructs and sends the next handshake message.
    ///
    /// Processes the current message pattern's tokens (generating ephemeral keys,
    /// performing DH operations, encrypting static keys) and appends an encrypted
    /// payload. Advances the handshake state; if this is the final message, the
    /// handshake completes and cipher states become available via ``split()``.
    ///
    /// - Parameter payload: Optional payload data to include in the handshake message.
    /// - Returns: The serialized handshake message bytes.
    /// - Throws: ``NoiseError`` if keys are missing or encryption fails.
    func writeMessage(payload: Data = Data()) throws -> Data {
        let pattern = messagePatterns[messageIndex]
        var buffer = Data()

        for token in pattern {
            switch token {
            case "e":
                e = fixedEphemeral ?? dhFn.generateKeyPair()
                eSecure = SecureBuffer.wrap(e!.privateKey)
                buffer.append(e!.publicKey)
                symmetricState.mixHash(e!.publicKey)
                if isPskHandshake { symmetricState.mixKey(e!.publicKey) }
            case "s":
                buffer.append(try symmetricState.encryptAndHash(s!.publicKey))
            case "psk":
                guard pskIndex < pskList.count else {
                    throw NoiseError.invalidKey("Missing PSK at index \(pskIndex)")
                }
                symmetricState.mixKeyAndHash(pskList[pskIndex])
                pskIndex += 1
            default:
                try processDHToken(token)
            }
        }

        buffer.append(try symmetricState.encryptAndHash(payload))
        advanceHandshake()
        return buffer
    }

    /// Processes a received handshake message and extracts its payload.
    ///
    /// Parses the message according to the current message pattern's tokens, extracting
    /// public keys, performing DH operations, and decrypting. Advances the handshake state.
    ///
    /// - Parameter message: The raw handshake message bytes received from the peer.
    /// - Returns: The decrypted payload contained in the message.
    /// - Throws: ``NoiseError`` if decryption fails or keys are missing.
    func readMessage(_ message: Data) throws -> Data {
        let pattern = messagePatterns[messageIndex]
        var offset = 0

        for token in pattern {
            switch token {
            case "e":
                re = message.subdata(in: offset..<(offset + dhFn.dhLen))
                offset += dhFn.dhLen
                symmetricState.mixHash(re!)
                if isPskHandshake { symmetricState.mixKey(re!) }
            case "s":
                let len = symmetricState.hasKey() ? dhFn.dhLen + 16 : dhFn.dhLen
                let temp = message.subdata(in: offset..<(offset + len))
                offset += len
                rs = try symmetricState.decryptAndHash(temp)
            case "psk":
                guard pskIndex < pskList.count else {
                    throw NoiseError.invalidKey("Missing PSK at index \(pskIndex)")
                }
                symmetricState.mixKeyAndHash(pskList[pskIndex])
                pskIndex += 1
            default:
                try processDHToken(token)
            }
        }

        let payload = try symmetricState.decryptAndHash(message.subdata(in: offset..<message.count))
        advanceHandshake()
        return payload
    }

    /// Splits the handshake state into two cipher states for transport-phase communication.
    ///
    /// Must only be called after the handshake is complete.
    ///
    /// - Returns: A tuple of (`CipherState`, `CipherState`): the first for the initiator's
    ///   sending direction, the second for the responder's sending direction.
    /// - Throws: ``NoiseError/handshakeNotComplete`` if the handshake has not finished.
    func split() throws -> (CipherState, CipherState) {
        guard isHandshakeComplete else { throw NoiseError.handshakeNotComplete }
        return cipherStatePair!
    }

    private func processDHToken(_ token: String) throws {
        let sharedSecret: Data
        switch token {
        case "ee": sharedSecret = try dhFn.dh(keyPair: e!, publicKey: re!)
        case "es": sharedSecret = role == .initiator ? try dhFn.dh(keyPair: e!, publicKey: rs!) : try dhFn.dh(keyPair: s!, publicKey: re!)
        case "se": sharedSecret = role == .initiator ? try dhFn.dh(keyPair: s!, publicKey: re!) : try dhFn.dh(keyPair: e!, publicKey: rs!)
        case "ss": sharedSecret = try dhFn.dh(keyPair: s!, publicKey: rs!)
        default: fatalError("Unknown token: \(token)")
        }
        symmetricState.mixKey(sharedSecret)
    }

    /// Returns the current chaining key from the underlying symmetric state.
    ///
    /// - Returns: The chaining key data.
    func getChainingKey() -> Data {
        return symmetricState.getChainingKey()
    }

    private func advanceHandshake() {
        messageIndex += 1
        if messageIndex >= messagePatterns.count {
            isHandshakeComplete = true
            cipherStatePair = symmetricState.split()
            eSecure?.zero()
        }
    }
}
