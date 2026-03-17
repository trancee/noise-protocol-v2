import Foundation

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
    private let fixedEphemeral: KeyPair?
    private let pskList: [Data]
    private var pskIndex = 0
    private let isNoisePSK: Bool
    private let isPskHandshake: Bool

    init(protocolName: String, role: Role, dh: DH, cipher: CipherFunction,
         hash: HashFunction, descriptor: HandshakeDescriptor,
         staticKeyPair: KeyPair? = nil,
         remoteStaticKey: Data? = nil, prologue: Data = Data(),
         localEphemeral: KeyPair? = nil,
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
            }
        }
    }

    func writeMessage(payload: Data = Data()) throws -> Data {
        let pattern = messagePatterns[messageIndex]
        var buffer = Data()

        for token in pattern {
            switch token {
            case "e":
                e = fixedEphemeral ?? dhFn.generateKeyPair()
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

    private func advanceHandshake() {
        messageIndex += 1
        if messageIndex >= messagePatterns.count {
            isHandshakeComplete = true
            cipherStatePair = symmetricState.split()
        }
    }
}
