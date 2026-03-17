import Foundation

/// Manages handshake key state with domain-error accessors.
class KeyStore {
    var s: KeyPair?
    var e: KeyPair?
    var rs: Data?
    var re: Data?

    init(staticKeyPair: KeyPair? = nil, remoteStaticKey: Data? = nil) {
        self.s = staticKeyPair
        self.rs = remoteStaticKey
    }

    /// Returns the local key pair for the given reference, or throws.
    func requireKeyPair(_ ref: KeyRef) throws -> KeyPair {
        switch ref {
        case .s:
            guard let kp = s else {
                throw NoiseError.invalidKey("Local static key not available")
            }
            return kp
        case .e:
            guard let kp = e else {
                throw NoiseError.invalidKey("Local ephemeral key not yet generated")
            }
            return kp
        default:
            throw NoiseError.invalidKey("\(ref) is not a local key pair reference")
        }
    }

    /// Returns the public key for the given reference, or throws.
    func requirePublicKey(_ ref: KeyRef) throws -> Data {
        switch ref {
        case .s:
            guard let pk = s?.publicKey else {
                throw NoiseError.invalidKey("Local static key not available")
            }
            return pk
        case .e:
            guard let pk = e?.publicKey else {
                throw NoiseError.invalidKey("Local ephemeral key not yet generated")
            }
            return pk
        case .rs:
            guard let pk = rs else {
                throw NoiseError.invalidKey("Remote static key not yet received")
            }
            return pk
        case .re:
            guard let pk = re else {
                throw NoiseError.invalidKey("Remote ephemeral key not yet received")
            }
            return pk
        }
    }
}
