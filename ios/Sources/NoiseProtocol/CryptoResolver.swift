import Foundation

/// Resolves Noise Protocol algorithm names to concrete implementations.
public protocol CryptoResolver: Sendable {
    func resolve(dhName: String, cipherName: String, hashName: String) throws -> CryptoSuite
}

/// Registry-backed CryptoResolver built via Builder.
public final class DefaultCryptoResolver: CryptoResolver {
    private let dhRegistry: [String: @Sendable () -> DH]
    private let cipherRegistry: [String: @Sendable () -> CipherFunction]
    private let hashRegistry: [String: @Sendable () -> HashFunction]

    private init(dhRegistry: [String: @Sendable () -> DH],
                 cipherRegistry: [String: @Sendable () -> CipherFunction],
                 hashRegistry: [String: @Sendable () -> HashFunction]) {
        self.dhRegistry = dhRegistry
        self.cipherRegistry = cipherRegistry
        self.hashRegistry = hashRegistry
    }

    public func resolve(dhName: String, cipherName: String, hashName: String) throws -> CryptoSuite {
        guard let dhFactory = dhRegistry[dhName] else {
            throw NoiseError.invalidPattern("Unsupported DH: \(dhName)")
        }
        guard let cipherFactory = cipherRegistry[cipherName] else {
            throw NoiseError.invalidPattern("Unsupported cipher: \(cipherName)")
        }
        guard let hashFactory = hashRegistry[hashName] else {
            throw NoiseError.invalidPattern("Unsupported hash: \(hashName)")
        }
        return CryptoSuite(dh: dhFactory(), cipher: cipherFactory(), hash: hashFactory())
    }

    /// Builds a DefaultCryptoResolver by registering algorithm factories.
    public final class Builder {
        private var dhMap: [String: @Sendable () -> DH] = [:]
        private var cipherMap: [String: @Sendable () -> CipherFunction] = [:]
        private var hashMap: [String: @Sendable () -> HashFunction] = [:]

        public init() {}

        @discardableResult
        public func dh(_ name: String, factory: @escaping @Sendable () -> DH) -> Builder {
            dhMap[name] = factory; return self
        }

        @discardableResult
        public func cipher(_ name: String, factory: @escaping @Sendable () -> CipherFunction) -> Builder {
            cipherMap[name] = factory; return self
        }

        @discardableResult
        public func hash(_ name: String, factory: @escaping @Sendable () -> HashFunction) -> Builder {
            hashMap[name] = factory; return self
        }

        public func build() -> DefaultCryptoResolver {
            DefaultCryptoResolver(dhRegistry: dhMap, cipherRegistry: cipherMap, hashRegistry: hashMap)
        }
    }

    /// Pre-wired resolver with all standard Noise algorithms.
    public static let `default`: CryptoResolver = DefaultCryptoResolver.Builder()
        .dh("25519") { Curve25519DH() }
        .dh("448") { X448DH_() }
        .cipher("ChaChaPoly") { ChaChaPoly_() }
        .cipher("AESGCM") { AESGCM_() }
        .hash("SHA256") { SHA256Hash_() }
        .hash("SHA512") { SHA512Hash_() }
        .hash("BLAKE2b") { Blake2bHash_() }
        .hash("BLAKE2s") { Blake2sHash_() }
        .build()
}
