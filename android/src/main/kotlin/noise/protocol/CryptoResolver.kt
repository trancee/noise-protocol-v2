package noise.protocol

/**
 * Resolves Noise Protocol algorithm names to concrete implementations.
 *
 * The default resolver supports all standard Noise algorithms. Custom resolvers
 * can be created via [DefaultCryptoResolver.Builder] to register additional or
 * replacement algorithms.
 *
 * @see CryptoSuite
 * @see DefaultCryptoResolver
 */
interface CryptoResolver {
    /**
     * Resolves DH, cipher, and hash names into a [CryptoSuite].
     *
     * @param dhName DH function name (e.g. "25519", "448")
     * @param cipherName Cipher name (e.g. "ChaChaPoly", "AESGCM")
     * @param hashName Hash name (e.g. "SHA256", "BLAKE2b")
     * @throws NoiseException.InvalidPattern if any name is not recognized
     */
    fun resolve(dhName: String, cipherName: String, hashName: String): CryptoSuite

    companion object {
        /** Pre-wired resolver with all standard Noise algorithms. */
        val default: CryptoResolver = DefaultCryptoResolver.Builder()
            .dh("25519") { Curve25519DH }
            .dh("448") { X448DH }
            .cipher("ChaChaPoly") { ChaChaPoly }
            .cipher("AESGCM") { AESGCM }
            .hash("SHA256") { SHA256Hash }
            .hash("SHA512") { SHA512Hash }
            .hash("BLAKE2b") { Blake2bHash }
            .hash("BLAKE2s") { Blake2sHash }
            .build()
    }
}

/**
 * Registry-backed [CryptoResolver] built via [Builder].
 *
 * Immutable after construction — safe to share across threads.
 */
class DefaultCryptoResolver private constructor(
    private val dhRegistry: Map<String, () -> DH>,
    private val cipherRegistry: Map<String, () -> CipherFunction>,
    private val hashRegistry: Map<String, () -> HashFunction>
) : CryptoResolver {

    override fun resolve(dhName: String, cipherName: String, hashName: String): CryptoSuite {
        val dh = dhRegistry[dhName]?.invoke()
            ?: throw NoiseException.InvalidPattern("Unsupported DH: $dhName")
        val cipher = cipherRegistry[cipherName]?.invoke()
            ?: throw NoiseException.InvalidPattern("Unsupported cipher: $cipherName")
        val hash = hashRegistry[hashName]?.invoke()
            ?: throw NoiseException.InvalidPattern("Unsupported hash: $hashName")
        return CryptoSuite(dh, cipher, hash)
    }

    /** Builds a [DefaultCryptoResolver] by registering algorithm factories. */
    class Builder {
        private val dh = mutableMapOf<String, () -> DH>()
        private val cipher = mutableMapOf<String, () -> CipherFunction>()
        private val hash = mutableMapOf<String, () -> HashFunction>()

        fun dh(name: String, factory: () -> DH) = apply { dh[name] = factory }
        fun cipher(name: String, factory: () -> CipherFunction) = apply { cipher[name] = factory }
        fun hash(name: String, factory: () -> HashFunction) = apply { hash[name] = factory }

        fun build(): DefaultCryptoResolver =
            DefaultCryptoResolver(dh.toMap(), cipher.toMap(), hash.toMap())
    }
}
