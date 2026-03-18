@file:OptIn(ExperimentalUnsignedTypes::class)

package noise.protocol

import java.security.KeyPairGenerator
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Abstraction for a Diffie-Hellman key-agreement function as defined by the
 * Noise Protocol Framework (Section 4.1).
 *
 * Implementations must be thread-safe.
 *
 * @see Curve25519DH
 * @see X448DH
 */
interface DH {
    /** The length of a public key in bytes (also the DH output length). */
    val dhLen: Int

    /**
     * Generates a new random DH key pair.
     *
     * @return A fresh [KeyPair] with [dhLen]-byte keys.
     */
    fun generateKeyPair(): KeyPair

    /**
     * Performs a Diffie-Hellman key agreement.
     *
     * @param keyPair The local key pair (private key is used).
     * @param publicKey The remote party's public key ([dhLen] bytes).
     * @return The shared secret ([dhLen] bytes).
     */
    fun dh(keyPair: KeyPair, publicKey: ByteArray): ByteArray
}

/**
 * Abstraction for an AEAD cipher function as defined by the Noise Protocol
 * Framework (Section 4.2).
 *
 * Each implementation provides authenticated encryption with associated data (AEAD)
 * using a 256-bit key, a 64-bit nonce, and arbitrary associated data.
 *
 * Implementations must be thread-safe.
 *
 * @see ChaChaPoly
 * @see AESGCM
 */
interface CipherFunction {
    /**
     * Encrypts [plaintext] with the given [key], [nonce], and associated data [ad].
     *
     * @param key The 256-bit (32-byte) encryption key.
     * @param nonce The 64-bit nonce value.
     * @param ad Associated data to authenticate but not encrypt.
     * @param plaintext The data to encrypt.
     * @return The ciphertext including a 16-byte authentication tag appended.
     */
    fun encrypt(key: ByteArray, nonce: Long, ad: ByteArray, plaintext: ByteArray): ByteArray

    /**
     * Decrypts [ciphertext] with the given [key], [nonce], and associated data [ad].
     *
     * @param key The 256-bit (32-byte) decryption key.
     * @param nonce The 64-bit nonce value.
     * @param ad Associated data that was authenticated during encryption.
     * @param ciphertext The data to decrypt (including the 16-byte authentication tag).
     * @return The decrypted plaintext.
     * @throws javax.crypto.AEADBadTagException If authentication fails.
     */
    fun decrypt(key: ByteArray, nonce: Long, ad: ByteArray, ciphertext: ByteArray): ByteArray
}

/**
 * Abstraction for a hash function as defined by the Noise Protocol Framework (Section 4.3).
 *
 * Provides basic hashing plus HMAC and HKDF (used internally by [SymmetricState]).
 *
 * Implementations must be thread-safe.
 *
 * @see SHA256Hash
 * @see SHA512Hash
 * @see Blake2bHash
 * @see Blake2sHash
 */
interface HashFunction {
    /** The output length of this hash function in bytes. */
    val hashLen: Int

    /** The internal block length of this hash function in bytes. */
    val blockLen: Int

    /**
     * Computes the hash digest of [data].
     *
     * @param data The input bytes to hash.
     * @return The [hashLen]-byte digest.
     */
    fun hash(data: ByteArray): ByteArray

    /**
     * Computes the hash digest of the concatenation of [a] and [b].
     *
     * This overload may be more efficient than manually concatenating
     * the arrays when the implementation supports incremental hashing.
     *
     * @param a The first input bytes.
     * @param b The second input bytes.
     * @return The [hashLen]-byte digest of `a || b`.
     */
    fun hash(a: ByteArray, b: ByteArray): ByteArray = hash(a + b)
    /**
     * Computes an HMAC using this hash function as specified by RFC 2104.
     *
     * @param key The HMAC key (will be hashed if longer than [blockLen]).
     * @param data The message to authenticate.
     * @return The [hashLen]-byte HMAC output.
     */
    fun hmacHash(key: ByteArray, data: ByteArray): ByteArray {
        val paddedKey = if (key.size > blockLen) hash(key) else key
        val ipad = ByteArray(blockLen) { if (it < paddedKey.size) (paddedKey[it].toInt() xor 0x36).toByte() else 0x36 }
        val opad = ByteArray(blockLen) { if (it < paddedKey.size) (paddedKey[it].toInt() xor 0x5c).toByte() else 0x5c }
        return hash(opad + hash(ipad + data))
    }
    /**
     * Derives keys using HKDF as specified by the Noise Protocol Framework (Section 4.3).
     *
     * @param chainingKey The chaining key used as the HKDF salt.
     * @param inputKeyMaterial The input key material.
     * @param numOutputs The number of output keys to derive (2 or 3).
     * @return A list of [numOutputs] derived keys, each [hashLen] bytes long.
     */
    fun hkdf(chainingKey: ByteArray, inputKeyMaterial: ByteArray, numOutputs: Int): List<ByteArray> {
        val tempKey = hmacHash(chainingKey, inputKeyMaterial)
        val output1 = hmacHash(tempKey, byteArrayOf(0x01))
        if (numOutputs == 2) {
            // Avoid output1 + byteArrayOf(0x02) allocation
            val input2 = ByteArray(output1.size + 1)
            output1.copyInto(input2)
            input2[output1.size] = 0x02
            val output2 = hmacHash(tempKey, input2)
            return listOf(output1, output2)
        }
        val input2 = ByteArray(output1.size + 1)
        output1.copyInto(input2)
        input2[output1.size] = 0x02
        val output2 = hmacHash(tempKey, input2)
        val input3 = ByteArray(output2.size + 1)
        output2.copyInto(input3)
        input3[output2.size] = 0x03
        val output3 = hmacHash(tempKey, input3)
        return listOf(output1, output2, output3)
    }
}

/**
 * Curve25519 (X25519) Diffie-Hellman implementation backed by the JCA.
 *
 * Uses thread-local JCA instances ([KeyPairGenerator], [KeyAgreement]) for
 * thread-safety without synchronization overhead.
 *
 * Key length: 32 bytes.
 *
 * @see DH
 * @see X448DH
 */
object Curve25519DH : DH {
    /** DH output and public key length: 32 bytes. */
    override val dhLen = 32

    // Cached JCA instances (KeyFactory is thread-safe; KPG/KA are per-thread)
    private val keyFactory = java.security.KeyFactory.getInstance("X25519")
    private val kpgLocal = ThreadLocal.withInitial { KeyPairGenerator.getInstance("X25519") }
    private val kaLocal = ThreadLocal.withInitial { KeyAgreement.getInstance("X25519") }

    // Pre-allocated ASN.1 headers (avoid concatenation per call)
    private val pkcs8Header = byteArrayOf(
        0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
        0x03, 0x2B, 0x65, 0x6E, 0x04, 0x22, 0x04, 0x20
    )
    private val x509Header = byteArrayOf(
        0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65,
        0x6E, 0x03, 0x21, 0x00
    )

    override fun generateKeyPair(): KeyPair {
        val javaKeyPair = kpgLocal.get().generateKeyPair()
        val privBytes = extractRawPrivateKey(javaKeyPair.private)
        val pubBytes = extractRawPublicKey(javaKeyPair.public)
        return KeyPair(privBytes, pubBytes)
    }

    override fun dh(keyPair: KeyPair, publicKey: ByteArray): ByteArray {
        val privKey = buildX25519PrivateKey(keyPair.privateKey)
        val pubKey = buildX25519PublicKey(publicKey)
        val ka = kaLocal.get()
        ka.init(privKey)
        ka.doPhase(pubKey, true)
        return ka.generateSecret()
    }

    private fun extractRawPrivateKey(key: java.security.PrivateKey): ByteArray {
        val encoded = key.encoded
        return encoded.copyOfRange(encoded.size - 32, encoded.size)
    }

    private fun extractRawPublicKey(key: java.security.PublicKey): ByteArray {
        val encoded = key.encoded
        return encoded.copyOfRange(encoded.size - 32, encoded.size)
    }

    private fun buildX25519PrivateKey(raw: ByteArray): java.security.PrivateKey {
        // Inline ASN.1 wrapping into pre-sized buffer (avoid + concatenation)
        val pkcs8 = ByteArray(pkcs8Header.size + 32)
        pkcs8Header.copyInto(pkcs8)
        raw.copyInto(pkcs8, pkcs8Header.size)
        return keyFactory.generatePrivate(java.security.spec.PKCS8EncodedKeySpec(pkcs8))
    }

    private fun buildX25519PublicKey(raw: ByteArray): java.security.PublicKey {
        val x509 = ByteArray(x509Header.size + 32)
        x509Header.copyInto(x509)
        raw.copyInto(x509, x509Header.size)
        return keyFactory.generatePublic(java.security.spec.X509EncodedKeySpec(x509))
    }

    /**
     * Derives the X25519 public key from a raw private key by performing scalar
     * multiplication with the standard base point.
     *
     * @param privateKey The 32-byte raw private key.
     * @return The corresponding 32-byte public key.
     */
    fun generatePublicKey(privateKey: ByteArray): ByteArray {
        val privKey = buildX25519PrivateKey(privateKey)
        val ka = kaLocal.get()
        ka.init(privKey)
        val basepoint = ByteArray(32).also { it[0] = 9 }
        ka.doPhase(buildX25519PublicKey(basepoint), true)
        return ka.generateSecret()
    }
}

/**
 * X448 (Goldilocks) Diffie-Hellman implementation using a pure-Kotlin scalar
 * multiplication ([X448] helper object).
 *
 * Key length: 56 bytes.
 *
 * @see DH
 * @see Curve25519DH
 */
object X448DH : DH {
    /** DH output and public key length: 56 bytes. */
    override val dhLen = 56

    override fun generateKeyPair(): KeyPair {
        val privateKey = ByteArray(56).also { java.security.SecureRandom().nextBytes(it) }
        val basePoint = ByteArray(56).also { it[0] = 5 }
        val publicKey = X448.scalarMult(privateKey, basePoint)
        return KeyPair(privateKey, publicKey)
    }

    override fun dh(keyPair: KeyPair, publicKey: ByteArray): ByteArray {
        return X448.scalarMult(keyPair.privateKey, publicKey)
    }
}

// Noise spec: 4 bytes zeros + 8 bytes little-endian nonce = 12 bytes
// Thread-local buffer to avoid per-call allocation
private val nonceBuffer = ThreadLocal.withInitial { ByteArray(12) }

private fun nonceToBytes(nonce: Long): ByteArray {
    val bytes = nonceBuffer.get()
    // First 4 bytes are always zero (already initialized)
    bytes[4] = (nonce).toByte()
    bytes[5] = (nonce shr 8).toByte()
    bytes[6] = (nonce shr 16).toByte()
    bytes[7] = (nonce shr 24).toByte()
    bytes[8] = (nonce shr 32).toByte()
    bytes[9] = (nonce shr 40).toByte()
    bytes[10] = (nonce shr 48).toByte()
    bytes[11] = (nonce shr 56).toByte()
    return bytes
}

/**
 * ChaCha20-Poly1305 AEAD cipher implementation backed by the JCA.
 *
 * Nonce encoding follows the Noise specification: 4 zero bytes followed by
 * 8 bytes of the 64-bit nonce in little-endian byte order (12 bytes total).
 *
 * Uses thread-local JCA [Cipher] instances for thread-safety.
 *
 * @see CipherFunction
 * @see AESGCM
 */
object ChaChaPoly : CipherFunction {
    private val cipherLocal = ThreadLocal.withInitial { Cipher.getInstance("ChaCha20-Poly1305") }

    override fun encrypt(key: ByteArray, nonce: Long, ad: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = cipherLocal.get()
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), javax.crypto.spec.IvParameterSpec(nonceToBytes(nonce)))
        cipher.updateAAD(ad)
        return cipher.doFinal(plaintext)
    }

    override fun decrypt(key: ByteArray, nonce: Long, ad: ByteArray, ciphertext: ByteArray): ByteArray {
        val cipher = cipherLocal.get()
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), javax.crypto.spec.IvParameterSpec(nonceToBytes(nonce)))
        cipher.updateAAD(ad)
        return cipher.doFinal(ciphertext)
    }
}

/**
 * AES-256-GCM AEAD cipher implementation backed by the JCA.
 *
 * Nonce encoding follows the Noise specification: 4 zero bytes followed by
 * 8 bytes of the 64-bit nonce in little-endian byte order (12 bytes total).
 * Uses a 128-bit authentication tag.
 *
 * Uses thread-local JCA [Cipher] instances for thread-safety.
 *
 * @see CipherFunction
 * @see ChaChaPoly
 */
object AESGCM : CipherFunction {
    // GCM encrypt requires a fresh Cipher per call — Java 21 refuses re-init after doFinal
    private val decryptCipherLocal = ThreadLocal.withInitial { Cipher.getInstance("AES/GCM/NoPadding") }

    override fun encrypt(key: ByteArray, nonce: Long, ad: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonceToBytes(nonce)))
        cipher.updateAAD(ad)
        return cipher.doFinal(plaintext)
    }

    override fun decrypt(key: ByteArray, nonce: Long, ad: ByteArray, ciphertext: ByteArray): ByteArray {
        val cipher = decryptCipherLocal.get()
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonceToBytes(nonce)))
        cipher.updateAAD(ad)
        return cipher.doFinal(ciphertext)
    }
}

/**
 * SHA-256 hash function implementation backed by the JCA.
 *
 * Provides an optimized [hmacHash] via the JCA `HmacSHA256` [javax.crypto.Mac],
 * as well as incremental [hash] for two-part inputs.
 *
 * Hash length: 32 bytes. Block length: 64 bytes.
 *
 * @see HashFunction
 * @see SHA512Hash
 */
object SHA256Hash : HashFunction {
    /** Hash output length: 32 bytes. */
    override val hashLen = 32
    /** Internal block length: 64 bytes. */
    override val blockLen = 64
    private val mdLocal = ThreadLocal.withInitial { MessageDigest.getInstance("SHA-256") }
    private val macLocal = ThreadLocal.withInitial { javax.crypto.Mac.getInstance("HmacSHA256") }

    override fun hash(data: ByteArray): ByteArray {
        val md = mdLocal.get()
        md.reset()
        return md.digest(data)
    }

    override fun hash(a: ByteArray, b: ByteArray): ByteArray {
        val md = mdLocal.get()
        md.reset()
        md.update(a)
        return md.digest(b)
    }

    override fun hmacHash(key: ByteArray, data: ByteArray): ByteArray {
        val mac = macLocal.get()
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }
}

/**
 * SHA-512 hash function implementation backed by the JCA.
 *
 * Provides an optimized [hmacHash] via the JCA `HmacSHA512` [javax.crypto.Mac],
 * as well as incremental [hash] for two-part inputs.
 *
 * Hash length: 64 bytes. Block length: 128 bytes.
 *
 * @see HashFunction
 * @see SHA256Hash
 */
object SHA512Hash : HashFunction {
    /** Hash output length: 64 bytes. */
    override val hashLen = 64
    /** Internal block length: 128 bytes. */
    override val blockLen = 128
    private val mdLocal = ThreadLocal.withInitial { MessageDigest.getInstance("SHA-512") }
    private val macLocal = ThreadLocal.withInitial { javax.crypto.Mac.getInstance("HmacSHA512") }

    override fun hash(data: ByteArray): ByteArray {
        val md = mdLocal.get()
        md.reset()
        return md.digest(data)
    }

    override fun hash(a: ByteArray, b: ByteArray): ByteArray {
        val md = mdLocal.get()
        md.reset()
        md.update(a)
        return md.digest(b)
    }

    override fun hmacHash(key: ByteArray, data: ByteArray): ByteArray {
        val mac = macLocal.get()
        mac.init(SecretKeySpec(key, "HmacSHA512"))
        return mac.doFinal(data)
    }
}

/**
 * BLAKE2b hash function implemented in pure Kotlin.
 *
 * Implements the BLAKE2b algorithm (RFC 7693) with a fixed 64-byte output.
 * Uses 12 rounds of the G mixing function on 64-bit words.
 *
 * Hash length: 64 bytes. Block length: 128 bytes.
 *
 * @see HashFunction
 * @see Blake2sHash
 */
object Blake2bHash : HashFunction {
    /** Hash output length: 64 bytes. */
    override val hashLen = 64
    /** Internal block length: 128 bytes. */
    override val blockLen = 128

    private val IV = ulongArrayOf(
        0x6A09E667F3BCC908uL, 0xBB67AE8584CAA73BuL,
        0x3C6EF372FE94F82BuL, 0xA54FF53A5F1D36F1uL,
        0x510E527FADE682D1uL, 0x9B05688C2B3E6C1FuL,
        0x1F83D9ABFB41BD6BuL, 0x5BE0CD19137E2179uL
    )

    private val SIGMA = arrayOf(
        intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
        intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
        intArrayOf(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
        intArrayOf(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
        intArrayOf(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
        intArrayOf(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
        intArrayOf(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
        intArrayOf(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
        intArrayOf(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
        intArrayOf(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
        intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
        intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3)
    )

    override fun hash(data: ByteArray): ByteArray {
        val h = ULongArray(8)
        for (i in 0..7) h[i] = IV[i]
        h[0] = h[0] xor (0x01010000uL or 64uL) // parameter block: depth=1, fanout=1, nn=64

        val dd = if (data.isEmpty()) 1 else (data.size + blockLen - 1) / blockLen
        val padded = ByteArray(dd * blockLen)
        data.copyInto(padded)

        for (i in 0 until dd) {
            val block = getWordsLE64(padded, i * blockLen, 16)
            val t = if (i < dd - 1) ((i + 1).toLong() * blockLen).toULong() else data.size.toULong()
            val last = i == dd - 1
            compress(h, block, t, last)
        }

        return wordsToLE64(h)
    }

    private fun compress(h: ULongArray, m: ULongArray, t: ULong, last: Boolean) {
        val v = ULongArray(16)
        for (i in 0..7) { v[i] = h[i]; v[i + 8] = IV[i] }
        v[12] = v[12] xor t
        // v[13] = v[13] xor (t >> 64) — always 0 for our use case
        if (last) v[14] = v[14] xor ULong.MAX_VALUE

        for (i in 0..11) {
            val s = SIGMA[i]
            g(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
            g(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
            g(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
            g(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
            g(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
            g(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
            g(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
            g(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
        }

        for (i in 0..7) h[i] = h[i] xor v[i] xor v[i + 8]
    }

    private fun g(v: ULongArray, a: Int, b: Int, c: Int, d: Int, x: ULong, y: ULong) {
        v[a] = v[a] + v[b] + x
        v[d] = (v[d] xor v[a]).rotateRight(32)
        v[c] = v[c] + v[d]
        v[b] = (v[b] xor v[c]).rotateRight(24)
        v[a] = v[a] + v[b] + y
        v[d] = (v[d] xor v[a]).rotateRight(16)
        v[c] = v[c] + v[d]
        v[b] = (v[b] xor v[c]).rotateRight(63)
    }

    private fun getWordsLE64(bytes: ByteArray, offset: Int, count: Int): ULongArray {
        val words = ULongArray(count)
        for (i in 0 until count) {
            var w = 0uL
            for (j in 0..7) w = w or (bytes[offset + i * 8 + j].toUByte().toULong() shl (j * 8))
            words[i] = w
        }
        return words
    }

    private fun wordsToLE64(words: ULongArray): ByteArray {
        val bytes = ByteArray(words.size * 8)
        for (i in words.indices) {
            for (j in 0..7) bytes[i * 8 + j] = (words[i] shr (j * 8)).toByte()
        }
        return bytes
    }
}

/**
 * BLAKE2s hash function implemented in pure Kotlin.
 *
 * Implements the BLAKE2s algorithm (RFC 7693) with a fixed 32-byte output.
 * Uses 10 rounds of the G mixing function on 32-bit words.
 *
 * Hash length: 32 bytes. Block length: 64 bytes.
 *
 * @see HashFunction
 * @see Blake2bHash
 */
object Blake2sHash : HashFunction {
    /** Hash output length: 32 bytes. */
    override val hashLen = 32
    /** Internal block length: 64 bytes. */
    override val blockLen = 64

    private val IV = uintArrayOf(
        0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
        0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u
    )

    private val SIGMA = arrayOf(
        intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
        intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
        intArrayOf(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
        intArrayOf(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
        intArrayOf(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
        intArrayOf(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
        intArrayOf(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
        intArrayOf(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
        intArrayOf(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
        intArrayOf(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0)
    )

    override fun hash(data: ByteArray): ByteArray {
        val h = UIntArray(8)
        for (i in 0..7) h[i] = IV[i]
        h[0] = h[0] xor (0x01010000u or 32u)

        val dd = if (data.isEmpty()) 1 else (data.size + blockLen - 1) / blockLen
        val padded = ByteArray(dd * blockLen)
        data.copyInto(padded)

        for (i in 0 until dd) {
            val block = getWordsLE32(padded, i * blockLen, 16)
            val t = if (i < dd - 1) ((i + 1) * blockLen).toUInt() else data.size.toUInt()
            val last = i == dd - 1
            compress(h, block, t, last)
        }

        return wordsToLE32(h)
    }

    private fun compress(h: UIntArray, m: UIntArray, t: UInt, last: Boolean) {
        val v = UIntArray(16)
        for (i in 0..7) { v[i] = h[i]; v[i + 8] = IV[i] }
        v[12] = v[12] xor t
        if (last) v[14] = v[14] xor UInt.MAX_VALUE

        for (i in 0..9) {
            val s = SIGMA[i]
            g(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
            g(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
            g(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
            g(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
            g(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
            g(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
            g(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
            g(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
        }

        for (i in 0..7) h[i] = h[i] xor v[i] xor v[i + 8]
    }

    private fun g(v: UIntArray, a: Int, b: Int, c: Int, d: Int, x: UInt, y: UInt) {
        v[a] = v[a] + v[b] + x
        v[d] = (v[d] xor v[a]).rotateRight(16)
        v[c] = v[c] + v[d]
        v[b] = (v[b] xor v[c]).rotateRight(12)
        v[a] = v[a] + v[b] + y
        v[d] = (v[d] xor v[a]).rotateRight(8)
        v[c] = v[c] + v[d]
        v[b] = (v[b] xor v[c]).rotateRight(7)
    }

    private fun getWordsLE32(bytes: ByteArray, offset: Int, count: Int): UIntArray {
        val words = UIntArray(count)
        for (i in 0 until count) {
            var w = 0u
            for (j in 0..3) w = w or (bytes[offset + i * 4 + j].toUByte().toUInt() shl (j * 8))
            words[i] = w
        }
        return words
    }

    private fun wordsToLE32(words: UIntArray): ByteArray {
        val bytes = ByteArray(words.size * 4)
        for (i in words.indices) {
            for (j in 0..3) bytes[i * 4 + j] = (words[i] shr (j * 8)).toByte()
        }
        return bytes
    }
}
