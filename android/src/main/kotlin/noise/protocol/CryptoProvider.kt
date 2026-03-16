package noise.protocol

import java.security.KeyPairGenerator
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

interface DH {
    val dhLen: Int
    fun generateKeyPair(): KeyPair
    fun dh(keyPair: KeyPair, publicKey: ByteArray): ByteArray
}

interface CipherFunction {
    fun encrypt(key: ByteArray, nonce: Long, ad: ByteArray, plaintext: ByteArray): ByteArray
    fun decrypt(key: ByteArray, nonce: Long, ad: ByteArray, ciphertext: ByteArray): ByteArray
}

interface HashFunction {
    val hashLen: Int
    val blockLen: Int
    fun hash(data: ByteArray): ByteArray
    fun hmacHash(key: ByteArray, data: ByteArray): ByteArray {
        val paddedKey = if (key.size > blockLen) hash(key) else key
        val ipad = ByteArray(blockLen) { if (it < paddedKey.size) (paddedKey[it].toInt() xor 0x36).toByte() else 0x36 }
        val opad = ByteArray(blockLen) { if (it < paddedKey.size) (paddedKey[it].toInt() xor 0x5c).toByte() else 0x5c }
        return hash(opad + hash(ipad + data))
    }
    fun hkdf(chainingKey: ByteArray, inputKeyMaterial: ByteArray, numOutputs: Int): List<ByteArray> {
        val tempKey = hmacHash(chainingKey, inputKeyMaterial)
        val output1 = hmacHash(tempKey, byteArrayOf(0x01))
        if (numOutputs == 2) {
            val output2 = hmacHash(tempKey, output1 + byteArrayOf(0x02))
            return listOf(output1, output2)
        }
        val output2 = hmacHash(tempKey, output1 + byteArrayOf(0x02))
        val output3 = hmacHash(tempKey, output2 + byteArrayOf(0x03))
        return listOf(output1, output2, output3)
    }
}

object Curve25519DH : DH {
    override val dhLen = 32

    override fun generateKeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("X25519")
        val javaKeyPair = kpg.generateKeyPair()
        val privBytes = extractRawPrivateKey(javaKeyPair.private)
        val pubBytes = extractRawPublicKey(javaKeyPair.public)
        return KeyPair(privBytes, pubBytes)
    }

    override fun dh(keyPair: KeyPair, publicKey: ByteArray): ByteArray {
        val privKey = buildX25519PrivateKey(keyPair.privateKey)
        val pubKey = buildX25519PublicKey(publicKey)
        val ka = KeyAgreement.getInstance("X25519")
        ka.init(privKey)
        ka.doPhase(pubKey, true)
        return ka.generateSecret()
    }

    private fun extractRawPrivateKey(key: java.security.PrivateKey): ByteArray {
        // PKCS#8 DER for X25519: last 32 bytes after the ASN.1 wrapper
        val encoded = key.encoded
        return encoded.copyOfRange(encoded.size - 32, encoded.size)
    }

    private fun extractRawPublicKey(key: java.security.PublicKey): ByteArray {
        // X.509 DER for X25519: last 32 bytes after the ASN.1 wrapper
        val encoded = key.encoded
        return encoded.copyOfRange(encoded.size - 32, encoded.size)
    }

    private fun buildX25519PrivateKey(raw: ByteArray): java.security.PrivateKey {
        // Build PKCS#8 encoding for X25519 private key
        val pkcs8Header = byteArrayOf(
            0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
            0x03, 0x2B, 0x65, 0x6E, 0x04, 0x22, 0x04, 0x20
        )
        val pkcs8 = pkcs8Header + raw
        val keySpec = java.security.spec.PKCS8EncodedKeySpec(pkcs8)
        return java.security.KeyFactory.getInstance("X25519").generatePrivate(keySpec)
    }

    private fun buildX25519PublicKey(raw: ByteArray): java.security.PublicKey {
        // Build X.509 encoding for X25519 public key
        val x509Header = byteArrayOf(
            0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65,
            0x6E, 0x03, 0x21, 0x00
        )
        val x509 = x509Header + raw
        val keySpec = java.security.spec.X509EncodedKeySpec(x509)
        return java.security.KeyFactory.getInstance("X25519").generatePublic(keySpec)
    }
}

// Noise spec: 4 bytes zeros + 8 bytes little-endian nonce = 12 bytes
private fun nonceToBytes(nonce: Long): ByteArray {
    val bytes = ByteArray(12)
    for (i in 0..7) {
        bytes[4 + i] = (nonce shr (8 * i)).toByte()
    }
    return bytes
}

object ChaChaPoly : CipherFunction {
    override fun encrypt(key: ByteArray, nonce: Long, ad: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        val spec = javax.crypto.spec.IvParameterSpec(nonceToBytes(nonce))
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), spec)
        cipher.updateAAD(ad)
        return cipher.doFinal(plaintext)
    }

    override fun decrypt(key: ByteArray, nonce: Long, ad: ByteArray, ciphertext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        val spec = javax.crypto.spec.IvParameterSpec(nonceToBytes(nonce))
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), spec)
        cipher.updateAAD(ad)
        return cipher.doFinal(ciphertext)
    }
}

object AESGCM : CipherFunction {
    override fun encrypt(key: ByteArray, nonce: Long, ad: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonceToBytes(nonce)))
        cipher.updateAAD(ad)
        return cipher.doFinal(plaintext)
    }

    override fun decrypt(key: ByteArray, nonce: Long, ad: ByteArray, ciphertext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonceToBytes(nonce)))
        cipher.updateAAD(ad)
        return cipher.doFinal(ciphertext)
    }
}

object SHA256Hash : HashFunction {
    override val hashLen = 32
    override val blockLen = 64

    override fun hash(data: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(data)
    }

    override fun hmacHash(key: ByteArray, data: ByteArray): ByteArray {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }
}

object SHA512Hash : HashFunction {
    override val hashLen = 64
    override val blockLen = 128

    override fun hash(data: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-512").digest(data)
    }

    override fun hmacHash(key: ByteArray, data: ByteArray): ByteArray {
        val mac = javax.crypto.Mac.getInstance("HmacSHA512")
        mac.init(SecretKeySpec(key, "HmacSHA512"))
        return mac.doFinal(data)
    }
}

object Blake2bHash : HashFunction {
    override val hashLen = 64
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

object Blake2sHash : HashFunction {
    override val hashLen = 32
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
