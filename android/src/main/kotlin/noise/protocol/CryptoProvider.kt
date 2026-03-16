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
    fun hmacHash(key: ByteArray, data: ByteArray): ByteArray
    fun hkdf(chainingKey: ByteArray, inputKeyMaterial: ByteArray, numOutputs: Int): List<ByteArray>
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

object ChaChaPoly : CipherFunction {
    override fun encrypt(key: ByteArray, nonce: Long, ad: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        val nonceBytes = nonceToBytes(nonce)
        val spec = javax.crypto.spec.IvParameterSpec(nonceBytes)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), spec)
        cipher.updateAAD(ad)
        return cipher.doFinal(plaintext)
    }

    override fun decrypt(key: ByteArray, nonce: Long, ad: ByteArray, ciphertext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        val nonceBytes = nonceToBytes(nonce)
        val spec = javax.crypto.spec.IvParameterSpec(nonceBytes)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), spec)
        cipher.updateAAD(ad)
        return cipher.doFinal(ciphertext)
    }

    private fun nonceToBytes(nonce: Long): ByteArray {
        // Noise spec: 4 bytes zeros + 8 bytes little-endian nonce = 12 bytes
        val bytes = ByteArray(12)
        for (i in 0..7) {
            bytes[4 + i] = (nonce shr (8 * i)).toByte()
        }
        return bytes
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

    override fun hkdf(chainingKey: ByteArray, inputKeyMaterial: ByteArray, numOutputs: Int): List<ByteArray> {
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
