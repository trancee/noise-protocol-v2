package noise.protocol

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class CryptoResolverTest {

    @Test
    fun `default resolver resolves all 8 standard algorithm names`() {
        val resolver = CryptoResolver.default

        // DH functions
        val suite25519 = resolver.resolve("25519", "ChaChaPoly", "SHA256")
        assertEquals(32, suite25519.dh.dhLen)

        val suite448 = resolver.resolve("448", "ChaChaPoly", "SHA256")
        assertEquals(56, suite448.dh.dhLen)

        // Ciphers — verify they encrypt/decrypt correctly
        for (cipherName in listOf("ChaChaPoly", "AESGCM")) {
            val suite = resolver.resolve("25519", cipherName, "SHA256")
            val key = ByteArray(32) { it.toByte() }
            val plaintext = "hello".toByteArray()
            val ct = suite.cipher.encrypt(key, 0, byteArrayOf(), plaintext)
            val pt = suite.cipher.decrypt(key, 0, byteArrayOf(), ct)
            assertEquals(String(plaintext), String(pt))
        }

        // Hashes — verify hash lengths
        val sha256Suite = resolver.resolve("25519", "ChaChaPoly", "SHA256")
        assertEquals(32, sha256Suite.hash.hashLen)

        val sha512Suite = resolver.resolve("25519", "ChaChaPoly", "SHA512")
        assertEquals(64, sha512Suite.hash.hashLen)

        val blake2bSuite = resolver.resolve("25519", "ChaChaPoly", "BLAKE2b")
        assertEquals(64, blake2bSuite.hash.hashLen)

        val blake2sSuite = resolver.resolve("25519", "ChaChaPoly", "BLAKE2s")
        assertEquals(32, blake2sSuite.hash.hashLen)
    }

    @Test
    fun `resolved DH generates valid key pairs`() {
        val suite = CryptoResolver.default.resolve("25519", "ChaChaPoly", "SHA256")
        val kp = suite.dh.generateKeyPair()
        assertEquals(32, kp.publicKey.size)
        assertTrue(kp.privateKey.isNotEmpty())
    }

    @Test
    fun `unknown DH name throws InvalidPattern`() {
        val ex = assertThrows<NoiseException.InvalidPattern> {
            CryptoResolver.default.resolve("FakeDH", "ChaChaPoly", "SHA256")
        }
        assertTrue(ex.message!!.contains("FakeDH"))
    }

    @Test
    fun `unknown cipher name throws InvalidPattern`() {
        val ex = assertThrows<NoiseException.InvalidPattern> {
            CryptoResolver.default.resolve("25519", "FakeCipher", "SHA256")
        }
        assertTrue(ex.message!!.contains("FakeCipher"))
    }

    @Test
    fun `unknown hash name throws InvalidPattern`() {
        val ex = assertThrows<NoiseException.InvalidPattern> {
            CryptoResolver.default.resolve("25519", "ChaChaPoly", "FakeHash")
        }
        assertTrue(ex.message!!.contains("FakeHash"))
    }

    @Test
    fun `builder allows registering custom algorithm`() {
        // Create a custom DH that returns fixed 16-byte keys
        val fakeDH = object : DH {
            override val dhLen = 16
            override fun generateKeyPair() = KeyPair(ByteArray(16), ByteArray(16))
            override fun dh(keyPair: KeyPair, publicKey: ByteArray) = ByteArray(16)
        }

        val resolver = DefaultCryptoResolver.Builder()
            .dh("25519") { Curve25519DH }
            .dh("custom") { fakeDH }
            .cipher("ChaChaPoly") { ChaChaPoly }
            .hash("SHA256") { SHA256Hash }
            .build()

        val suite = resolver.resolve("custom", "ChaChaPoly", "SHA256")
        assertEquals(16, suite.dh.dhLen)
    }

    @Test
    fun `NoiseSession works with custom CryptoResolver`() {
        // Verify NoiseSession accepts a CryptoResolver parameter
        val resolver = CryptoResolver.default
        val initiator = NoiseSession(
            protocolName = "Noise_NN_25519_ChaChaPoly_SHA256",
            role = Role.INITIATOR,
            crypto = resolver
        )
        val responder = NoiseSession(
            protocolName = "Noise_NN_25519_ChaChaPoly_SHA256",
            role = Role.RESPONDER,
            crypto = resolver
        )

        // NN handshake works
        val msg1 = initiator.writeMessage()
        responder.readMessage(msg1)
        val msg2 = responder.writeMessage()
        initiator.readMessage(msg2)

        assertTrue(initiator.isHandshakeComplete)
        assertTrue(responder.isHandshakeComplete)
    }
}
