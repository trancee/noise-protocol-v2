package noise.protocol

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals

class PatternParserTest {

    @Test
    fun `parse NN returns correct descriptor`() {
        val desc = PatternParser.parse("Noise_NN_25519_ChaChaPoly_SHA256")

        assertEquals("NN", desc.pattern)
        assertEquals("25519", desc.dhFunction)
        assertEquals("ChaChaPoly", desc.cipherFunction)
        assertEquals("SHA256", desc.hashFunction)
        assertEquals(emptyList<String>(), desc.initiatorPreMessages)
        assertEquals(emptyList<String>(), desc.responderPreMessages)
        assertEquals(
            listOf(listOf("e"), listOf("e", "ee")),
            desc.messagePatterns
        )
    }

    @Test
    fun `parse XX returns correct 3-message pattern`() {
        val desc = PatternParser.parse("Noise_XX_25519_ChaChaPoly_SHA256")

        assertEquals("XX", desc.pattern)
        assertEquals(emptyList<String>(), desc.initiatorPreMessages)
        assertEquals(emptyList<String>(), desc.responderPreMessages)
        assertEquals(
            listOf(
                listOf("e"),
                listOf("e", "ee", "s", "es"),
                listOf("s", "se")
            ),
            desc.messagePatterns
        )
    }

    @Test
    fun `all 12 fundamental and one-way patterns parse without error`() {
        val patterns = listOf("NN","NK","NX","KN","KK","KX","XN","XK","XX","IN","IK","IX","N","K","X")
        for (p in patterns) {
            val desc = PatternParser.parse("Noise_${p}_25519_ChaChaPoly_SHA256")
            assertEquals(p, desc.pattern, "Pattern $p should parse correctly")
            assert(desc.messagePatterns.isNotEmpty()) { "Pattern $p should have message patterns" }
        }
    }

    @Test
    fun `IK pattern has correct 2-message pattern with static key tokens`() {
        val desc = PatternParser.parse("Noise_IK_25519_ChaChaPoly_SHA256")

        assertEquals("IK", desc.pattern)
        assertEquals(emptyList<String>(), desc.initiatorPreMessages)
        assertEquals(listOf("s"), desc.responderPreMessages)
        assertEquals(
            listOf(
                listOf("e", "es", "s", "ss"),
                listOf("e", "ee", "se")
            ),
            desc.messagePatterns
        )
    }

    @Test
    fun `extracts DH cipher and hash functions from protocol name`() {
        val desc1 = PatternParser.parse("Noise_NN_448_AESGCM_BLAKE2b")
        assertEquals("448", desc1.dhFunction)
        assertEquals("AESGCM", desc1.cipherFunction)
        assertEquals("BLAKE2b", desc1.hashFunction)

        val desc2 = PatternParser.parse("Noise_NN_25519_ChaChaPoly_SHA512")
        assertEquals("25519", desc2.dhFunction)
        assertEquals("ChaChaPoly", desc2.cipherFunction)
        assertEquals("SHA512", desc2.hashFunction)
    }

    @Test
    fun `rejects malformed protocol names`() {
        assertThrows<NoiseException.InvalidPattern> { PatternParser.parse("") }
        assertThrows<NoiseException.InvalidPattern> { PatternParser.parse("Noise_NN") }
        assertThrows<NoiseException.InvalidPattern> { PatternParser.parse("Noise_ZZ_25519_ChaChaPoly_SHA256") }
        assertThrows<NoiseException.InvalidPattern> { PatternParser.parse("Noise_NN_25519_AES_SHA256") }
        assertThrows<NoiseException.InvalidPattern> { PatternParser.parse("Noise_NN_25519_ChaChaPoly_MD5") }
        assertThrows<NoiseException.InvalidPattern> { PatternParser.parse("NotNoise_NN_25519_ChaChaPoly_SHA256") }
    }

    @Test
    fun `NK pattern has responder pre-message s`() {
        val desc = PatternParser.parse("Noise_NK_25519_ChaChaPoly_SHA256")
        assertEquals(emptyList<String>(), desc.initiatorPreMessages)
        assertEquals(listOf("s"), desc.responderPreMessages)
    }

    @Test
    fun `KK pattern has both initiator and responder pre-message s`() {
        val desc = PatternParser.parse("Noise_KK_25519_ChaChaPoly_SHA256")
        assertEquals(listOf("s"), desc.initiatorPreMessages)
        assertEquals(listOf("s"), desc.responderPreMessages)
    }

    @Test
    fun `KN pattern has initiator pre-message s only`() {
        val desc = PatternParser.parse("Noise_KN_25519_ChaChaPoly_SHA256")
        assertEquals(listOf("s"), desc.initiatorPreMessages)
        assertEquals(emptyList<String>(), desc.responderPreMessages)
    }

    @Test
    fun `one-way N pattern has responder pre-message s and single message`() {
        val desc = PatternParser.parse("Noise_N_25519_ChaChaPoly_SHA256")
        assertEquals(emptyList<String>(), desc.initiatorPreMessages)
        assertEquals(listOf("s"), desc.responderPreMessages)
        assertEquals(1, desc.messagePatterns.size)
        assertEquals(listOf("e", "es"), desc.messagePatterns[0])
    }
}
