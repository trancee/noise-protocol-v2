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
        // Algorithm name validation is now handled by CryptoResolver, not PatternParser
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

    @Test
    fun `NoisePSK prefix sets isNoisePSK flag without modifying message patterns`() {
        val desc = PatternParser.parse("NoisePSK_NN_25519_ChaChaPoly_SHA256")

        assertEquals("NN", desc.pattern)
        assertEquals(true, desc.isNoisePSK)
        assertEquals(emptyList<Int>(), desc.pskPositions)
        // NoisePSK_ convention: no psk tokens in patterns — PSK mixed separately
        assertEquals(
            listOf(listOf("e"), listOf("e", "ee")),
            desc.messagePatterns
        )
    }

    @Test
    fun `Noise_NNpsk0 inserts psk at beginning of first message`() {
        val desc = PatternParser.parse("Noise_NNpsk0_25519_ChaChaPoly_SHA256")

        assertEquals("NN", desc.pattern)
        assertEquals(listOf(0), desc.pskPositions)
        assertEquals(
            listOf(listOf("psk", "e"), listOf("e", "ee")),
            desc.messagePatterns
        )
    }

    @Test
    fun `XXfallback converts first message to initiator pre-message`() {
        val desc = PatternParser.parse("Noise_XXfallback_25519_ChaChaPoly_SHA256")

        assertEquals("XXfallback", desc.pattern)
        assertEquals(listOf("e"), desc.initiatorPreMessages)
        assertEquals(emptyList<String>(), desc.responderPreMessages)
        assertEquals(
            listOf(
                listOf("e", "ee", "s", "es"),
                listOf("s", "se")
            ),
            desc.messagePatterns
        )
    }

    @Test
    fun `IKfallback converts first message tokens to initiator pre-messages`() {
        val desc = PatternParser.parse("Noise_IKfallback_25519_ChaChaPoly_SHA256")

        assertEquals("IKfallback", desc.pattern)
        // Original IK: initiatorPre=[], responderPre=["s"]
        // Fallback extracts e,s from first message ["e", "es", "s", "ss"] → initiatorPre gets ["e", "s"]
        assertEquals(listOf("e", "s"), desc.initiatorPreMessages)
        assertEquals(listOf("s"), desc.responderPreMessages) // unchanged
        assertEquals(
            listOf(listOf("e", "ee", "se")),
            desc.messagePatterns
        )
    }

    @Test
    fun `Noise_XXpsk0+psk3 inserts psk at two positions`() {
        val desc = PatternParser.parse("Noise_XXpsk0+psk3_25519_ChaChaPoly_SHA256")

        assertEquals("XX", desc.pattern)
        assertEquals(listOf(0, 3), desc.pskPositions)
        assertEquals(
            listOf(
                listOf("psk", "e"),
                listOf("e", "ee", "s", "es"),
                listOf("s", "se", "psk")
            ),
            desc.messagePatterns
        )
    }
}
