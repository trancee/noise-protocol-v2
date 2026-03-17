package noise.protocol

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class FallbackTest {

    @Test
    fun `XXfallback handshake completes with pre-message ephemeral`() {
        // Simulate IK → XXfallback: Alice tried IK, Bob couldn't decrypt, switches to XXfallback
        // Roles stay the same: Alice=INITIATOR, Bob=RESPONDER
        // But Bob writes first in the fallback pattern

        val aliceStatic = Curve25519DH.generateKeyPair()
        val bobStatic = Curve25519DH.generateKeyPair()
        val aliceEphemeral = Curve25519DH.generateKeyPair()

        // Alice is INITIATOR — reuses her ephemeral from the failed IK attempt
        val alice = NoiseSession(
            protocolName = "Noise_XXfallback_25519_ChaChaPoly_SHA256",
            role = Role.INITIATOR,
            staticKeyPair = aliceStatic,
            localEphemeral = aliceEphemeral
        )

        // Bob is RESPONDER — has Alice's ephemeral from the failed IK message
        val bob = NoiseSession(
            protocolName = "Noise_XXfallback_25519_ChaChaPoly_SHA256",
            role = Role.RESPONDER,
            staticKeyPair = bobStatic,
            remoteEphemeral = aliceEphemeral.publicKey
        )

        // Bob (responder) writes first message: e, ee, s, es
        val msg1 = bob.writeMessage("hello from bob".toByteArray())
        val payload1 = alice.readMessage(msg1)
        assertEquals("hello from bob", String(payload1))

        // Alice (initiator) writes second message: s, se
        val msg2 = alice.writeMessage("hello from alice".toByteArray())
        val payload2 = bob.readMessage(msg2)
        assertEquals("hello from alice", String(payload2))

        // Both handshakes complete
        assertTrue(bob.isHandshakeComplete)
        assertTrue(alice.isHandshakeComplete)

        // Transport works
        val bobTransport = bob.split()
        val aliceTransport = alice.split()

        val ct = aliceTransport.sender.encryptWithAd(byteArrayOf(), "transport test".toByteArray())
        val pt = bobTransport.receiver.decryptWithAd(byteArrayOf(), ct)
        assertEquals("transport test", String(pt))
    }

    @Test
    fun `IK failure transitions to XXfallback compound protocol`() {
        // Full Noise Pipes scenario:
        // 1. Alice tries IK to Bob with WRONG static key for Bob
        // 2. Bob can't decrypt → initiates XXfallback
        // 3. Fallback completes and transport works

        val aliceStatic = Curve25519DH.generateKeyPair()
        val bobStatic = Curve25519DH.generateKeyPair()
        val wrongBobStatic = Curve25519DH.generateKeyPair()

        // Step 1: Alice initiates IK with wrong remote static key
        val aliceIK = NoiseSession(
            protocolName = "Noise_IK_25519_ChaChaPoly_SHA256",
            role = Role.INITIATOR,
            staticKeyPair = aliceStatic,
            remoteStaticKey = wrongBobStatic.publicKey
        )
        val ikMsg = aliceIK.writeMessage("initial payload".toByteArray())

        // Step 2: Bob tries to read IK message — decryption fails
        val bobIK = NoiseSession(
            protocolName = "Noise_IK_25519_ChaChaPoly_SHA256",
            role = Role.RESPONDER,
            staticKeyPair = bobStatic
        )
        assertThrows<NoiseException.DecryptionFailed> {
            bobIK.readMessage(ikMsg)
        }

        // Step 3: Bob extracts Alice's ephemeral from the failed IK message
        // In IK, the first 32 bytes are Alice's unencrypted ephemeral public key
        val aliceEphemeralPublic = ikMsg.copyOfRange(0, 32)

        // Step 4: Bob initiates XXfallback (responder writes first)
        val bobFallback = NoiseSession(
            protocolName = "Noise_XXfallback_25519_ChaChaPoly_SHA256",
            role = Role.RESPONDER,
            staticKeyPair = bobStatic,
            remoteEphemeral = aliceEphemeralPublic
        )

        // Step 5: Alice creates her side of the fallback (reuses her IK ephemeral)
        val aliceEphemeralKeyPair = KeyPair(
            privateKey = aliceIK.getLocalEphemeralPrivateKey()!!,
            publicKey = aliceEphemeralPublic
        )
        val aliceFallback = NoiseSession(
            protocolName = "Noise_XXfallback_25519_ChaChaPoly_SHA256",
            role = Role.INITIATOR,
            staticKeyPair = aliceStatic,
            localEphemeral = aliceEphemeralKeyPair
        )

        // Step 6: Complete the fallback handshake (Bob writes first)
        val fbMsg1 = bobFallback.writeMessage()
        aliceFallback.readMessage(fbMsg1)

        val fbMsg2 = aliceFallback.writeMessage()
        bobFallback.readMessage(fbMsg2)

        assertTrue(bobFallback.isHandshakeComplete)
        assertTrue(aliceFallback.isHandshakeComplete)

        // Step 7: Transport works both directions
        val bobTransport = bobFallback.split()
        val aliceTransport = aliceFallback.split()

        val ct = aliceTransport.sender.encryptWithAd(byteArrayOf(), "fallback success".toByteArray())
        val pt = bobTransport.receiver.decryptWithAd(byteArrayOf(), ct)
        assertEquals("fallback success", String(pt))

        val ct2 = bobTransport.sender.encryptWithAd(byteArrayOf(), "bob replies".toByteArray())
        val pt2 = aliceTransport.receiver.decryptWithAd(byteArrayOf(), ct2)
        assertEquals("bob replies", String(pt2))
    }
}
