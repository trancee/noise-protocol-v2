package noise.protocol

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertContentEquals
import kotlin.test.assertTrue

/**
 * Tests for one-way handshake patterns (N, K, X).
 * One-way patterns have a single handshake message from initiator to responder,
 * then transport is unidirectional (initiator encrypts, responder decrypts).
 */
class OneWayPatternsTest {

    @Test
    fun `pattern N completes single-message handshake and transports data`() {
        val respStatic = Curve25519DH.generateKeyPair()

        // N: responder's static key is pre-known to initiator
        val initiator = NoiseSession(
            "Noise_N_25519_ChaChaPoly_SHA256", Role.INITIATOR,
            remoteStaticKey = respStatic.publicKey
        )
        val responder = NoiseSession(
            "Noise_N_25519_ChaChaPoly_SHA256", Role.RESPONDER,
            staticKeyPair = respStatic
        )

        // Single handshake message: → e, es
        val msg = initiator.writeMessage("Hello one-way".toByteArray())
        val payload = responder.readMessage(msg)
        assertContentEquals("Hello one-way".toByteArray(), payload)

        assertTrue(initiator.isHandshakeComplete)
        assertTrue(responder.isHandshakeComplete)

        // Transport: initiator can encrypt, responder can decrypt
        val initT = initiator.split()
        val respT = responder.split()

        val plaintext = "One-way message".toByteArray()
        val ciphertext = initT.sender.encryptWithAd(byteArrayOf(), plaintext)
        val decrypted = respT.receiver.decryptWithAd(byteArrayOf(), ciphertext)
        assertContentEquals(plaintext, decrypted)
    }

    @Test
    fun `one-way responder sender throws InvalidState`() {
        val respStatic = Curve25519DH.generateKeyPair()
        val initiator = NoiseSession(
            "Noise_N_25519_ChaChaPoly_SHA256", Role.INITIATOR,
            remoteStaticKey = respStatic.publicKey
        )
        val responder = NoiseSession(
            "Noise_N_25519_ChaChaPoly_SHA256", Role.RESPONDER,
            staticKeyPair = respStatic
        )

        responder.readMessage(initiator.writeMessage())
        val respT = responder.split()

        assertThrows<NoiseException.InvalidState> {
            respT.sender.encryptWithAd(byteArrayOf(), "should fail".toByteArray())
        }
    }

    @Test
    fun `pattern K completes with pre-shared static keys`() {
        val initStatic = Curve25519DH.generateKeyPair()
        val respStatic = Curve25519DH.generateKeyPair()

        // K: both sides know each other's static keys (pre-messages → s, ← s)
        val initiator = NoiseSession(
            "Noise_K_25519_ChaChaPoly_SHA256", Role.INITIATOR,
            staticKeyPair = initStatic, remoteStaticKey = respStatic.publicKey
        )
        val responder = NoiseSession(
            "Noise_K_25519_ChaChaPoly_SHA256", Role.RESPONDER,
            staticKeyPair = respStatic, remoteStaticKey = initStatic.publicKey
        )

        // Single message: → e, es, ss
        val msg = initiator.writeMessage("K pattern".toByteArray())
        val payload = responder.readMessage(msg)
        assertContentEquals("K pattern".toByteArray(), payload)

        assertTrue(initiator.isHandshakeComplete)
        assertTrue(responder.isHandshakeComplete)

        // Transport: initiator → responder only
        val initT = initiator.split()
        val respT = responder.split()

        val plaintext = "K transport".toByteArray()
        val ciphertext = initT.sender.encryptWithAd(byteArrayOf(), plaintext)
        val decrypted = respT.receiver.decryptWithAd(byteArrayOf(), ciphertext)
        assertContentEquals(plaintext, decrypted)

        // Reverse direction is disabled
        assertThrows<NoiseException.InvalidState> {
            respT.sender.encryptWithAd(byteArrayOf(), "nope".toByteArray())
        }
    }

    @Test
    fun `pattern X transmits initiator static and completes`() {
        val initStatic = Curve25519DH.generateKeyPair()
        val respStatic = Curve25519DH.generateKeyPair()

        // X: responder's static pre-known, initiator transmits static in handshake
        val initiator = NoiseSession(
            "Noise_X_25519_ChaChaPoly_SHA256", Role.INITIATOR,
            staticKeyPair = initStatic, remoteStaticKey = respStatic.publicKey
        )
        val responder = NoiseSession(
            "Noise_X_25519_ChaChaPoly_SHA256", Role.RESPONDER,
            staticKeyPair = respStatic
        )

        // Single message: → e, es, s, ss
        val msg = initiator.writeMessage("X pattern".toByteArray())
        val payload = responder.readMessage(msg)
        assertContentEquals("X pattern".toByteArray(), payload)

        assertTrue(initiator.isHandshakeComplete)
        assertTrue(responder.isHandshakeComplete)

        // Transport works in the forward direction
        val initT = initiator.split()
        val respT = responder.split()

        val plaintext = "X transport".toByteArray()
        val ciphertext = initT.sender.encryptWithAd(byteArrayOf(), plaintext)
        val decrypted = respT.receiver.decryptWithAd(byteArrayOf(), ciphertext)
        assertContentEquals(plaintext, decrypted)

        // Reverse is disabled
        assertThrows<NoiseException.InvalidState> {
            initT.receiver.decryptWithAd(byteArrayOf(), ByteArray(32))
        }
    }

    @Test
    fun `one-way initiator receiver throws InvalidState`() {
        val respStatic = Curve25519DH.generateKeyPair()
        val initiator = NoiseSession(
            "Noise_N_25519_ChaChaPoly_SHA256", Role.INITIATOR,
            remoteStaticKey = respStatic.publicKey
        )
        val responder = NoiseSession(
            "Noise_N_25519_ChaChaPoly_SHA256", Role.RESPONDER,
            staticKeyPair = respStatic
        )

        responder.readMessage(initiator.writeMessage())
        val initT = initiator.split()

        assertThrows<NoiseException.InvalidState> {
            initT.receiver.decryptWithAd(byteArrayOf(), ByteArray(32))
        }
    }
}
