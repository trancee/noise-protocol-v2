package noise.protocol

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals

class CipherStateHardeningTest {

    private fun setupCipherStates(): Pair<CipherState, CipherState> {
        // Complete an NN handshake, return the transport cipher states
        val alice = NoiseSession("Noise_NN_25519_ChaChaPoly_SHA256", Role.INITIATOR)
        val bob = NoiseSession("Noise_NN_25519_ChaChaPoly_SHA256", Role.RESPONDER)
        val msg1 = alice.writeMessage()
        bob.readMessage(msg1)
        val msg2 = bob.writeMessage()
        alice.readMessage(msg2)
        val at = alice.split()
        val bt = bob.split()
        return at.sender to bt.receiver
    }

    @Test
    fun `MAC failure permanently invalidates CipherState`() {
        val (sender, receiver) = setupCipherStates()

        // Good encrypt
        val ct = sender.encryptWithAd(byteArrayOf(), "hello".toByteArray())

        // Tamper with ciphertext to cause MAC failure
        val tampered = ct.copyOf()
        tampered[0] = (tampered[0].toInt() xor 0xFF).toByte()

        // Decrypt should fail
        assertThrows<NoiseException.DecryptionFailed> {
            receiver.decryptWithAd(byteArrayOf(), tampered)
        }

        // Now the receiver CipherState is permanently invalidated
        // Even a valid ciphertext should fail with SessionInvalidated
        val ct2 = sender.encryptWithAd(byteArrayOf(), "world".toByteArray())
        assertThrows<NoiseException.SessionInvalidated> {
            receiver.decryptWithAd(byteArrayOf(), ct2)
        }
    }

    @Test
    fun `encrypt throws SessionInvalidated after MAC failure on decrypt`() {
        val (sender, receiver) = setupCipherStates()

        val ct = sender.encryptWithAd(byteArrayOf(), "hello".toByteArray())
        val tampered = ct.copyOf()
        tampered[0] = (tampered[0].toInt() xor 0xFF).toByte()

        assertThrows<NoiseException.DecryptionFailed> {
            receiver.decryptWithAd(byteArrayOf(), tampered)
        }

        // Encrypt also throws SessionInvalidated
        assertThrows<NoiseException.SessionInvalidated> {
            receiver.encryptWithAd(byteArrayOf(), "anything".toByteArray())
        }
    }

    @Test
    fun `nonce exhaustion throws NonceExhausted`() {
        val (sender, _) = setupCipherStates()

        sender.setNonceForTesting(Long.MAX_VALUE)

        assertThrows<NoiseException.NonceExhausted> {
            sender.encryptWithAd(byteArrayOf(), "hello".toByteArray())
        }
    }

    @Test
    fun `auto-rekey triggers before nonce limit and transport continues`() {
        val (sender, receiver) = setupCipherStates()

        // Set nonce to MAX_VALUE - 1 (one before the hard limit)
        // Without auto-rekey, the second encrypt would hit MAX_VALUE and throw NonceExhausted
        sender.setNonceForTesting(Long.MAX_VALUE - 1)
        receiver.setNonceForTesting(Long.MAX_VALUE - 1)

        // First encrypt at nonce MAX-1 should succeed and trigger auto-rekey
        val ct1 = sender.encryptWithAd(byteArrayOf(), "before rekey".toByteArray())
        val pt1 = receiver.decryptWithAd(byteArrayOf(), ct1)
        assertEquals("before rekey", String(pt1))

        // Second encrypt: without rekey this would fail with NonceExhausted
        // With rekey, nonce is reset and we continue with a new key
        val ct2 = sender.encryptWithAd(byteArrayOf(), "after rekey".toByteArray())
        val pt2 = receiver.decryptWithAd(byteArrayOf(), ct2)
        assertEquals("after rekey", String(pt2))

        // Third encrypt also works (nonce is well below limit now)
        val ct3 = sender.encryptWithAd(byteArrayOf(), "still going".toByteArray())
        val pt3 = receiver.decryptWithAd(byteArrayOf(), ct3)
        assertEquals("still going", String(pt3))
    }

    @Test
    fun `concurrent encrypt from 100 threads produces no data races`() {
        val (sender, receiver) = setupCipherStates()
        val threads = 100
        val messagesPerThread = 10
        val latch = java.util.concurrent.CountDownLatch(threads)
        val results = java.util.concurrent.ConcurrentLinkedQueue<ByteArray>()
        val errors = java.util.concurrent.ConcurrentLinkedQueue<Throwable>()

        (0 until threads).map { t ->
            Thread {
                try {
                    for (i in 0 until messagesPerThread) {
                        val ct = sender.encryptWithAd(byteArrayOf(), "msg-$t-$i".toByteArray())
                        results.add(ct)
                    }
                } catch (e: Throwable) {
                    errors.add(e)
                } finally {
                    latch.countDown()
                }
            }.apply { start() }
        }

        latch.await()

        assert(errors.isEmpty()) { "Errors during concurrent encrypt: ${errors.map { it.message }}" }
        assertEquals(threads * messagesPerThread, results.size)

        // All ciphertexts should be unique (different nonces produce different output)
        val unique = results.map { it.toList() }.toSet()
        assertEquals(threads * messagesPerThread, unique.size, "All ciphertexts should be unique")
    }

    @Test
    fun `prologue mismatch causes decryption failure`() {
        val alice = NoiseSession(
            protocolName = "Noise_NN_25519_ChaChaPoly_SHA256",
            role = Role.INITIATOR,
            prologue = "version-1".toByteArray()
        )
        val bob = NoiseSession(
            protocolName = "Noise_NN_25519_ChaChaPoly_SHA256",
            role = Role.RESPONDER,
            prologue = "version-2".toByteArray() // different!
        )

        // First message (e only, no encryption) succeeds
        val msg1 = alice.writeMessage()
        bob.readMessage(msg1)

        // Second message has encrypted payload — prologue mismatch causes MAC failure
        val msg2 = bob.writeMessage("secret".toByteArray())
        assertThrows<NoiseException.DecryptionFailed> {
            alice.readMessage(msg2)
        }
    }

    @Test
    fun `matching prologue allows successful handshake`() {
        val prologue = "app-context-v1".toByteArray()
        val alice = NoiseSession(
            protocolName = "Noise_NN_25519_ChaChaPoly_SHA256",
            role = Role.INITIATOR,
            prologue = prologue
        )
        val bob = NoiseSession(
            protocolName = "Noise_NN_25519_ChaChaPoly_SHA256",
            role = Role.RESPONDER,
            prologue = prologue
        )

        val msg1 = alice.writeMessage()
        bob.readMessage(msg1)
        val msg2 = bob.writeMessage("hello".toByteArray())
        val payload = alice.readMessage(msg2)
        assertEquals("hello", String(payload))
    }
}
