import XCTest
@testable import NoiseProtocol

final class CipherStateHardeningTests: XCTestCase {

    func testMACFailurePermanentlyInvalidatesCipherState() throws {
        let alice = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_SHA256", role: .initiator)
        let bob = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_SHA256", role: .responder)
        let _ = try bob.readMessage(try alice.writeMessage())
        let _ = try alice.readMessage(try bob.writeMessage())
        let sender = try alice.split().sender
        let receiver = try bob.split().receiver

        let ct = try sender.encryptWithAd(Data(), plaintext: Data("hello".utf8))
        var tampered = Data(ct)
        tampered[tampered.startIndex] ^= 0xFF

        do {
            let _ = try receiver.decryptWithAd(Data(), ciphertext: tampered)
            XCTFail("Expected decryptionFailed")
        } catch let e as NoiseError {
            XCTAssertEqual(e, .decryptionFailed)
        }

        let ct2 = try sender.encryptWithAd(Data(), plaintext: Data("world".utf8))
        do {
            let _ = try receiver.decryptWithAd(Data(), ciphertext: ct2)
            XCTFail("Expected sessionInvalidated")
        } catch let e as NoiseError {
            XCTAssertEqual(e, .sessionInvalidated)
        }
    }

    func testEncryptThrowsSessionInvalidatedAfterMACFailure() throws {
        let alice = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_SHA256", role: .initiator)
        let bob = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_SHA256", role: .responder)
        let _ = try bob.readMessage(try alice.writeMessage())
        let _ = try alice.readMessage(try bob.writeMessage())
        let sender = try alice.split().sender
        let receiver = try bob.split().receiver

        let ct = try sender.encryptWithAd(Data(), plaintext: Data("hello".utf8))
        var tampered = Data(ct)
        tampered[tampered.startIndex] ^= 0xFF

        do {
            let _ = try receiver.decryptWithAd(Data(), ciphertext: tampered)
        } catch {}

        do {
            let _ = try receiver.encryptWithAd(Data(), plaintext: Data("anything".utf8))
            XCTFail("Expected sessionInvalidated")
        } catch let e as NoiseError {
            XCTAssertEqual(e, .sessionInvalidated)
        }
    }

    func testNonceExhaustionThrowsError() throws {
        let alice = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_SHA256", role: .initiator)
        let bob = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_SHA256", role: .responder)
        let _ = try bob.readMessage(try alice.writeMessage())
        let _ = try alice.readMessage(try bob.writeMessage())
        let sender = try alice.split().sender

        sender.setNonceForTesting(UInt64.max)

        do {
            let _ = try sender.encryptWithAd(Data(), plaintext: Data("hello".utf8))
            XCTFail("Expected nonceExhausted")
        } catch let e as NoiseError {
            XCTAssertEqual(e, .nonceExhausted)
        }
    }

    func testAutoRekeyTriggersBeforeNonceLimit() throws {
        let alice = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_SHA256", role: .initiator)
        let bob = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_SHA256", role: .responder)
        let _ = try bob.readMessage(try alice.writeMessage())
        let _ = try alice.readMessage(try bob.writeMessage())
        let sender = try alice.split().sender
        let receiver = try bob.split().receiver

        sender.setNonceForTesting(UInt64.max - 1)
        receiver.setNonceForTesting(UInt64.max - 1)

        let ct1 = try sender.encryptWithAd(Data(), plaintext: Data("before rekey".utf8))
        let pt1 = try receiver.decryptWithAd(Data(), ciphertext: ct1)
        XCTAssertEqual(String(data: pt1, encoding: .utf8), "before rekey")

        let ct2 = try sender.encryptWithAd(Data(), plaintext: Data("after rekey".utf8))
        let pt2 = try receiver.decryptWithAd(Data(), ciphertext: ct2)
        XCTAssertEqual(String(data: pt2, encoding: .utf8), "after rekey")

        let ct3 = try sender.encryptWithAd(Data(), plaintext: Data("still going".utf8))
        let pt3 = try receiver.decryptWithAd(Data(), ciphertext: ct3)
        XCTAssertEqual(String(data: pt3, encoding: .utf8), "still going")
    }

    func testConcurrentEncryptFrom100Threads() throws {
        let alice = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_SHA256", role: .initiator)
        let bob = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_SHA256", role: .responder)
        let _ = try bob.readMessage(try alice.writeMessage())
        let _ = try alice.readMessage(try bob.writeMessage())
        let sender = try alice.split().sender

        let threads = 100
        let messagesPerThread = 10
        let ciphertexts = NSMutableArray()
        let resultsLock = NSLock()
        let errors = NSMutableArray()
        let errorLock = NSLock()

        DispatchQueue.concurrentPerform(iterations: threads) { t in
            for i in 0..<messagesPerThread {
                do {
                    let ct = try sender.encryptWithAd(Data(), plaintext: Data("msg-\(t)-\(i)".utf8))
                    resultsLock.lock()
                    ciphertexts.add(ct)
                    resultsLock.unlock()
                } catch {
                    errorLock.lock()
                    errors.add(error)
                    errorLock.unlock()
                }
            }
        }

        XCTAssertEqual(errors.count, 0, "Errors during concurrent encrypt")
        XCTAssertEqual(ciphertexts.count, threads * messagesPerThread)
    }

    func testPrologueMismatchCausesDecryptionFailure() throws {
        let alice = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_SHA256", role: .initiator, prologue: Data("version-1".utf8))
        let bob = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_SHA256", role: .responder, prologue: Data("version-2".utf8))

        let _ = try bob.readMessage(try alice.writeMessage())
        let msg2 = try bob.writeMessage(Data("secret".utf8))
        do {
            let _ = try alice.readMessage(msg2)
            XCTFail("Expected decryptionFailed")
        } catch let e as NoiseError {
            XCTAssertEqual(e, .decryptionFailed)
        }
    }

    func testMatchingPrologueAllowsHandshake() throws {
        let prologue = Data("app-context-v1".utf8)
        let alice = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_SHA256", role: .initiator, prologue: prologue)
        let bob = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_SHA256", role: .responder, prologue: prologue)

        let _ = try bob.readMessage(try alice.writeMessage())
        let msg2 = try bob.writeMessage(Data("hello".utf8))
        let payload = try alice.readMessage(msg2)
        XCTAssertEqual(String(data: payload, encoding: .utf8), "hello")
    }
}
