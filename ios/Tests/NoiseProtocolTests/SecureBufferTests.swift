import XCTest
@testable import NoiseProtocol

final class SecureBufferTests: XCTestCase {

    func testAllocatesAndStoresData() {
        let data = Data([0x01, 0x02, 0x03, 0x04])
        let buf = SecureBuffer.wrap(data)
        XCTAssertEqual(buf.size, 4)
        XCTAssertEqual(buf.copyBytes(), data)
        buf.zero()
    }

    func testZeroClearsContents() {
        let data = Data(repeating: 0xFF, count: 32)
        let buf = SecureBuffer.wrap(data)
        buf.zero()
        let read = buf.copyBytes()
        XCTAssertTrue(read.allSatisfy { $0 == 0 }, "Buffer should be all zeros")
    }

    func testUseBlockAutoZerosOnExit() throws {
        let buf = SecureBuffer.wrap(Data(repeating: 0xAB, count: 32))
        let result = buf.use { b -> String in
            let bytes = b.copyBytes()
            XCTAssertTrue(bytes.contains { $0 != 0 }, "Data should be present during use")
            return "done"
        }
        XCTAssertEqual(result, "done")
    }

    func testUseBlockAutoZerosOnException() {
        let buf = SecureBuffer.wrap(Data(repeating: 0xCD, count: 32))
        do {
            let _ = try buf.use { _ -> Int in
                throw NoiseError.invalidState("oops")
            }
        } catch {
            // expected
        }
        let read = buf.copyBytes()
        XCTAssertTrue(read.allSatisfy { $0 == 0 }, "Buffer should be zeroed after exception")
    }

    func testHandshakeZeroesEphemeralAfterComplete() throws {
        let alice = try NoiseSession(
            protocolName: "Noise_NN_25519_ChaChaPoly_SHA256",
            role: .initiator
        )
        let bob = try NoiseSession(
            protocolName: "Noise_NN_25519_ChaChaPoly_SHA256",
            role: .responder
        )

        let msg1 = try alice.writeMessage()
        let _ = try bob.readMessage(msg1)
        let msg2 = try bob.writeMessage()
        let _ = try alice.readMessage(msg2)

        let ephPriv = alice.getLocalEphemeralPrivateKey()
        XCTAssertNotNil(ephPriv)

        let _ = try alice.split()
    }

    func testChainingKeyZeroedAfterHandshake() throws {
        let alice = try NoiseSession(
            protocolName: "Noise_NN_25519_ChaChaPoly_SHA256",
            role: .initiator
        )
        let bob = try NoiseSession(
            protocolName: "Noise_NN_25519_ChaChaPoly_SHA256",
            role: .responder
        )

        let msg1 = try alice.writeMessage()
        let _ = try bob.readMessage(msg1)
        let msg2 = try bob.writeMessage()
        let _ = try alice.readMessage(msg2)

        let ck = alice.getChainingKey()
        XCTAssertNotNil(ck)
        XCTAssertTrue(ck!.allSatisfy { $0 == 0 }, "Chaining key should be zeroed after handshake completes")

        let aliceTransport = try alice.split()
        let bobTransport = try bob.split()
        let ct = try aliceTransport.sender.encryptWithAd(Data(), plaintext: Data("works".utf8))
        let pt = try bobTransport.receiver.decryptWithAd(Data(), ciphertext: ct)
        XCTAssertEqual(String(data: pt, encoding: .utf8), "works")
    }
}
