import XCTest
@testable import NoiseProtocol

final class X448Tests: XCTestCase {

    func testScalarMultRFC7748Vector1() {
        let scalar = hex("3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3")
        let u = hex("06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086")
        let result = X448_.scalarMult(k: scalar, u: u)
        XCTAssertEqual(toHex(result), "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f")
    }

    func testScalarMultRFC7748Vector2() {
        let scalar = hex("203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f")
        let u = hex("0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db")
        let result = X448_.scalarMult(k: scalar, u: u)
        XCTAssertEqual(toHex(result), "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d")
    }

    func testDHKeyAgreementRFC7748() {
        var basePoint = Data(count: 56)
        basePoint[0] = 5

        let alicePriv = hex("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b")
        let alicePub = X448_.scalarMult(k: alicePriv, u: basePoint)
        XCTAssertEqual(toHex(alicePub), "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0")

        let bobPriv = hex("1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d")
        let bobPub = X448_.scalarMult(k: bobPriv, u: basePoint)
        XCTAssertEqual(toHex(bobPub), "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609")

        let sharedAlice = X448_.scalarMult(k: alicePriv, u: bobPub)
        let sharedBob = X448_.scalarMult(k: bobPriv, u: alicePub)
        let expectedShared = "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d"
        XCTAssertEqual(toHex(sharedAlice), expectedShared)
        XCTAssertEqual(toHex(sharedBob), expectedShared)
    }

    func testNoiseNN448ChaChaPolySHA256() throws {
        var basePoint = Data(count: 56)
        basePoint[0] = 5
        let prologue = hex("4a6f686e2047616c74")

        let initPriv = hex("7fd26c8b8a0d5c98c85ff9ca1d7bc66d78578b9f2c4c170850748b27992767e6ea6cc9992a561c9d19dfc342e260c280ef4f3f9b8f879d4e")
        let initPub = X448_.scalarMult(k: initPriv, u: basePoint)
        let respPriv = hex("3facf7503ebee252465689f1d4e3b1dd219639ef9de4ffd6049d6d71a0f62126840febb99042421ce12af6626d98d9170260390fbc8399a5")
        let respPub = X448_.scalarMult(k: respPriv, u: basePoint)

        let initiator = try NoiseSession(
            protocolName: "Noise_NN_448_ChaChaPoly_SHA256",
            role: .initiator,
            prologue: prologue,
            localEphemeral: KeyPair(privateKey: initPriv, publicKey: initPub)
        )
        let responder = try NoiseSession(
            protocolName: "Noise_NN_448_ChaChaPoly_SHA256",
            role: .responder,
            prologue: prologue,
            localEphemeral: KeyPair(privateKey: respPriv, publicKey: respPub)
        )

        let msg1 = try initiator.writeMessage(hex("4c756477696720766f6e204d69736573"))
        XCTAssertEqual(toHex(msg1), "6cfcb98ae6b1bc5659cadc595bf664e17094404eae6b45fde6fc40ca937d1dbe1464cb66eb21fdbaa487cd0d11d6dce5aa07b8219bfdc49a4c756477696720766f6e204d69736573")
        try responder.readMessage(msg1)

        let msg2 = try responder.writeMessage(hex("4d757272617920526f746862617264"))
        XCTAssertEqual(toHex(msg2), "f7eb9a09468f9564819de07ada77a6cf5d5eacd84682067538bf2c4e4c905e5cc35cc3ff41241e47ae3bd296477a236ef185e5a8a0f18d65e5542247f888a7287c99e43a2b0a95bd6080d248cf2b6d9f9b05e2563f6f07")
        try initiator.readMessage(msg2)

        let (initTransport, respTransport) = (try initiator.split(), try responder.split())

        let t1 = try initTransport.sender.encryptWithAd(Data(), plaintext: hex("462e20412e20486179656b"))
        XCTAssertEqual(toHex(t1), "b8004e4570dbf47915c337816d44cc5f63d3622ea7932dbbffbbcb")

        let t2 = try respTransport.sender.encryptWithAd(Data(), plaintext: hex("4361726c204d656e676572"))
        XCTAssertEqual(toHex(t2), "651507604443049e8d21f7e9a0e49b67c770b8f3ec208fb4e4f030")
    }

    // MARK: - Helpers

    private func hex(_ str: String) -> Data {
        var data = Data()
        var i = str.startIndex
        while i < str.endIndex {
            let end = str.index(i, offsetBy: 2)
            data.append(UInt8(str[i..<end], radix: 16)!)
            i = end
        }
        return data
    }

    private func toHex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}
