import XCTest
@testable import NoiseProtocol

// MARK: - BenchmarkRunner Tests

final class BenchmarkRunnerTests: XCTestCase {

    func testRunnerMeasuresBlockAndProducesTimingResult() throws {
        let runner = BenchmarkRunner(warmupIterations: 10, measureIterations: 100)
        let result = runner.run("test-busy-wait") {
            let start = DispatchTime.now()
            while DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds < 100_000 {}
        }

        XCTAssertEqual(result.name, "test-busy-wait")
        XCTAssertEqual(result.iterations, 100)
        XCTAssertGreaterThan(result.totalNs, 0)
        XCTAssertGreaterThan(result.opsPerSec, 0)
        XCTAssertGreaterThan(result.avgNs, 0)
        XCTAssertGreaterThanOrEqual(result.totalNs, 5_000_000) // 100 × 100µs ≈ 10ms min
    }

    func testRunnerWithZeroWarmup() throws {
        let runner = BenchmarkRunner(warmupIterations: 0, measureIterations: 50)
        var count = 0
        let result = runner.run("counter") { count += 1 }

        XCTAssertEqual(count, 50)
        XCTAssertEqual(result.iterations, 50)
        XCTAssertGreaterThan(result.totalNs, 0)
    }
}

// MARK: - Serialization Tests

final class BenchmarkSerializationTests: XCTestCase {

    func testSuiteRoundTripsJSON() throws {
        let suite = BenchmarkSuite(
            platform: "swift",
            timestamp: "2026-03-17T12:00:00Z",
            results: [
                BenchmarkResult(name: "dh-x25519", iterations: 1000, totalNs: 50_000_000, opsPerSec: 20000.0, avgNs: 50000.0),
                BenchmarkResult(name: "cipher-chacha", iterations: 5000, totalNs: 10_000_000, opsPerSec: 500000.0, avgNs: 2000.0),
            ]
        )

        let json = suite.toJson()
        let restored = BenchmarkSuite.fromJson(json)

        XCTAssertEqual(restored.platform, suite.platform)
        XCTAssertEqual(restored.timestamp, suite.timestamp)
        XCTAssertEqual(restored.results.count, suite.results.count)
        for i in suite.results.indices {
            XCTAssertEqual(restored.results[i].name, suite.results[i].name)
            XCTAssertEqual(restored.results[i].iterations, suite.results[i].iterations)
            XCTAssertEqual(restored.results[i].totalNs, suite.results[i].totalNs)
            XCTAssertEqual(restored.results[i].opsPerSec, suite.results[i].opsPerSec, accuracy: 0.001)
            XCTAssertEqual(restored.results[i].avgNs, suite.results[i].avgNs, accuracy: 0.001)
        }
    }

    func testSuiteSavesAndLoadsFromFile() throws {
        let suite = BenchmarkSuite(
            platform: "swift",
            timestamp: "2026-03-17T12:00:00Z",
            results: [
                BenchmarkResult(name: "test-op", iterations: 100, totalNs: 1_000_000, opsPerSec: 100000.0, avgNs: 10000.0),
            ]
        )

        let tempURL = FileManager.default.temporaryDirectory.appendingPathComponent("benchmark-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: tempURL) }

        try suite.saveToFile(tempURL)
        XCTAssertTrue(FileManager.default.fileExists(atPath: tempURL.path))

        let loaded = try BenchmarkSuite.loadFromFile(tempURL)
        XCTAssertEqual(loaded.platform, suite.platform)
        XCTAssertEqual(loaded.results.count, 1)
        XCTAssertEqual(loaded.results[0].name, "test-op")
    }
}

// MARK: - Comparison Tests

final class BenchmarkComparisonTests: XCTestCase {

    func testComparisonDetectsImprovement() throws {
        let baseline = BenchmarkSuite(platform: "swift", timestamp: "before", results: [
            BenchmarkResult(name: "op-a", iterations: 1000, totalNs: 100_000_000, opsPerSec: 10000.0, avgNs: 100000.0),
        ])
        let current = BenchmarkSuite(platform: "swift", timestamp: "after", results: [
            BenchmarkResult(name: "op-a", iterations: 1000, totalNs: 50_000_000, opsPerSec: 20000.0, avgNs: 50000.0),
        ])

        let report = current.compareToBaseline(baseline)
        XCTAssertEqual(report.comparisons.count, 1)
        XCTAssertEqual(report.comparisons[0].speedup, 2.0, accuracy: 0.01)
        XCTAssertTrue(report.comparisons[0].improved)
    }

    func testComparisonDetectsRegression() throws {
        let baseline = BenchmarkSuite(platform: "swift", timestamp: "before", results: [
            BenchmarkResult(name: "op-b", iterations: 1000, totalNs: 50_000_000, opsPerSec: 20000.0, avgNs: 50000.0),
        ])
        let current = BenchmarkSuite(platform: "swift", timestamp: "after", results: [
            BenchmarkResult(name: "op-b", iterations: 1000, totalNs: 100_000_000, opsPerSec: 10000.0, avgNs: 100000.0),
        ])

        let report = current.compareToBaseline(baseline)
        XCTAssertEqual(report.comparisons[0].speedup, 0.5, accuracy: 0.01)
        XCTAssertFalse(report.comparisons[0].improved)
    }

    func testReportProducesSummary() throws {
        let baseline = BenchmarkSuite(platform: "swift", timestamp: "before", results: [
            BenchmarkResult(name: "dh-x25519", iterations: 1000, totalNs: 100_000_000, opsPerSec: 10000.0, avgNs: 100000.0),
        ])
        let current = BenchmarkSuite(platform: "swift", timestamp: "after", results: [
            BenchmarkResult(name: "dh-x25519", iterations: 1000, totalNs: 50_000_000, opsPerSec: 20000.0, avgNs: 50000.0),
        ])

        let report = current.compareToBaseline(baseline)
        let summary = report.toSummary()
        XCTAssertTrue(summary.contains("dh-x25519"))
        XCTAssertTrue(summary.contains("2.0"))
    }
}

// MARK: - Primitive Benchmarks

final class PrimitiveBenchmarkTests: XCTestCase {

    let runner = BenchmarkRunner(warmupIterations: 50, measureIterations: 200)

    func testBenchmarkX25519KeyGen() throws {
        let dh = Curve25519DH()
        let result = runner.run("dh-x25519-keygen") { _ = dh.generateKeyPair() }
        XCTAssertGreaterThan(result.opsPerSec, 0)
        print("X25519 keygen: \(String(format: "%.1f", result.opsPerSec)) ops/sec (avg \(String(format: "%.1f", result.avgNs / 1000)) µs)")
    }

    func testBenchmarkX25519DH() throws {
        let dh = Curve25519DH()
        let kpA = dh.generateKeyPair()
        let kpB = dh.generateKeyPair()
        let result = try runner.run("dh-x25519") { _ = try dh.dh(keyPair: kpA, publicKey: kpB.publicKey) }
        XCTAssertGreaterThan(result.opsPerSec, 0)
        print("X25519 DH: \(String(format: "%.1f", result.opsPerSec)) ops/sec (avg \(String(format: "%.1f", result.avgNs / 1000)) µs)")
    }

    func testBenchmarkX448DH() throws {
        let dh = X448DH_()
        let kpA = dh.generateKeyPair()
        let kpB = dh.generateKeyPair()
        let result = try runner.run("dh-x448") { _ = try dh.dh(keyPair: kpA, publicKey: kpB.publicKey) }
        XCTAssertGreaterThan(result.opsPerSec, 0)
        print("X448 DH: \(String(format: "%.1f", result.opsPerSec)) ops/sec (avg \(String(format: "%.1f", result.avgNs / 1000)) µs)")
    }

    func testBenchmarkChaChaPolyEncrypt() throws {
        let cipher = ChaChaPoly_()
        let key = Data(repeating: 0x42, count: 32)
        let plaintext = Data(repeating: 0, count: 64)
        let ad = Data()
        var nonce: UInt64 = 0
        let result = try runner.run("cipher-chacha") {
            _ = try cipher.encrypt(key: key, nonce: nonce, ad: ad, plaintext: plaintext)
            nonce += 1
        }
        XCTAssertGreaterThan(result.opsPerSec, 0)
        print("ChaChaPoly encrypt: \(String(format: "%.1f", result.opsPerSec)) ops/sec")
    }

    func testBenchmarkAESGCMEncrypt() throws {
        let cipher = AESGCM_()
        let key = Data(repeating: 0x42, count: 32)
        let plaintext = Data(repeating: 0, count: 64)
        let ad = Data()
        var nonce: UInt64 = 0
        let result = try runner.run("cipher-aesgcm") {
            _ = try cipher.encrypt(key: key, nonce: nonce, ad: ad, plaintext: plaintext)
            nonce += 1
        }
        XCTAssertGreaterThan(result.opsPerSec, 0)
        print("AESGCM encrypt: \(String(format: "%.1f", result.opsPerSec)) ops/sec")
    }

    func testBenchmarkSHA256() throws {
        let hash = SHA256Hash_()
        let data = Data(repeating: 0, count: 64)
        let result = runner.run("hash-sha256") { _ = hash.hash(data) }
        XCTAssertGreaterThan(result.opsPerSec, 0)
        print("SHA256: \(String(format: "%.1f", result.opsPerSec)) ops/sec")
    }

    func testBenchmarkSHA512() throws {
        let hash = SHA512Hash_()
        let data = Data(repeating: 0, count: 64)
        let result = runner.run("hash-sha512") { _ = hash.hash(data) }
        XCTAssertGreaterThan(result.opsPerSec, 0)
        print("SHA512: \(String(format: "%.1f", result.opsPerSec)) ops/sec")
    }

    func testBenchmarkBLAKE2b() throws {
        let hash = Blake2bHash_()
        let data = Data(repeating: 0, count: 64)
        let result = runner.run("hash-blake2b") { _ = hash.hash(data) }
        XCTAssertGreaterThan(result.opsPerSec, 0)
        print("BLAKE2b: \(String(format: "%.1f", result.opsPerSec)) ops/sec")
    }

    func testBenchmarkBLAKE2s() throws {
        let hash = Blake2sHash_()
        let data = Data(repeating: 0, count: 64)
        let result = runner.run("hash-blake2s") { _ = hash.hash(data) }
        XCTAssertGreaterThan(result.opsPerSec, 0)
        print("BLAKE2s: \(String(format: "%.1f", result.opsPerSec)) ops/sec")
    }
}

// MARK: - Handshake Benchmarks

final class HandshakeBenchmarkTests: XCTestCase {

    let runner = BenchmarkRunner(warmupIterations: 10, measureIterations: 50)

    func testBenchmarkNNHandshake() throws {
        let result = try runner.run("handshake-NN") {
            let i = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_SHA256", role: .initiator)
            let r = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_SHA256", role: .responder)
            _ = try r.readMessage(i.writeMessage())
            _ = try i.readMessage(r.writeMessage())
        }
        XCTAssertGreaterThan(result.opsPerSec, 0)
        print("NN handshake: \(String(format: "%.1f", result.opsPerSec)) ops/sec (avg \(String(format: "%.1f", result.avgNs / 1000)) µs)")
    }

    func testBenchmarkXXHandshake() throws {
        let dh = Curve25519DH()
        let result = try runner.run("handshake-XX") {
            let i = try NoiseSession(protocolName: "Noise_XX_25519_ChaChaPoly_SHA256", role: .initiator,
                                     staticKeyPair: dh.generateKeyPair())
            let r = try NoiseSession(protocolName: "Noise_XX_25519_ChaChaPoly_SHA256", role: .responder,
                                     staticKeyPair: dh.generateKeyPair())
            _ = try r.readMessage(i.writeMessage())
            _ = try i.readMessage(r.writeMessage())
            _ = try r.readMessage(i.writeMessage())
        }
        XCTAssertGreaterThan(result.opsPerSec, 0)
        print("XX handshake: \(String(format: "%.1f", result.opsPerSec)) ops/sec (avg \(String(format: "%.1f", result.avgNs / 1000)) µs)")
    }

    func testBenchmarkIKHandshake() throws {
        let dh = Curve25519DH()
        let responderStatic = dh.generateKeyPair()
        let result = try runner.run("handshake-IK") {
            let i = try NoiseSession(protocolName: "Noise_IK_25519_ChaChaPoly_SHA256", role: .initiator,
                                     staticKeyPair: dh.generateKeyPair(),
                                     remoteStaticKey: responderStatic.publicKey)
            let r = try NoiseSession(protocolName: "Noise_IK_25519_ChaChaPoly_SHA256", role: .responder,
                                     staticKeyPair: responderStatic)
            _ = try r.readMessage(i.writeMessage())
            _ = try i.readMessage(r.writeMessage())
        }
        XCTAssertGreaterThan(result.opsPerSec, 0)
        print("IK handshake: \(String(format: "%.1f", result.opsPerSec)) ops/sec (avg \(String(format: "%.1f", result.avgNs / 1000)) µs)")
    }
}

// MARK: - Transport Benchmarks

final class TransportBenchmarkTests: XCTestCase {

    func testBenchmarkTransportThroughput() throws {
        let payloadSizes = [64, 1024, 65536]
        let runner = BenchmarkRunner(warmupIterations: 5, measureIterations: 20)

        for size in payloadSizes {
            let i = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_SHA256", role: .initiator)
            let r = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_SHA256", role: .responder)
            _ = try r.readMessage(i.writeMessage())
            _ = try i.readMessage(r.writeMessage())

            let transport = try i.split()
            let payload = Data(repeating: 0x42, count: size)

            let result = try runner.run("transport-encrypt-\(size)B") {
                _ = try transport.sender.encryptWithAd(Data(), plaintext: payload)
            }

            let mbPerSec = Double(size) * result.opsPerSec / (1024.0 * 1024.0)
            XCTAssertGreaterThan(result.opsPerSec, 0)
            print("Transport \(size)B: \(String(format: "%.1f", result.opsPerSec)) ops/sec, \(String(format: "%.2f", mbPerSec)) MB/s")
        }
    }
}
