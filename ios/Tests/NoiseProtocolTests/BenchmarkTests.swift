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

// MARK: - Full Benchmark Suite

final class FullBenchmarkSuiteTests: XCTestCase {

    func testRunFullBenchmarkSuiteAndSaveResults() throws {
        let runner = BenchmarkRunner(warmupIterations: 20, measureIterations: 100)
        let slowRunner = BenchmarkRunner(warmupIterations: 2, measureIterations: 10)
        var results = [BenchmarkResult]()

        // DH primitives
        let dh25519 = Curve25519DH()
        results.append(runner.run("dh-x25519-keygen") { _ = dh25519.generateKeyPair() })
        let kp25519A = dh25519.generateKeyPair()
        let kp25519B = dh25519.generateKeyPair()
        results.append(try runner.run("dh-x25519") { _ = try dh25519.dh(keyPair: kp25519A, publicKey: kp25519B.publicKey) })

        let dh448 = X448DH_()
        results.append(slowRunner.run("dh-x448-keygen") { _ = dh448.generateKeyPair() })
        let kp448A = dh448.generateKeyPair()
        let kp448B = dh448.generateKeyPair()
        results.append(try slowRunner.run("dh-x448") { _ = try dh448.dh(keyPair: kp448A, publicKey: kp448B.publicKey) })

        // Ciphers
        let chacha = ChaChaPoly_()
        let aesgcm = AESGCM_()
        let key = Data(repeating: 0x42, count: 32)
        let plaintext = Data(repeating: 0, count: 64)
        let ad = Data()
        var n1: UInt64 = 0; var n2: UInt64 = 0
        results.append(try runner.run("cipher-chacha") { _ = try chacha.encrypt(key: key, nonce: n1, ad: ad, plaintext: plaintext); n1 += 1 })
        results.append(try runner.run("cipher-aesgcm") { _ = try aesgcm.encrypt(key: key, nonce: n2, ad: ad, plaintext: plaintext); n2 += 1 })

        // Hashes
        let sha256 = SHA256Hash_(); let sha512 = SHA512Hash_()
        let blake2b = Blake2bHash_(); let blake2s = Blake2sHash_()
        let data = Data(repeating: 0, count: 64)
        results.append(runner.run("hash-sha256") { _ = sha256.hash(data) })
        results.append(runner.run("hash-sha512") { _ = sha512.hash(data) })
        results.append(runner.run("hash-blake2b") { _ = blake2b.hash(data) })
        results.append(runner.run("hash-blake2s") { _ = blake2s.hash(data) })

        // Handshakes
        results.append(try runner.run("handshake-NN") {
            let i = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_SHA256", role: .initiator)
            let r = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_SHA256", role: .responder)
            _ = try r.readMessage(i.writeMessage())
            _ = try i.readMessage(r.writeMessage())
        })

        let suite = BenchmarkSuite(
            platform: "swift",
            timestamp: ISO8601DateFormatter().string(from: Date()),
            results: results
        )

        // Save baseline
        let baselineDir = URL(fileURLWithPath: ".build/benchmarks", isDirectory: true)
        try FileManager.default.createDirectory(at: baselineDir, withIntermediateDirectories: true)
        let baselineFile = baselineDir.appendingPathComponent("baseline-swift.json")
        try suite.saveToFile(baselineFile)
        XCTAssertTrue(FileManager.default.fileExists(atPath: baselineFile.path))

        // Print results table
        let nameW = max(results.map(\.name.count).max() ?? 9, 9)
        print("\n⚡ Swift Benchmark Results\n")
        print("| \("Benchmark".padding(toLength: nameW, withPad: " ", startingAt: 0)) |    ops/sec |  avg latency |")
        print("|\(String(repeating: "-", count: nameW + 2))|-----------:|-------------:|")
        for r in results {
            let latency: String
            if r.avgNs < 1_000 {
                latency = "\(Int(r.avgNs)) ns"
            } else if r.avgNs < 1_000_000 {
                latency = String(format: "%.1f µs", r.avgNs / 1_000)
            } else {
                latency = String(format: "%.1f ms", r.avgNs / 1_000_000)
            }
            let opsCol = String(format: "%9d", Int(r.opsPerSec))
            let latCol = String(repeating: " ", count: max(0, 12 - latency.count)) + latency
            print("| \(r.name.padding(toLength: nameW, withPad: " ", startingAt: 0)) | \(opsCol) | \(latCol) |")
        }
        print()

        XCTAssertTrue(results.allSatisfy { $0.opsPerSec > 0 }, "All benchmarks should produce positive ops/sec")
    }
}
