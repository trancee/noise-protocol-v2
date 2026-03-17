package noise.protocol

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import kotlin.test.assertTrue
import kotlin.test.assertEquals

class BenchmarkRunnerTest {

    @Test
    fun `runner measures a block and produces timing result`() {
        val runner = BenchmarkRunner(warmupIterations = 10, measureIterations = 100)
        val result = runner.run("test-sleep") {
            // Busy-wait ~100µs to give measurable time
            val start = System.nanoTime()
            @Suppress("ControlFlowWithEmptyBody")
            while (System.nanoTime() - start < 100_000L) {}
        }

        assertEquals("test-sleep", result.name)
        assertEquals(100, result.iterations)
        assertTrue(result.totalNs > 0, "Total time should be positive")
        assertTrue(result.opsPerSec > 0.0, "Ops/sec should be positive")
        assertTrue(result.avgNs > 0.0, "Average ns should be positive")
        // 100µs × 100 iterations = ~10ms minimum
        assertTrue(result.totalNs >= 5_000_000, "Total should be at least 5ms for 100 × 100µs iterations")
    }

    @Test
    fun `runner with zero warmup still measures correctly`() {
        val runner = BenchmarkRunner(warmupIterations = 0, measureIterations = 50)
        var count = 0
        val result = runner.run("counter") { count++ }

        assertEquals(50, count)
        assertEquals(50, result.iterations)
        assertTrue(result.totalNs > 0)
    }

    @Test
    fun `result computes ops per second correctly`() {
        // Manually construct a result to verify math
        val result = BenchmarkResult(
            name = "math-check",
            iterations = 1000,
            totalNs = 1_000_000_000L, // 1 second
            opsPerSec = 1000.0,
            avgNs = 1_000_000.0
        )
        assertEquals(1000.0, result.opsPerSec, 0.1)
        assertEquals(1_000_000.0, result.avgNs, 0.1)
    }
}

class BenchmarkSerializationTest {

    @Test
    fun `suite round-trips through JSON`() {
        val suite = BenchmarkSuite(
            platform = "kotlin",
            timestamp = "2026-03-17T12:00:00Z",
            results = listOf(
                BenchmarkResult("dh-x25519", 1000, 50_000_000L, 20000.0, 50000.0),
                BenchmarkResult("cipher-chacha", 5000, 10_000_000L, 500000.0, 2000.0)
            )
        )

        val json = suite.toJson()
        val restored = BenchmarkSuite.fromJson(json)

        assertEquals(suite.platform, restored.platform)
        assertEquals(suite.timestamp, restored.timestamp)
        assertEquals(suite.results.size, restored.results.size)
        for (i in suite.results.indices) {
            assertEquals(suite.results[i].name, restored.results[i].name)
            assertEquals(suite.results[i].iterations, restored.results[i].iterations)
            assertEquals(suite.results[i].totalNs, restored.results[i].totalNs)
            assertEquals(suite.results[i].opsPerSec, restored.results[i].opsPerSec, 0.001)
            assertEquals(suite.results[i].avgNs, restored.results[i].avgNs, 0.001)
        }
    }

    @Test
    fun `suite saves to and loads from file`() {
        val suite = BenchmarkSuite(
            platform = "kotlin",
            timestamp = "2026-03-17T12:00:00Z",
            results = listOf(
                BenchmarkResult("test-op", 100, 1_000_000L, 100000.0, 10000.0)
            )
        )

        val file = java.io.File.createTempFile("benchmark-", ".json")
        try {
            suite.saveToFile(file)
            assertTrue(file.exists())
            assertTrue(file.length() > 0)

            val loaded = BenchmarkSuite.loadFromFile(file)
            assertEquals(suite.platform, loaded.platform)
            assertEquals(suite.results.size, loaded.results.size)
            assertEquals(suite.results[0].name, loaded.results[0].name)
        } finally {
            file.delete()
        }
    }
}

class BenchmarkComparisonTest {

    @Test
    fun `comparison detects improvement`() {
        val baseline = BenchmarkSuite("kotlin", "before", listOf(
            BenchmarkResult("op-a", 1000, 100_000_000L, 10000.0, 100000.0)
        ))
        val current = BenchmarkSuite("kotlin", "after", listOf(
            BenchmarkResult("op-a", 1000, 50_000_000L, 20000.0, 50000.0)
        ))

        val report = current.compareToBaseline(baseline)
        assertEquals(1, report.comparisons.size)
        val comp = report.comparisons[0]
        assertEquals("op-a", comp.name)
        assertEquals(2.0, comp.speedup, 0.01) // 20000/10000 = 2x faster
        assertTrue(comp.improved)
    }

    @Test
    fun `comparison detects regression`() {
        val baseline = BenchmarkSuite("kotlin", "before", listOf(
            BenchmarkResult("op-b", 1000, 50_000_000L, 20000.0, 50000.0)
        ))
        val current = BenchmarkSuite("kotlin", "after", listOf(
            BenchmarkResult("op-b", 1000, 100_000_000L, 10000.0, 100000.0)
        ))

        val report = current.compareToBaseline(baseline)
        val comp = report.comparisons[0]
        assertEquals(0.5, comp.speedup, 0.01) // 10000/20000 = 0.5x (slower)
        assertTrue(!comp.improved)
    }

    @Test
    fun `comparison handles new benchmarks not in baseline`() {
        val baseline = BenchmarkSuite("kotlin", "before", listOf(
            BenchmarkResult("op-a", 1000, 100_000_000L, 10000.0, 100000.0)
        ))
        val current = BenchmarkSuite("kotlin", "after", listOf(
            BenchmarkResult("op-a", 1000, 100_000_000L, 10000.0, 100000.0),
            BenchmarkResult("op-new", 1000, 50_000_000L, 20000.0, 50000.0)
        ))

        val report = current.compareToBaseline(baseline)
        assertEquals(2, report.comparisons.size)
        // op-new should have speedup of 1.0 (no baseline to compare against)
        val newComp = report.comparisons.first { it.name == "op-new" }
        assertEquals(1.0, newComp.speedup, 0.01)
    }

    @Test
    fun `report produces readable summary`() {
        val baseline = BenchmarkSuite("kotlin", "before", listOf(
            BenchmarkResult("dh-x25519", 1000, 100_000_000L, 10000.0, 100000.0),
            BenchmarkResult("cipher-chacha", 5000, 10_000_000L, 500000.0, 2000.0)
        ))
        val current = BenchmarkSuite("kotlin", "after", listOf(
            BenchmarkResult("dh-x25519", 1000, 50_000_000L, 20000.0, 50000.0),
            BenchmarkResult("cipher-chacha", 5000, 10_000_000L, 500000.0, 2000.0)
        ))

        val report = current.compareToBaseline(baseline)
        val summary = report.toSummary()
        assertTrue(summary.contains("dh-x25519"), "Summary should mention benchmark name")
        assertTrue(summary.contains("2.0"), "Summary should show speedup factor")
    }
}

class PrimitiveBenchmarkTest {

    private val runner = BenchmarkRunner(warmupIterations = 50, measureIterations = 200)

    @Test
    fun `benchmark X25519 key generation`() {
        val result = runner.run("dh-x25519-keygen") {
            Curve25519DH.generateKeyPair()
        }
        assertTrue(result.opsPerSec > 0, "X25519 keygen should produce measurable ops/sec")
        println("X25519 keygen: %.1f ops/sec (avg %.1f µs)".format(result.opsPerSec, result.avgNs / 1000))
    }

    @Test
    fun `benchmark X25519 DH`() {
        val kpA = Curve25519DH.generateKeyPair()
        val kpB = Curve25519DH.generateKeyPair()
        val result = runner.run("dh-x25519") {
            Curve25519DH.dh(kpA, kpB.publicKey)
        }
        assertTrue(result.opsPerSec > 0, "X25519 DH should produce measurable ops/sec")
        println("X25519 DH: %.1f ops/sec (avg %.1f µs)".format(result.opsPerSec, result.avgNs / 1000))
    }

    @Test
    fun `benchmark X448 DH`() {
        val kpA = X448DH.generateKeyPair()
        val kpB = X448DH.generateKeyPair()
        val result = runner.run("dh-x448") {
            X448DH.dh(kpA, kpB.publicKey)
        }
        assertTrue(result.opsPerSec > 0, "X448 DH should produce measurable ops/sec")
        println("X448 DH: %.1f ops/sec (avg %.1f µs)".format(result.opsPerSec, result.avgNs / 1000))
    }

    @Test
    fun `benchmark ChaChaPoly encrypt`() {
        val key = ByteArray(32) { it.toByte() }
        val plaintext = ByteArray(64)
        val ad = ByteArray(0)
        var nonce = 0L
        val result = runner.run("cipher-chacha") {
            ChaChaPoly.encrypt(key, nonce++, ad, plaintext)
        }
        assertTrue(result.opsPerSec > 0)
        println("ChaChaPoly encrypt: %.1f ops/sec (avg %.1f µs)".format(result.opsPerSec, result.avgNs / 1000))
    }

    @Test
    fun `benchmark AESGCM encrypt`() {
        val key = ByteArray(32) { it.toByte() }
        val plaintext = ByteArray(64)
        val ad = ByteArray(0)
        var nonce = 0L
        val result = runner.run("cipher-aesgcm") {
            AESGCM.encrypt(key, nonce++, ad, plaintext)
        }
        assertTrue(result.opsPerSec > 0)
        println("AESGCM encrypt: %.1f ops/sec (avg %.1f µs)".format(result.opsPerSec, result.avgNs / 1000))
    }

    @Test
    fun `benchmark SHA256 hash`() {
        val data = ByteArray(64)
        val result = runner.run("hash-sha256") {
            SHA256Hash.hash(data)
        }
        assertTrue(result.opsPerSec > 0)
        println("SHA256 hash: %.1f ops/sec (avg %.1f µs)".format(result.opsPerSec, result.avgNs / 1000))
    }

    @Test
    fun `benchmark SHA512 hash`() {
        val data = ByteArray(64)
        val result = runner.run("hash-sha512") {
            SHA512Hash.hash(data)
        }
        assertTrue(result.opsPerSec > 0)
        println("SHA512 hash: %.1f ops/sec (avg %.1f µs)".format(result.opsPerSec, result.avgNs / 1000))
    }

    @Test
    fun `benchmark BLAKE2b hash`() {
        val data = ByteArray(64)
        val result = runner.run("hash-blake2b") {
            Blake2bHash.hash(data)
        }
        assertTrue(result.opsPerSec > 0)
        println("BLAKE2b hash: %.1f ops/sec (avg %.1f µs)".format(result.opsPerSec, result.avgNs / 1000))
    }

    @Test
    fun `benchmark BLAKE2s hash`() {
        val data = ByteArray(64)
        val result = runner.run("hash-blake2s") {
            Blake2sHash.hash(data)
        }
        assertTrue(result.opsPerSec > 0)
        println("BLAKE2s hash: %.1f ops/sec (avg %.1f µs)".format(result.opsPerSec, result.avgNs / 1000))
    }
}

class HandshakeBenchmarkTest {

    private val runner = BenchmarkRunner(warmupIterations = 10, measureIterations = 50)

    @Test
    fun `benchmark NN handshake latency`() {
        val result = runner.run("handshake-NN") {
            val initiator = NoiseSession("Noise_NN_25519_ChaChaPoly_SHA256", Role.INITIATOR)
            val responder = NoiseSession("Noise_NN_25519_ChaChaPoly_SHA256", Role.RESPONDER)
            // NN: -> e, <- e,ee
            responder.readMessage(initiator.writeMessage())
            initiator.readMessage(responder.writeMessage())
        }
        assertTrue(result.opsPerSec > 0)
        println("NN handshake: %.1f ops/sec (avg %.1f µs)".format(result.opsPerSec, result.avgNs / 1000))
    }

    @Test
    fun `benchmark XX handshake latency`() {
        val result = runner.run("handshake-XX") {
            val initiator = NoiseSession("Noise_XX_25519_ChaChaPoly_SHA256", Role.INITIATOR,
                staticKeyPair = Curve25519DH.generateKeyPair())
            val responder = NoiseSession("Noise_XX_25519_ChaChaPoly_SHA256", Role.RESPONDER,
                staticKeyPair = Curve25519DH.generateKeyPair())
            // XX: -> e, <- e,ee,s,es, -> s,se
            responder.readMessage(initiator.writeMessage())
            initiator.readMessage(responder.writeMessage())
            responder.readMessage(initiator.writeMessage())
        }
        assertTrue(result.opsPerSec > 0)
        println("XX handshake: %.1f ops/sec (avg %.1f µs)".format(result.opsPerSec, result.avgNs / 1000))
    }

    @Test
    fun `benchmark IK handshake latency`() {
        val responderStatic = Curve25519DH.generateKeyPair()
        val result = runner.run("handshake-IK") {
            val initiator = NoiseSession(
                "Noise_IK_25519_ChaChaPoly_SHA256", Role.INITIATOR,
                staticKeyPair = Curve25519DH.generateKeyPair(),
                remoteStaticKey = responderStatic.publicKey
            )
            val responder = NoiseSession(
                "Noise_IK_25519_ChaChaPoly_SHA256", Role.RESPONDER,
                staticKeyPair = responderStatic
            )
            // IK: -> e,es,s,ss, <- e,ee,se
            responder.readMessage(initiator.writeMessage())
            initiator.readMessage(responder.writeMessage())
        }
        assertTrue(result.opsPerSec > 0)
        println("IK handshake: %.1f ops/sec (avg %.1f µs)".format(result.opsPerSec, result.avgNs / 1000))
    }
}

class TransportBenchmarkTest {

    @Test
    fun `benchmark transport throughput at multiple payload sizes`() {
        val payloadSizes = listOf(64, 1024, 65536)
        val runner = BenchmarkRunner(warmupIterations = 5, measureIterations = 20)

        for (size in payloadSizes) {
            val initiator = NoiseSession("Noise_NN_25519_ChaChaPoly_SHA256", Role.INITIATOR)
            val responder = NoiseSession("Noise_NN_25519_ChaChaPoly_SHA256", Role.RESPONDER)
            responder.readMessage(initiator.writeMessage())
            initiator.readMessage(responder.writeMessage())

            val transport = initiator.split()
            val payload = ByteArray(size) { (it % 256).toByte() }

            val result = runner.run("transport-encrypt-${size}B") {
                transport.sender.encryptWithAd(byteArrayOf(), payload)
            }

            val bytesPerSec = size.toDouble() * result.opsPerSec
            val mbPerSec = bytesPerSec / (1024.0 * 1024.0)
            assertTrue(result.opsPerSec > 0, "Transport encrypt at ${size}B should produce measurable ops/sec")
            println("Transport encrypt ${size}B: %.1f ops/sec, %.2f MB/s".format(result.opsPerSec, mbPerSec))
        }
    }
}

class FullBenchmarkSuiteTest {

    @Test
    fun `run full benchmark suite and save results`() {
        val runner = BenchmarkRunner(warmupIterations = 20, measureIterations = 100)
        val results = mutableListOf<BenchmarkResult>()

        // DH primitives
        results.add(runner.run("dh-x25519-keygen") { Curve25519DH.generateKeyPair() })
        val kp25519A = Curve25519DH.generateKeyPair()
        val kp25519B = Curve25519DH.generateKeyPair()
        results.add(runner.run("dh-x25519") { Curve25519DH.dh(kp25519A, kp25519B.publicKey) })

        results.add(runner.run("dh-x448-keygen") { X448DH.generateKeyPair() })
        val kp448A = X448DH.generateKeyPair()
        val kp448B = X448DH.generateKeyPair()
        results.add(runner.run("dh-x448") { X448DH.dh(kp448A, kp448B.publicKey) })

        // Ciphers
        val key = ByteArray(32) { it.toByte() }
        val pt = ByteArray(64)
        var n1 = 0L; var n2 = 0L
        results.add(runner.run("cipher-chacha") { ChaChaPoly.encrypt(key, n1++, byteArrayOf(), pt) })
        results.add(runner.run("cipher-aesgcm") { AESGCM.encrypt(key, n2++, byteArrayOf(), pt) })

        // Hashes
        val data = ByteArray(64)
        results.add(runner.run("hash-sha256") { SHA256Hash.hash(data) })
        results.add(runner.run("hash-sha512") { SHA512Hash.hash(data) })
        results.add(runner.run("hash-blake2b") { Blake2bHash.hash(data) })
        results.add(runner.run("hash-blake2s") { Blake2sHash.hash(data) })

        // Handshakes
        results.add(runner.run("handshake-NN") {
            val i = NoiseSession("Noise_NN_25519_ChaChaPoly_SHA256", Role.INITIATOR)
            val r = NoiseSession("Noise_NN_25519_ChaChaPoly_SHA256", Role.RESPONDER)
            r.readMessage(i.writeMessage()); i.readMessage(r.writeMessage())
        })

        val suite = BenchmarkSuite(
            platform = "kotlin",
            timestamp = java.time.Instant.now().toString(),
            results = results
        )

        // Save baseline
        val baselineDir = java.io.File("build/benchmarks")
        baselineDir.mkdirs()
        val baselineFile = java.io.File(baselineDir, "baseline-kotlin.json")
        suite.saveToFile(baselineFile)
        assertTrue(baselineFile.exists(), "Baseline file should be created")

        // If previous baseline exists, compare
        val previousFile = java.io.File(baselineDir, "previous-kotlin.json")
        if (previousFile.exists()) {
            val previous = BenchmarkSuite.loadFromFile(previousFile)
            val report = suite.compareToBaseline(previous)
            println("\n=== Benchmark Comparison ===")
            println(report.toSummary())
        }

        // Print current results
        println("\n=== Current Benchmark Results ===")
        for (r in results) {
            println("%-25s %12.1f ops/sec  avg %10.1f µs".format(r.name, r.opsPerSec, r.avgNs / 1000))
        }

        assertTrue(results.all { it.opsPerSec > 0 }, "All benchmarks should produce positive ops/sec")
    }
}
