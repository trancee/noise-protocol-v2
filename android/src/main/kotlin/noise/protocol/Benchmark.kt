package noise.protocol

/**
 * Holds the result of a single benchmark measurement.
 *
 * @property name Human-readable name of the benchmark.
 * @property iterations Number of iterations executed during the measurement phase.
 * @property totalNs Total elapsed wall-clock time in nanoseconds.
 * @property opsPerSec Throughput expressed as operations per second.
 * @property avgNs Average time per operation in nanoseconds.
 */
data class BenchmarkResult(
    val name: String,
    val iterations: Int,
    val totalNs: Long,
    val opsPerSec: Double,
    val avgNs: Double
)

/**
 * Compares a single benchmark between a baseline and the current run.
 *
 * @property name The benchmark name.
 * @property baselineOpsPerSec Baseline throughput (ops/sec).
 * @property currentOpsPerSec Current throughput (ops/sec).
 * @property speedup Ratio of current to baseline throughput (`> 1.0` means faster).
 * @property improved `true` if [speedup] is greater than `1.0`.
 */
data class BenchmarkComparison(
    val name: String,
    val baselineOpsPerSec: Double,
    val currentOpsPerSec: Double,
    val speedup: Double,
    val improved: Boolean
)

/**
 * A report comparing a set of benchmark results against a baseline.
 *
 * @property comparisons The individual benchmark comparisons.
 */
data class ComparisonReport(
    val comparisons: List<BenchmarkComparison>
) {
    /**
     * Formats the comparison data as a human-readable ASCII table with columns
     * for benchmark name, baseline ops/sec, current ops/sec, speedup ratio,
     * and a status indicator (FASTER / SLOWER / SAME).
     *
     * @return The formatted summary string.
     */
    fun toSummary(): String {
        val sb = StringBuilder()
        sb.appendLine("%-30s %15s %15s %10s %8s".format("Benchmark", "Baseline", "Current", "Speedup", "Status"))
        sb.appendLine("-".repeat(83))
        for (c in comparisons) {
            val status = when {
                c.speedup > 1.05 -> "✓ FASTER"
                c.speedup < 0.95 -> "✗ SLOWER"
                else -> "= SAME"
            }
            sb.appendLine("%-30s %13.1f %13.1f %9.2fx %8s".format(
                c.name, c.baselineOpsPerSec, c.currentOpsPerSec, c.speedup, status
            ))
        }
        return sb.toString()
    }
}

/**
 * A collection of benchmark results for a single platform and point in time.
 *
 * Supports JSON serialization ([toJson] / [fromJson]) and comparison against
 * a baseline suite via [compareToBaseline].
 *
 * @property platform The platform identifier (e.g. `"JVM 17"`, `"Android API 34"`).
 * @property timestamp ISO 8601 timestamp of when the suite was run.
 * @property results The individual [BenchmarkResult] entries.
 * @see BenchmarkRunner
 * @see ComparisonReport
 */
data class BenchmarkSuite(
    val platform: String,
    val timestamp: String,
    val results: List<BenchmarkResult>
) {
    /**
     * Serializes this suite to a JSON string.
     *
     * @return The JSON representation.
     */
    fun toJson(): String {
        val sb = StringBuilder()
        sb.appendLine("{")
        sb.appendLine("""  "platform": "${platform.jsonEscape()}",""")
        sb.appendLine("""  "timestamp": "${timestamp.jsonEscape()}",""")
        sb.appendLine("""  "results": [""")
        results.forEachIndexed { i, r ->
            sb.appendLine("    {")
            sb.appendLine("""      "name": "${r.name.jsonEscape()}",""")
            sb.appendLine("""      "iterations": ${r.iterations},""")
            sb.appendLine("""      "totalNs": ${r.totalNs},""")
            sb.appendLine("""      "opsPerSec": ${r.opsPerSec},""")
            sb.appendLine("""      "avgNs": ${r.avgNs}""")
            sb.append("    }")
            if (i < results.size - 1) sb.appendLine(",") else sb.appendLine()
        }
        sb.appendLine("  ]")
        sb.append("}")
        return sb.toString()
    }

    /**
     * Writes the JSON serialization of this suite to a [file].
     *
     * @param file The destination file.
     */
    fun saveToFile(file: java.io.File) {
        file.writeText(toJson())
    }

    /**
     * Compares each result in this suite against the matching result (by name)
     * in the [baseline] suite and produces a [ComparisonReport].
     *
     * If a benchmark name exists in this suite but not in the [baseline],
     * the current ops/sec is used as the baseline (speedup = 1.0).
     *
     * @param baseline The baseline suite to compare against.
     * @return A [ComparisonReport] with per-benchmark speedup data.
     */
    fun compareToBaseline(baseline: BenchmarkSuite): ComparisonReport {
        val baselineByName = baseline.results.associateBy { it.name }
        val comparisons = results.map { current ->
            val base = baselineByName[current.name]
            val baseOps = base?.opsPerSec ?: current.opsPerSec
            val speedup = if (baseOps > 0) current.opsPerSec / baseOps else 1.0
            BenchmarkComparison(
                name = current.name,
                baselineOpsPerSec = baseOps,
                currentOpsPerSec = current.opsPerSec,
                speedup = speedup,
                improved = speedup > 1.0
            )
        }
        return ComparisonReport(comparisons)
    }

    companion object {
        /**
         * Deserializes a [BenchmarkSuite] from a JSON string.
         *
         * @param json The JSON string (as produced by [toJson]).
         * @return The deserialized [BenchmarkSuite].
         */
        fun fromJson(json: String): BenchmarkSuite {
            val platform = json.extractString("platform")
            val timestamp = json.extractString("timestamp")
            val results = mutableListOf<BenchmarkResult>()

            val resultsArray = json.substringAfter("\"results\":")
                .substringAfter("[").substringBeforeLast("]")
            val objects = resultsArray.split(Regex("\\}\\s*,\\s*\\{"))

            for (obj in objects) {
                val cleaned = obj.trim().removePrefix("{").removeSuffix("}")
                if (cleaned.isBlank()) continue
                results.add(
                    BenchmarkResult(
                        name = cleaned.extractString("name"),
                        iterations = cleaned.extractInt("iterations"),
                        totalNs = cleaned.extractLong("totalNs"),
                        opsPerSec = cleaned.extractDouble("opsPerSec"),
                        avgNs = cleaned.extractDouble("avgNs")
                    )
                )
            }

            return BenchmarkSuite(platform, timestamp, results)
        }

        /**
         * Loads a [BenchmarkSuite] from a JSON [file].
         *
         * @param file The source file containing JSON.
         * @return The deserialized [BenchmarkSuite].
         */
        fun loadFromFile(file: java.io.File): BenchmarkSuite = fromJson(file.readText())
    }
}

private fun String.jsonEscape(): String = replace("\\", "\\\\").replace("\"", "\\\"")

private fun String.extractString(key: String): String =
    Regex(""""$key"\s*:\s*"([^"]*?)"""").find(this)?.groupValues?.get(1) ?: ""

private fun String.extractInt(key: String): Int =
    Regex(""""$key"\s*:\s*(\d+)""").find(this)?.groupValues?.get(1)?.toInt() ?: 0

private fun String.extractLong(key: String): Long =
    Regex(""""$key"\s*:\s*(\d+)""").find(this)?.groupValues?.get(1)?.toLong() ?: 0L

private fun String.extractDouble(key: String): Double =
    Regex(""""$key"\s*:\s*([\d.E+-]+)""").find(this)?.groupValues?.get(1)?.toDouble() ?: 0.0

/**
 * Runs micro-benchmarks with a configurable warmup and measurement phase.
 *
 * The warmup phase allows the JIT compiler to optimize hotspots before
 * measurement begins.
 *
 * @param warmupIterations Number of iterations to run before measuring (default: 100).
 * @param measureIterations Number of iterations to measure (default: 1000).
 * @see BenchmarkResult
 * @see BenchmarkSuite
 */
class BenchmarkRunner(
    private val warmupIterations: Int = 100,
    private val measureIterations: Int = 1000
) {
    /**
     * Executes a benchmark: runs the warmup phase, then measures [block]
     * for [measureIterations] iterations.
     *
     * @param name A descriptive name for this benchmark.
     * @param block The code to benchmark (called once per iteration).
     * @return A [BenchmarkResult] containing timing statistics.
     */
    fun run(name: String, block: () -> Unit): BenchmarkResult {
        // Warmup phase — let JIT compile hotspots
        repeat(warmupIterations) { block() }

        // Measure phase
        val start = System.nanoTime()
        repeat(measureIterations) { block() }
        val totalNs = System.nanoTime() - start

        val avgNs = totalNs.toDouble() / measureIterations
        val opsPerSec = if (totalNs > 0) measureIterations.toDouble() / (totalNs / 1_000_000_000.0) else 0.0

        return BenchmarkResult(
            name = name,
            iterations = measureIterations,
            totalNs = totalNs,
            opsPerSec = opsPerSec,
            avgNs = avgNs
        )
    }
}
