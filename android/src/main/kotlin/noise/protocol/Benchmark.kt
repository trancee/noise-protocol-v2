package noise.protocol

data class BenchmarkResult(
    val name: String,
    val iterations: Int,
    val totalNs: Long,
    val opsPerSec: Double,
    val avgNs: Double
)

data class BenchmarkComparison(
    val name: String,
    val baselineOpsPerSec: Double,
    val currentOpsPerSec: Double,
    val speedup: Double,
    val improved: Boolean
)

data class ComparisonReport(
    val comparisons: List<BenchmarkComparison>
) {
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

data class BenchmarkSuite(
    val platform: String,
    val timestamp: String,
    val results: List<BenchmarkResult>
) {
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

    fun saveToFile(file: java.io.File) {
        file.writeText(toJson())
    }

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

class BenchmarkRunner(
    private val warmupIterations: Int = 100,
    private val measureIterations: Int = 1000
) {
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
