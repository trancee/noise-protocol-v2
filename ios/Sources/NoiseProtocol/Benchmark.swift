import Foundation

/// The result of a single benchmark measurement.
public struct BenchmarkResult: Sendable {
    /// The name identifying this benchmark.
    public let name: String
    /// The number of iterations measured.
    public let iterations: Int
    /// The total elapsed time in nanoseconds.
    public let totalNs: Int64
    /// The computed operations per second.
    public let opsPerSec: Double
    /// The average time per operation in nanoseconds.
    public let avgNs: Double
}

/// A comparison between a baseline and current benchmark measurement.
public struct BenchmarkComparison: Sendable {
    /// The name of the benchmark being compared.
    public let name: String
    /// The baseline operations per second.
    public let baselineOpsPerSec: Double
    /// The current operations per second.
    public let currentOpsPerSec: Double
    /// The speedup ratio (current / baseline). Values > 1.0 indicate improvement.
    public let speedup: Double
    /// Whether the current result is faster than the baseline.
    public let improved: Bool
}

/// A report comparing current benchmark results against a baseline.
public struct ComparisonReport: Sendable {
    /// The individual benchmark comparisons.
    public let comparisons: [BenchmarkComparison]

    /// Formats the comparison report as a human-readable summary table.
    ///
    /// - Returns: A multi-line string with columns for baseline, current, speedup, and status.
    public func toSummary() -> String {
        var lines = [String]()
        let header = "Benchmark" + String(repeating: " ", count: 21) +
                     "       Baseline        Current    Speedup   Status"
        lines.append(header)
        lines.append(String(repeating: "-", count: 83))
        for c in comparisons {
            let status: String
            if c.speedup > 1.05 { status = "✓ FASTER" }
            else if c.speedup < 0.95 { status = "✗ SLOWER" }
            else { status = "= SAME" }
            let namePadded = c.name.padding(toLength: 30, withPad: " ", startingAt: 0)
            let line = "\(namePadded) \(String(format: "%13.1f %13.1f %9.2fx", c.baselineOpsPerSec, c.currentOpsPerSec, c.speedup)) \(status)"
            lines.append(line)
        }
        return lines.joined(separator: "\n")
    }
}

/// A collection of benchmark results with metadata, supporting JSON serialization and baseline comparison.
public struct BenchmarkSuite: Sendable {
    /// The platform identifier (e.g., OS and hardware description).
    public let platform: String
    /// The ISO 8601 timestamp when the suite was run.
    public let timestamp: String
    /// The individual benchmark results.
    public let results: [BenchmarkResult]

    /// Serializes the suite to a JSON string.
    ///
    /// - Returns: A formatted JSON string containing all results and metadata.
    public func toJson() -> String {
        var lines = [String]()
        lines.append("{")
        lines.append("  \"platform\": \"\(platform)\",")
        lines.append("  \"timestamp\": \"\(timestamp)\",")
        lines.append("  \"results\": [")
        for (i, r) in results.enumerated() {
            lines.append("    {")
            lines.append("      \"name\": \"\(r.name)\",")
            lines.append("      \"iterations\": \(r.iterations),")
            lines.append("      \"totalNs\": \(r.totalNs),")
            lines.append("      \"opsPerSec\": \(r.opsPerSec),")
            lines.append("      \"avgNs\": \(r.avgNs)")
            lines.append("    }" + (i < results.count - 1 ? "," : ""))
        }
        lines.append("  ]")
        lines.append("}")
        return lines.joined(separator: "\n")
    }

    /// Saves the benchmark suite as JSON to the specified file URL.
    ///
    /// - Parameter url: The file URL to write the JSON data to.
    /// - Throws: An error if the file cannot be written.
    public func saveToFile(_ url: URL) throws {
        try toJson().write(to: url, atomically: true, encoding: .utf8)
    }

    /// Loads a benchmark suite from a JSON file.
    ///
    /// - Parameter url: The file URL to read.
    /// - Returns: A deserialized `BenchmarkSuite`.
    /// - Throws: An error if the file cannot be read.
    public static func loadFromFile(_ url: URL) throws -> BenchmarkSuite {
        let json = try String(contentsOf: url, encoding: .utf8)
        return fromJson(json)
    }

    /// Parses a benchmark suite from a JSON string.
    ///
    /// - Parameter json: The JSON string to parse.
    /// - Returns: A deserialized `BenchmarkSuite`.
    public static func fromJson(_ json: String) -> BenchmarkSuite {
        let platform = json.extractString("platform")
        let timestamp = json.extractString("timestamp")

        var results = [BenchmarkResult]()
        guard let resultsStart = json.range(of: "\"results\":") else { return BenchmarkSuite(platform: platform, timestamp: timestamp, results: []) }
        let afterResults = String(json[resultsStart.upperBound...])
        guard let arrayStart = afterResults.firstIndex(of: "["),
              let arrayEnd = afterResults.lastIndex(of: "]") else { return BenchmarkSuite(platform: platform, timestamp: timestamp, results: []) }

        let arrayContent = String(afterResults[afterResults.index(after: arrayStart)..<arrayEnd])

        // Split on }...{ pattern (with optional whitespace/newlines/commas between)
        let objectStrings = arrayContent.components(separatedBy: "}")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: ",", with: "").replacingOccurrences(of: "{", with: "") }
            .filter { !$0.isEmpty }

        for obj in objectStrings {
            results.append(BenchmarkResult(
                name: obj.extractString("name"),
                iterations: obj.extractInt("iterations"),
                totalNs: obj.extractInt64("totalNs"),
                opsPerSec: obj.extractDouble("opsPerSec"),
                avgNs: obj.extractDouble("avgNs")
            ))
        }

        return BenchmarkSuite(platform: platform, timestamp: timestamp, results: results)
    }

    /// Compares this suite's results against a baseline suite.
    ///
    /// For each benchmark in this suite, finds the matching baseline result by name
    /// and computes the speedup ratio.
    ///
    /// - Parameter baseline: The baseline suite to compare against.
    /// - Returns: A ``ComparisonReport`` with per-benchmark comparisons.
    public func compareToBaseline(_ baseline: BenchmarkSuite) -> ComparisonReport {
        var baselineByName = [String: BenchmarkResult]()
        for r in baseline.results { baselineByName[r.name] = r }

        let comparisons = results.map { current -> BenchmarkComparison in
            let baseOps = baselineByName[current.name]?.opsPerSec ?? current.opsPerSec
            let speedup = baseOps > 0 ? current.opsPerSec / baseOps : 1.0
            return BenchmarkComparison(
                name: current.name,
                baselineOpsPerSec: baseOps,
                currentOpsPerSec: current.opsPerSec,
                speedup: speedup,
                improved: speedup > 1.0
            )
        }
        return ComparisonReport(comparisons: comparisons)
    }
}

/// Runs benchmark closures with configurable warmup and measurement iterations.
///
/// `BenchmarkRunner` handles the warmup phase to allow JIT and cache effects to stabilize,
/// then measures the specified number of iterations to produce accurate timing results.
public final class BenchmarkRunner: Sendable {
    /// The number of warmup iterations to run before measuring.
    public let warmupIterations: Int
    /// The number of iterations to measure for timing.
    public let measureIterations: Int

    /// Creates a new benchmark runner.
    ///
    /// - Parameters:
    ///   - warmupIterations: The number of warmup iterations (default: 100).
    ///   - measureIterations: The number of measured iterations (default: 1000).
    public init(warmupIterations: Int = 100, measureIterations: Int = 1000) {
        self.warmupIterations = warmupIterations
        self.measureIterations = measureIterations
    }

    /// Runs a benchmark with the given name and closure.
    ///
    /// Executes the warmup phase, then measures the closure for the configured number
    /// of iterations, computing total time, average time, and operations per second.
    ///
    /// - Parameters:
    ///   - name: A descriptive name for this benchmark.
    ///   - block: The closure to benchmark. Called once per iteration.
    /// - Returns: A ``BenchmarkResult`` with timing statistics.
    /// - Throws: Rethrows any error thrown by the block.
    public func run(_ name: String, block: () throws -> Void) rethrows -> BenchmarkResult {
        // Warmup
        for _ in 0..<warmupIterations { try block() }

        // Measure
        let start = DispatchTime.now()
        for _ in 0..<measureIterations { try block() }
        let end = DispatchTime.now()

        let totalNs = Int64(end.uptimeNanoseconds - start.uptimeNanoseconds)
        let avgNs = Double(totalNs) / Double(measureIterations)
        let opsPerSec = totalNs > 0 ? Double(measureIterations) / (Double(totalNs) / 1_000_000_000.0) : 0.0

        return BenchmarkResult(
            name: name,
            iterations: measureIterations,
            totalNs: totalNs,
            opsPerSec: opsPerSec,
            avgNs: avgNs
        )
    }
}

// MARK: - JSON Parsing Helpers

private extension String {
    func extractString(_ key: String) -> String {
        guard let range = self.range(of: "\"\(key)\"\\s*:\\s*\"([^\"]*?)\"", options: .regularExpression) else { return "" }
        let match = String(self[range])
        guard let valueStart = match.range(of: ": \"") else { return "" }
        let value = String(match[valueStart.upperBound...]).dropLast()
        return String(value)
    }

    func extractInt(_ key: String) -> Int {
        guard let range = self.range(of: "\"\(key)\"\\s*:\\s*(\\d+)", options: .regularExpression) else { return 0 }
        let match = String(self[range])
        guard let colonRange = match.range(of: ": ") else { return 0 }
        let numStr = match[colonRange.upperBound...].trimmingCharacters(in: .whitespaces)
        return Int(numStr) ?? 0
    }

    func extractInt64(_ key: String) -> Int64 {
        guard let range = self.range(of: "\"\(key)\"\\s*:\\s*(\\d+)", options: .regularExpression) else { return 0 }
        let match = String(self[range])
        guard let colonRange = match.range(of: ": ") else { return 0 }
        let numStr = match[colonRange.upperBound...].trimmingCharacters(in: .whitespaces)
        return Int64(numStr) ?? 0
    }

    func extractDouble(_ key: String) -> Double {
        guard let range = self.range(of: "\"\(key)\"\\s*:\\s*([\\d.eE+-]+)", options: .regularExpression) else { return 0 }
        let match = String(self[range])
        guard let colonRange = match.range(of: ": ") else { return 0 }
        let numStr = match[colonRange.upperBound...].trimmingCharacters(in: .whitespaces)
        return Double(numStr) ?? 0
    }
}
