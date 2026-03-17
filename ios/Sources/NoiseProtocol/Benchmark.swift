import Foundation

public struct BenchmarkResult: Sendable {
    public let name: String
    public let iterations: Int
    public let totalNs: Int64
    public let opsPerSec: Double
    public let avgNs: Double
}

public struct BenchmarkComparison: Sendable {
    public let name: String
    public let baselineOpsPerSec: Double
    public let currentOpsPerSec: Double
    public let speedup: Double
    public let improved: Bool
}

public struct ComparisonReport: Sendable {
    public let comparisons: [BenchmarkComparison]

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

public struct BenchmarkSuite: Sendable {
    public let platform: String
    public let timestamp: String
    public let results: [BenchmarkResult]

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

    public func saveToFile(_ url: URL) throws {
        try toJson().write(to: url, atomically: true, encoding: .utf8)
    }

    public static func loadFromFile(_ url: URL) throws -> BenchmarkSuite {
        let json = try String(contentsOf: url, encoding: .utf8)
        return fromJson(json)
    }

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

public final class BenchmarkRunner: Sendable {
    public let warmupIterations: Int
    public let measureIterations: Int

    public init(warmupIterations: Int = 100, measureIterations: Int = 1000) {
        self.warmupIterations = warmupIterations
        self.measureIterations = measureIterations
    }

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
