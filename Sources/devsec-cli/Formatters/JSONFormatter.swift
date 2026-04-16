import Foundation
import DevsecCore

// MARK: - JSONFormatter

enum JSONFormatter {

    // MARK: - Output Shape

    private struct JSONOutput: Encodable {
        let version: String
        let totalFindings: Int
        let newFindings: Int
        let criticalCount: Int
        let highCount: Int
        let mediumCount: Int
        let lowCount: Int
        let duration: Double
        let findings: [JSONFinding]
    }

    private struct JSONFinding: Encodable {
        let id: String
        let module: String
        let severity: String
        let gitRisk: String
        let localRisk: String
        let filePath: String?
        let lineNumber: Int?
        let description: String
        let secretPreview: String
        let recommendation: String
        let isNew: Bool
    }

    // MARK: - Format

    static func format(_ result: FullScanResult) -> String {
        let jsonFindings = result.findings.map { f in
            JSONFinding(
                id: f.id,
                module: f.module.rawValue,
                severity: f.severity.rawValue,
                gitRisk: f.gitRisk.rawValue,
                localRisk: f.localRisk.rawValue,
                filePath: f.filePath,
                lineNumber: f.lineNumber,
                description: f.description,
                secretPreview: f.secretPreview,
                recommendation: f.recommendation,
                isNew: f.isNew
            )
        }

        let output = JSONOutput(
            version: "0.1.0",
            totalFindings: result.findings.count,
            newFindings: result.newCount,
            criticalCount: result.criticalCount,
            highCount: result.highCount,
            mediumCount: result.mediumCount,
            lowCount: result.lowCount,
            duration: result.totalDuration,
            findings: jsonFindings
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]

        guard let data = try? encoder.encode(output),
              let json = String(data: data, encoding: .utf8) else {
            return "{\"error\": \"encoding failed\"}"
        }

        return json
    }
}
