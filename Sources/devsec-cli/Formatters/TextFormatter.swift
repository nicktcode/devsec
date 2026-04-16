import Foundation
import DevsecCore

// MARK: - TextFormatter

enum TextFormatter {

    static func format(_ result: FullScanResult) -> String {
        var lines: [String] = []

        // Header
        lines.append("devsec v0.1.0 -- scan complete")
        lines.append(String(repeating: "=", count: 60))
        lines.append("")

        // Module summary with dot leaders
        let moduleOrder: [ScanModule] = [.env, .history, .ssh, .documents, .aiTools, .credentialFiles]
        for module in moduleOrder {
            let matchingResult = result.results.first { $0.module == module }
            let count = matchingResult?.findings.count ?? 0
            let duration = matchingResult?.duration ?? 0
            let label = module.rawValue
            let countStr = "\(count) finding\(count == 1 ? "" : "s") (\(String(format: "%.2f", duration))s)"
            let dotCount = max(1, 50 - label.count - countStr.count)
            let dots = String(repeating: ".", count: dotCount)
            lines.append("  \(label)\(dots)\(countStr)")
        }

        lines.append("")
        lines.append(String(repeating: "-", count: 60))

        // Counts summary
        let total = result.findings.count
        let parts = [
            "total: \(total)",
            "critical: \(result.criticalCount)",
            "high: \(result.highCount)",
            "medium: \(result.mediumCount)",
            "low: \(result.lowCount)",
            "new: \(result.newCount)",
        ]
        lines.append(parts.joined(separator: "  "))
        lines.append(String(repeating: "-", count: 60))
        lines.append("")

        if result.findings.isEmpty {
            lines.append("No findings. Your machine looks clean.")
        } else {
            // Each finding
            for finding in result.findings {
                let severityTag = "[\(finding.severity.rawValue.uppercased())]"
                let newTag = finding.isNew ? " [NEW]" : ""
                lines.append("\(severityTag)\(newTag) \(finding.description)")

                // Path and line
                if let path = finding.filePath {
                    let locationStr: String
                    if let line = finding.lineNumber {
                        locationStr = "\(path):\(line)"
                    } else {
                        locationStr = path
                    }
                    lines.append("  Location : \(locationStr)")
                }

                // Secret preview
                if !finding.secretPreview.isEmpty {
                    lines.append("  Preview  : \(finding.secretPreview)")
                }

                // Risk levels
                lines.append("  Git risk : \(finding.gitRisk.rawValue)  Local risk: \(finding.localRisk.rawValue)")

                // Recommendation
                if !finding.recommendation.isEmpty {
                    lines.append("  Fix      : \(finding.recommendation)")
                }

                // Finding ID
                lines.append("  ID       : \(finding.id)")
                lines.append("")
            }
        }

        lines.append(String(repeating: "-", count: 60))
        lines.append(String(format: "Scan completed in %.2fs", result.totalDuration))
        lines.append("")
        lines.append("Tip: whitelist a finding with: devsec whitelist add <id>")

        return lines.joined(separator: "\n")
    }
}
