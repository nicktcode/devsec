import Foundation

// MARK: - FindingExporter

/// Serializes a set of findings to JSON or CSV for export to external
/// tooling (spreadsheets, SIEMs, ticket systems). Kept deliberately
/// simple. one row per finding, no nested structures. so CSV users
/// can open the output in Excel / Numbers without wrangling.
///
/// Secret previews remain masked (same format as the UI); export is for
/// routing and triage, not for shipping raw credentials around.
public enum FindingExporter {

    // MARK: - JSON

    /// Pretty-printed JSON array. Stable field order via a custom
    /// encoder key strategy so diffs between exports stay readable.
    public static func exportJSON(_ findings: [Finding]) -> Data? {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601

        let rows = findings.map(ExportRow.init)
        return try? encoder.encode(rows)
    }

    // MARK: - CSV

    /// RFC 4180-ish CSV: CRLF line endings, double-quote escaping for
    /// embedded quotes/commas/newlines. Excel, Numbers, and every SIEM
    /// that accepts CSV will take this.
    public static func exportCSV(_ findings: [Finding]) -> String {
        let columns: [(String, (Finding) -> String)] = [
            ("id",             { $0.id }),
            ("module",         { $0.module.rawValue }),
            ("severity",       { $0.severity.rawValue }),
            ("gitRisk",        { $0.gitRisk.rawValue }),
            ("localRisk",      { $0.localRisk.rawValue }),
            ("filePath",       { $0.filePath ?? "" }),
            ("lineNumber",     { $0.lineNumber.map(String.init) ?? "" }),
            ("description",   { $0.description }),
            ("secretPreview",  { $0.secretPreview }),
            ("recommendation", { $0.recommendation }),
            ("isNew",          { $0.isNew ? "true" : "false" }),
        ]

        var lines: [String] = []
        lines.append(columns.map { $0.0 }.joined(separator: ","))
        for finding in findings {
            let fields = columns.map { escape($0.1(finding)) }
            lines.append(fields.joined(separator: ","))
        }
        return lines.joined(separator: "\r\n")
    }

    // MARK: - Row model

    /// Codable DTO so we don't have to make `Finding` itself Codable
    /// (its nested enums already are, but controlling the shape here
    /// lets us change wire format without touching the core type).
    private struct ExportRow: Codable {
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

        init(_ f: Finding) {
            self.id = f.id
            self.module = f.module.rawValue
            self.severity = f.severity.rawValue
            self.gitRisk = f.gitRisk.rawValue
            self.localRisk = f.localRisk.rawValue
            self.filePath = f.filePath
            self.lineNumber = f.lineNumber
            self.description = f.description
            self.secretPreview = f.secretPreview
            self.recommendation = f.recommendation
            self.isNew = f.isNew
        }
    }

    // MARK: - CSV escaping

    /// Escapes a CSV field per RFC 4180: wrap in double-quotes if the
    /// value contains a comma, a quote, CR, or LF; double up any embedded
    /// quotes. This is the escaping every spreadsheet and SIEM expects.
    private static func escape(_ value: String) -> String {
        if value.contains(",") || value.contains("\"") || value.contains("\n") || value.contains("\r") {
            let escaped = value.replacingOccurrences(of: "\"", with: "\"\"")
            return "\"\(escaped)\""
        }
        return value
    }
}
