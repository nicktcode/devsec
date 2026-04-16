import Foundation

// MARK: - HistoryScanner

/// Scans shell history files for hardcoded secrets in commands.
///
/// Shell history files can contain API keys, tokens, and passwords passed as
/// command-line arguments. These are stored in plaintext and are accessible to
/// any process with read access to the home directory.
public struct HistoryScanner: Scanner {

    public init() {}

    // MARK: - Scanner Protocol

    public var module: ScanModule { .history }

    public func scan() async throws -> ScanResult {
        let start = Date()
        let home = FileManager.default.homeDirectoryForCurrentUser.path

        // Known history file locations
        let knownPaths = [
            "\(home)/.zsh_history",
            "\(home)/.bash_history",
            "\(home)/.sh_history",
        ]

        // Discover additional history files via Spotlight glob
        let discovered = await SpotlightEngine.findFiles(matchingGlob: "*_history", searchPath: home)

        // Deduplicate
        var seen = Set<String>()
        var allPaths: [String] = []
        for path in knownPaths + discovered {
            if seen.insert(path).inserted {
                allPaths.append(path)
            }
        }

        // Only include files that actually exist
        let fm = FileManager.default
        let existingPaths = allPaths.filter { fm.fileExists(atPath: $0) }

        var allFindings: [Finding] = []
        for path in existingPaths {
            let findings = HistoryScanner.scanFile(at: path)
            allFindings.append(contentsOf: findings)
        }

        let duration = Date().timeIntervalSince(start)
        return ScanResult(module: .history, findings: allFindings, duration: duration)
    }

    // MARK: - Static File Scanner

    /// Reads a history file, strips zsh timestamps, and scans each line for secrets.
    public static func scanFile(at path: String) -> [Finding] {
        guard let contents = try? String(contentsOfFile: path, encoding: .utf8) else {
            // Try latin1 as fallback since some history files have non-UTF8 bytes
            guard let contents = try? String(contentsOfFile: path, encoding: .isoLatin1) else {
                return []
            }
            return scanLines(contents.components(separatedBy: "\n"), path: path)
        }
        return scanLines(contents.components(separatedBy: "\n"), path: path)
    }

    private static func scanLines(_ lines: [String], path: String) -> [Finding] {
        var findings: [Finding] = []

        for (index, rawLine) in lines.enumerated() {
            let lineNumber = index + 1
            let command = stripZshTimestamp(rawLine)

            guard !command.isEmpty else { continue }

            let matches = PatternDatabase.findSecrets(in: command)
            guard !matches.isEmpty else { continue }

            for match in matches {
                let findingId = "history:\(path):\(lineNumber):\(match.patternName)"

                let finding = Finding(
                    id: findingId,
                    module: .history,
                    severity: .high,
                    gitRisk: .none,
                    localRisk: .high,
                    filePath: path,
                    lineNumber: lineNumber,
                    description: "\(match.patternName) found in shell history",
                    secretPreview: PatternDatabase.maskSecret(match.matchedText),
                    recommendation: "Remove this secret from your shell history. Run: sed -i '' '\(lineNumber)d' \(path)",
                    isNew: true
                )

                findings.append(finding)
            }
        }

        return findings
    }

    // MARK: - Private Helpers

    /// Strips the zsh extended history timestamp prefix.
    /// Zsh stores entries as ": <timestamp>:<elapsed>;<command>" when EXTENDED_HISTORY is set.
    /// This function strips the prefix and returns the bare command.
    static func stripZshTimestamp(_ line: String) -> String {
        // Pattern: ": <digits>:<digits>;<rest>"
        let pattern = #"^:\s*\d+:\d+;"#
        if let range = line.range(of: pattern, options: .regularExpression) {
            return String(line[range.upperBound...])
        }
        return line
    }
}
