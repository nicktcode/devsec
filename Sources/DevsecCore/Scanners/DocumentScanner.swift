import Foundation

// MARK: - DocumentScanner

/// Scans document and text files for hardcoded secrets.
///
/// Uses Spotlight content queries from PatternDatabase plus keyword searches
/// to discover files that may contain credentials. Files handled by other
/// scanners (env files, history files, known config files) are filtered out.
public struct DocumentScanner: Scanner {

    public init() {}

    // MARK: - Scanner Protocol

    public var module: ScanModule { .documents }

    public func scan() async throws -> ScanResult {
        let start = Date()
        let home = FileManager.default.homeDirectoryForCurrentUser.path

        // Spotlight content queries from PatternDatabase
        var allPaths: [String] = []
        for query in PatternDatabase.spotlightContentQueries {
            let found = await SpotlightEngine.findFiles(containingText: query, searchPath: home)
            allPaths.append(contentsOf: found)
        }

        // Additional keyword searches
        let keywords = ["password", "passwd", "secret_key"]
        for keyword in keywords {
            let found = await SpotlightEngine.findFiles(containingText: keyword, searchPath: home)
            allPaths.append(contentsOf: found)
        }

        // Deduplicate
        var seen = Set<String>()
        var uniquePaths: [String] = []
        for path in allPaths {
            if seen.insert(path).inserted {
                uniquePaths.append(path)
            }
        }

        // Filter out files handled by other scanners
        let filteredPaths = uniquePaths.filter { !shouldSkip($0) }

        var allFindings: [Finding] = []
        for path in filteredPaths {
            let findings = DocumentScanner.scanFile(at: path)
            allFindings.append(contentsOf: findings)
        }

        let duration = Date().timeIntervalSince(start)
        return ScanResult(module: .documents, findings: allFindings, duration: duration)
    }

    // MARK: - Static File Scanner

    /// Reads a document/text file and returns findings for any secrets detected.
    public static func scanFile(at path: String) -> [Finding] {
        guard let contents = try? String(contentsOfFile: path, encoding: .utf8) else {
            return []
        }

        let matches = PatternDatabase.findSecrets(in: contents)
        guard !matches.isEmpty else { return [] }

        var findings: [Finding] = []
        for match in matches {
            let assessment = RiskClassifier.classify(
                secretValue: match.matchedText,
                filePath: path,
                isInGitignore: false
            )

            // Build an ID using first 8 chars of matched text to keep it stable
            let preview8 = String(match.matchedText.prefix(8))
            let findingId = "doc:\(path):\(match.patternName):\(preview8)"

            let filename = URL(fileURLWithPath: path).lastPathComponent
            let finding = Finding(
                id: findingId,
                module: .documents,
                severity: assessment.severity,
                gitRisk: assessment.gitRisk,
                localRisk: assessment.localRisk,
                filePath: path,
                lineNumber: nil,
                description: "\(match.patternName) found in \(filename)",
                secretPreview: PatternDatabase.maskSecret(match.matchedText),
                recommendation: assessment.recommendation,
                isNew: true
            )

            findings.append(finding)
        }

        return findings
    }

    // MARK: - Private Helpers

    /// Returns true if the file should be skipped because another scanner handles it.
    private func shouldSkip(_ path: String) -> Bool {
        let url = URL(fileURLWithPath: path)
        let filename = url.lastPathComponent.lowercased()
        let ext = url.pathExtension.lowercased()

        // Skip env files (handled by EnvFileScanner)
        if filename == ".env" || filename.hasPrefix(".env.") { return true }
        if filename.hasSuffix(".env") { return true }

        // Skip history files (handled by HistoryScanner)
        if filename.hasSuffix("_history") { return true }

        // Skip SSH keys (handled by SSHScanner)
        if ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"].contains(filename) { return true }
        if ext == "pem" { return true }

        // Skip known config files that other scanners handle
        let knownConfigs = [".netrc", ".htpasswd", "wp-config.php"]
        if knownConfigs.contains(filename) { return true }

        // Skip binary/compiled files
        let binaryExtensions = ["o", "a", "dylib", "so", "class", "jar",
                                "zip", "tar", "gz", "bz2", "xz",
                                "png", "jpg", "jpeg", "gif", "ico", "svg",
                                "mp3", "mp4", "mov", "avi",
                                "app", "framework", "bundle"]
        if binaryExtensions.contains(ext) { return true }

        return false
    }
}
