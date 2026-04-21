import Foundation

// MARK: - AIToolScanner

/// Scans AI coding tool configuration files for hardcoded secrets.
///
/// AI tools like Claude Code, Cursor, GitHub Copilot, and others store configuration
/// in well-known locations. These configs sometimes include API keys or tokens that
/// should be stored in a secret manager instead.
public struct AIToolScanner: Scanner {

    // MARK: - AIToolConfig

    public struct AIToolConfig: Sendable {
        public let name: String
        public let configPaths: [String]  // Relative to home directory

        public init(name: String, configPaths: [String]) {
            self.name = name
            self.configPaths = configPaths
        }
    }

    // MARK: - Known AI Tools

    public static let knownTools: [AIToolConfig] = [
        AIToolConfig(name: "Claude Code", configPaths: [
            ".claude/settings.json",
            ".claude/settings.local.json",
        ]),
        AIToolConfig(name: "Cursor", configPaths: [
            ".cursor/mcp.json",
        ]),
        AIToolConfig(name: "GitHub Copilot", configPaths: [
            ".config/github-copilot/hosts.json",
            ".config/github-copilot/apps.json",
        ]),
        AIToolConfig(name: "Windsurf", configPaths: [
            ".windsurf/config.json",
            ".codeium/config.json",
        ]),
        AIToolConfig(name: "Continue.dev", configPaths: [
            ".continue/config.json",
        ]),
        AIToolConfig(name: "Aider", configPaths: [
            ".aider.conf.yml",
        ]),
        AIToolConfig(name: "OpenAI Codex", configPaths: [
            ".codex/config.json",
        ]),
        AIToolConfig(name: "ChatGPT Desktop", configPaths: [
            "Library/Application Support/com.openai.chat/config.json",
        ]),
        AIToolConfig(name: "Amazon Q", configPaths: [
            ".aws/amazonq/config.json",
        ]),
        AIToolConfig(name: "Gemini CLI", configPaths: [
            ".gemini/config.json",
            ".gemini/settings.json",
        ]),
        AIToolConfig(name: "Copilot CLI", configPaths: [
            ".copilot/config.json",
        ]),
    ]

    // MARK: - Scanner Protocol

    public init() {}

    public var module: ScanModule { .aiTools }

    public func scan(onProgress: ScanProgressHandler? = nil) async throws -> ScanResult {
        let start = Date()
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let fm = FileManager.default

        var allPaths: [(path: String, toolName: String)] = []

        // Check each tool's known config paths
        onProgress?("Checking AI tool configs")
        for tool in AIToolScanner.knownTools {
            for relativePath in tool.configPaths {
                let fullPath = "\(home)/\(relativePath)"
                if fm.fileExists(atPath: fullPath) {
                    allPaths.append((path: fullPath, toolName: tool.name))
                }
            }
        }

        // Spotlight discovery for common AI config filenames
        onProgress?("Discovering MCP/CLAUDE.md files")
        let spotlightTargets = ["mcp.json", "claude_desktop_config.json", "CLAUDE.md"]
        for target in spotlightTargets {
            let found = await SpotlightEngine.findFiles(named: target, searchPath: home)
            for path in found {
                // Avoid duplicates
                if !allPaths.contains(where: { $0.path == path }) {
                    let toolName = toolNameForPath(path)
                    allPaths.append((path: path, toolName: toolName))
                }
            }
        }

        onProgress?("Found \(allPaths.count) AI config files")

        var allFindings: [Finding] = []
        var offloadedPaths: [String] = []
        for (i, entry) in allPaths.enumerated() {
            let filename = (entry.path as NSString).lastPathComponent
            let dir = ((entry.path as NSString).deletingLastPathComponent as NSString).lastPathComponent
            onProgress?("[\(i+1)/\(allPaths.count)] \(dir)/\(filename)")
            let outcome = AIToolScanner.scanConfigFileDetailed(at: entry.path, toolName: entry.toolName)
            allFindings.append(contentsOf: outcome.findings)
            if outcome.skipped == .cloudPlaceholder {
                offloadedPaths.append(entry.path)
            }
        }

        let duration = Date().timeIntervalSince(start)
        return ScanResult(
            module: .aiTools,
            findings: allFindings,
            duration: duration,
            offloadedPaths: offloadedPaths
        )
    }

    // MARK: - Static Config File Scanner

    public struct FileScanOutcome: Sendable {
        public let findings: [Finding]
        public let skipped: SafeFileReader.SkipReason?
    }

    /// Back-compat wrapper. Prefer ``scanConfigFileDetailed(at:toolName:)``.
    public static func scanConfigFile(at path: String, toolName: String) -> [Finding] {
        scanConfigFileDetailed(at: path, toolName: toolName).findings
    }

    /// Reads an AI tool config file and returns findings plus skip reason.
    /// Uses ``SafeFileReader`` so iCloud placeholders aren't materialized.
    public static func scanConfigFileDetailed(at path: String, toolName: String) -> FileScanOutcome {
        var findings: [Finding] = []
        let filename = URL(fileURLWithPath: path).lastPathComponent

        let summary = SafeFileReader.forEachLine(at: path) { line, lineNumber in
            let matches = PatternDatabase.findSecrets(in: line)
            guard !matches.isEmpty else { return }

            for match in matches {
                let preview8 = String(match.matchedText.prefix(8))
                let findingId = "ai:\(path):\(match.patternName):\(preview8)"

                let finding = Finding(
                    id: findingId,
                    module: .aiTools,
                    severity: .high,
                    gitRisk: .high,
                    localRisk: .high,
                    filePath: path,
                    lineNumber: lineNumber,
                    description: "\(match.patternName) found in \(toolName) config (\(filename))",
                    secretPreview: PatternDatabase.maskSecret(match.matchedText),
                    recommendation: "Move this secret to 1Password and reference it via op://vault/item/field in your \(toolName) configuration.",
                    isNew: true
                )

                findings.append(finding)
            }
        }

        return FileScanOutcome(findings: findings, skipped: summary.skipped)
    }

    // MARK: - Private Helpers

    private func toolNameForPath(_ path: String) -> String {
        let lower = path.lowercased()
        for tool in AIToolScanner.knownTools {
            for configPath in tool.configPaths {
                if lower.contains(configPath.lowercased()) {
                    return tool.name
                }
            }
        }
        if lower.contains("claude") { return "Claude Code" }
        if lower.contains("cursor") { return "Cursor" }
        if lower.contains("copilot") { return "GitHub Copilot" }
        if lower.contains("windsurf") || lower.contains("codeium") { return "Windsurf" }
        if lower.contains("continue") { return "Continue.dev" }
        if lower.contains("aider") { return "Aider" }
        if lower.contains("gemini") { return "Gemini CLI" }
        return "AI Tool"
    }
}
