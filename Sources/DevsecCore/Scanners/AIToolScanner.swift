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

    public func scan() async throws -> ScanResult {
        let start = Date()
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let fm = FileManager.default

        var allPaths: [(path: String, toolName: String)] = []

        // Check each tool's known config paths
        for tool in AIToolScanner.knownTools {
            for relativePath in tool.configPaths {
                let fullPath = "\(home)/\(relativePath)"
                if fm.fileExists(atPath: fullPath) {
                    allPaths.append((path: fullPath, toolName: tool.name))
                }
            }
        }

        // Spotlight discovery for common AI config filenames
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

        var allFindings: [Finding] = []
        for entry in allPaths {
            let findings = AIToolScanner.scanConfigFile(at: entry.path, toolName: entry.toolName)
            allFindings.append(contentsOf: findings)
        }

        let duration = Date().timeIntervalSince(start)
        return ScanResult(module: .aiTools, findings: allFindings, duration: duration)
    }

    // MARK: - Static Config File Scanner

    /// Reads an AI tool config file and returns findings for any secrets detected.
    /// Skips files that only contain op:// references.
    public static func scanConfigFile(at path: String, toolName: String) -> [Finding] {
        guard let contents = try? String(contentsOfFile: path, encoding: .utf8) else {
            return []
        }

        // Skip if all values appear to be op:// references (properly managed)
        // We still scan: just let PatternDatabase handle op:// skipping internally
        let matches = PatternDatabase.findSecrets(in: contents)
        guard !matches.isEmpty else { return [] }

        var findings: [Finding] = []
        let filename = URL(fileURLWithPath: path).lastPathComponent

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
                lineNumber: nil,
                description: "\(match.patternName) found in \(toolName) config (\(filename))",
                secretPreview: PatternDatabase.maskSecret(match.matchedText),
                recommendation: "Move this secret to 1Password and reference it via op://vault/item/field in your \(toolName) configuration.",
                isNew: true
            )

            findings.append(finding)
        }

        return findings
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
