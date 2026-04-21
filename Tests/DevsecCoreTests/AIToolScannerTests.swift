import Testing
import Foundation
@testable import DevsecCore

@Suite("AIToolScanner")
struct AIToolScannerTests {

    // MARK: - Helpers

    private func makeTempConfig(
        contents: String,
        filename: String = "settings.json"
    ) throws -> (tempDir: URL, filePath: String) {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let fileURL = tempDir.appendingPathComponent(filename)
        try contents.write(to: fileURL, atomically: true, encoding: .utf8)
        return (tempDir, fileURL.path)
    }

    private func cleanup(_ tempDir: URL) {
        try? FileManager.default.removeItem(at: tempDir)
    }

    // MARK: - Secret Detection

    @Test("Detects hardcoded API key in AI tool config")
    func detectsHardcodedAPIKeyInConfig() throws {
        let contents = """
        {
          "mcpServers": {
            "openai": {
              "apiKey": "sk-proj-9gT7hP2kQ4wR8mZ5vN3jB6xF1yL0cV9bA8sW7uE4iK2oY6tM"
            }
          }
        }
        """
        let (tempDir, filePath) = try makeTempConfig(contents: contents)
        defer { cleanup(tempDir) }

        let findings = AIToolScanner.scanConfigFile(at: filePath, toolName: "Claude Code")
        #expect(!findings.isEmpty)
        #expect(findings.contains { $0.description.contains("OpenAI") })
    }

    @Test("Detects GitHub token in Cursor config")
    func detectsGitHubTokenInCursorConfig() throws {
        let contents = """
        {
          "github": {
            "token": "ghp_9gT7hP2kQ4wR8mZ5vN3jB6xF1yL0cV9bA8sW"
          }
        }
        """
        let (tempDir, filePath) = try makeTempConfig(contents: contents, filename: "mcp.json")
        defer { cleanup(tempDir) }

        let findings = AIToolScanner.scanConfigFile(at: filePath, toolName: "Cursor")
        #expect(!findings.isEmpty)
    }

    // MARK: - op:// Reference Handling

    @Test("Accepts op:// references without creating findings")
    func acceptsOpReferences() throws {
        let contents = """
        {
          "mcpServers": {
            "openai": {
              "apiKey": "op://vault/openai/api-key"
            },
            "github": {
              "token": "op://vault/github/token"
            }
          }
        }
        """
        let (tempDir, filePath) = try makeTempConfig(contents: contents)
        defer { cleanup(tempDir) }

        let findings = AIToolScanner.scanConfigFile(at: filePath, toolName: "Claude Code")
        #expect(findings.isEmpty)
    }

    @Test("Skips clean config files with no secrets")
    func skipsCleanConfig() throws {
        let contents = """
        {
          "theme": "dark",
          "fontSize": 14,
          "autoSave": true
        }
        """
        let (tempDir, filePath) = try makeTempConfig(contents: contents)
        defer { cleanup(tempDir) }

        let findings = AIToolScanner.scanConfigFile(at: filePath, toolName: "Claude Code")
        #expect(findings.isEmpty)
    }

    // MARK: - Known Tools Count

    @Test("Returns at least 10 known tool configurations")
    func returnsAtLeastTenKnownTools() {
        #expect(AIToolScanner.knownTools.count >= 10)
    }

    @Test("Known tools include major AI coding assistants")
    func knownToolsIncludeMajorAssistants() {
        let names = AIToolScanner.knownTools.map { $0.name }
        #expect(names.contains("Claude Code"))
        #expect(names.contains("Cursor"))
        #expect(names.contains("GitHub Copilot"))
        #expect(names.contains("Continue.dev"))
        #expect(names.contains("Aider"))
    }

    // MARK: - Finding Fields

    @Test("Finding has .aiTools module")
    func findingHasAIToolsModule() throws {
        let contents = """
        {"apiKey": "sk-proj-9gT7hP2kQ4wR8mZ5vN3jB6xF1yL0cV9bA8sW7uE4iK2oY6tM"}
        """
        let (tempDir, filePath) = try makeTempConfig(contents: contents)
        defer { cleanup(tempDir) }

        let findings = AIToolScanner.scanConfigFile(at: filePath, toolName: "TestTool")
        #expect(!findings.isEmpty)
        #expect(findings.allSatisfy { $0.module == .aiTools })
    }

    @Test("Finding ID uses ai prefix")
    func findingIDUsesAIPrefix() throws {
        let contents = """
        {"apiKey": "sk-proj-9gT7hP2kQ4wR8mZ5vN3jB6xF1yL0cV9bA8sW7uE4iK2oY6tM"}
        """
        let (tempDir, filePath) = try makeTempConfig(contents: contents)
        defer { cleanup(tempDir) }

        let findings = AIToolScanner.scanConfigFile(at: filePath, toolName: "TestTool")
        #expect(!findings.isEmpty)
        #expect(findings.allSatisfy { $0.id.hasPrefix("ai:") })
    }

    @Test("Finding recommendation mentions 1Password")
    func findingRecommendationMentions1Password() throws {
        let contents = """
        {"apiKey": "sk-proj-9gT7hP2kQ4wR8mZ5vN3jB6xF1yL0cV9bA8sW7uE4iK2oY6tM"}
        """
        let (tempDir, filePath) = try makeTempConfig(contents: contents)
        defer { cleanup(tempDir) }

        let findings = AIToolScanner.scanConfigFile(at: filePath, toolName: "TestTool")
        #expect(!findings.isEmpty)
        let f = try #require(findings.first)
        #expect(f.recommendation.contains("1Password") || f.recommendation.contains("op://"))
    }

    @Test("AIToolScanner module property returns .aiTools")
    func scannerModuleProperty() {
        let scanner = AIToolScanner()
        #expect(scanner.module == .aiTools)
    }
}
