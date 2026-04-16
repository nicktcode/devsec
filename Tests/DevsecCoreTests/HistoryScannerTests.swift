import Testing
import Foundation
@testable import DevsecCore

@Suite("HistoryScanner")
struct HistoryScannerTests {

    // MARK: - Helpers

    private func makeTempHistory(contents: String, filename: String = "test_history") throws -> (tempDir: URL, filePath: String) {
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

    @Test("Detects API key in shell history")
    func detectsAPIKeyInHistory() throws {
        let contents = """
        ls -la
        cd projects
        export OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123
        git status
        """
        let (tempDir, filePath) = try makeTempHistory(contents: contents)
        defer { cleanup(tempDir) }

        let findings = HistoryScanner.scanFile(at: filePath)
        #expect(!findings.isEmpty)
        #expect(findings.contains { $0.description.contains("OpenAI") })
    }

    @Test("Detects curl with bearer token in history")
    func detectsCurlWithBearerToken() throws {
        let contents = """
        curl -H "Authorization: Bearer ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" https://api.github.com/user
        echo done
        """
        let (tempDir, filePath) = try makeTempHistory(contents: contents)
        defer { cleanup(tempDir) }

        let findings = HistoryScanner.scanFile(at: filePath)
        #expect(!findings.isEmpty)
        #expect(findings.contains { $0.description.lowercased().contains("bearer") || $0.description.lowercased().contains("github") || $0.description.lowercased().contains("token") })
    }

    @Test("Does not match safe commands")
    func doesNotMatchSafeCommands() throws {
        let contents = """
        ls -la
        cd ~/projects
        git status
        npm install
        echo hello
        pwd
        cat README.md
        """
        let (tempDir, filePath) = try makeTempHistory(contents: contents)
        defer { cleanup(tempDir) }

        let findings = HistoryScanner.scanFile(at: filePath)
        #expect(findings.isEmpty)
    }

    @Test("Includes correct line number in finding")
    func includesCorrectLineNumber() throws {
        let contents = """
        ls
        cd projects
        curl -H "Authorization: Bearer sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123" https://api.example.com
        git push
        """
        let (tempDir, filePath) = try makeTempHistory(contents: contents)
        defer { cleanup(tempDir) }

        let findings = HistoryScanner.scanFile(at: filePath)
        #expect(!findings.isEmpty)
        // The secret is on line 3
        #expect(findings.contains { $0.lineNumber == 3 })
    }

    @Test("Strips zsh extended history timestamp prefix")
    func stripsZshTimestampPrefix() throws {
        // Zsh EXTENDED_HISTORY format: ": <timestamp>:<elapsed>;<command>"
        let contents = """
        : 1700000000:0;ls
        : 1700000001:0;cd projects
        : 1700000002:0;export STRIPE_KEY=sk_test_abcdefghijklmnopqrstuvwxyz
        : 1700000003:0;git status
        """
        let (tempDir, filePath) = try makeTempHistory(contents: contents)
        defer { cleanup(tempDir) }

        let findings = HistoryScanner.scanFile(at: filePath)
        #expect(!findings.isEmpty)
        #expect(findings.contains { $0.description.contains("Stripe") })
    }

    @Test("Finding has .history module")
    func findingHasHistoryModule() throws {
        let contents = "export AWS_SECRET=AKIAIOSFODNN7EXAMPLE123456\n"
        let (tempDir, filePath) = try makeTempHistory(contents: contents)
        defer { cleanup(tempDir) }

        let findings = HistoryScanner.scanFile(at: filePath)
        #expect(!findings.isEmpty)
        #expect(findings.allSatisfy { $0.module == .history })
    }

    @Test("Finding has high severity with no git risk and high local risk")
    func findingHasCorrectRiskLevels() throws {
        let contents = "curl -H 'Authorization: Bearer ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' https://api.github.com\n"
        let (tempDir, filePath) = try makeTempHistory(contents: contents)
        defer { cleanup(tempDir) }

        let findings = HistoryScanner.scanFile(at: filePath)
        #expect(!findings.isEmpty)
        let f = try #require(findings.first)
        #expect(f.severity == .high)
        #expect(f.gitRisk == .none)
        #expect(f.localRisk == .high)
    }

    @Test("Finding recommendation includes sed command")
    func findingRecommendationIncludesSedCommand() throws {
        let contents = "export OPENAI_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123\n"
        let (tempDir, filePath) = try makeTempHistory(contents: contents)
        defer { cleanup(tempDir) }

        let findings = HistoryScanner.scanFile(at: filePath)
        #expect(!findings.isEmpty)
        let f = try #require(findings.first)
        #expect(f.recommendation.contains("sed"))
    }

    @Test("Finding ID uses history prefix with path and line number")
    func findingIDUsesCorrectFormat() throws {
        let contents = "export OPENAI_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123\n"
        let (tempDir, filePath) = try makeTempHistory(contents: contents)
        defer { cleanup(tempDir) }

        let findings = HistoryScanner.scanFile(at: filePath)
        #expect(!findings.isEmpty)
        let f = try #require(findings.first)
        #expect(f.id.hasPrefix("history:"))
        #expect(f.id.contains(filePath))
        #expect(f.id.contains(":1:"))
    }

    // MARK: - Timestamp Stripping Unit Tests

    @Test("stripZshTimestamp removes zsh extended history prefix")
    func stripZshTimestampRemovesPrefix() {
        let line = ": 1700000000:0;export TOKEN=abc123"
        let result = HistoryScanner.stripZshTimestamp(line)
        #expect(result == "export TOKEN=abc123")
    }

    @Test("stripZshTimestamp leaves normal commands unchanged")
    func stripZshTimestampLeavesNormalCommandsUnchanged() {
        let line = "ls -la"
        let result = HistoryScanner.stripZshTimestamp(line)
        #expect(result == "ls -la")
    }
}
