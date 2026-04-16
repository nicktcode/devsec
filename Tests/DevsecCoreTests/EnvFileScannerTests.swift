import Testing
import Foundation
@testable import DevsecCore

@Suite("EnvFileScanner")
struct EnvFileScannerTests {

    // MARK: - Helpers

    /// Creates a temporary directory, writes a .env file, and returns the file path.
    /// Returns a tuple of (tempDir, filePath) so the caller can clean up.
    private func makeTempEnv(contents: String) throws -> (tempDir: URL, filePath: String) {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let fileURL = tempDir.appendingPathComponent(".env")
        try contents.write(to: fileURL, atomically: true, encoding: .utf8)
        return (tempDir, fileURL.path)
    }

    private func cleanup(_ tempDir: URL) {
        try? FileManager.default.removeItem(at: tempDir)
    }

    // MARK: - Secret Detection

    @Test("Detects OpenAI API key in env file")
    func detectsOpenAIKey() throws {
        let contents = """
        APP_NAME=MyApp
        OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123
        DEBUG=false
        """
        let (tempDir, filePath) = try makeTempEnv(contents: contents)
        defer { cleanup(tempDir) }

        let findings = EnvFileScanner.scanFile(at: filePath)
        #expect(!findings.isEmpty)
        #expect(findings.contains { $0.description.contains("OpenAI") })
    }

    @Test("Detects multiple secrets in env file")
    func detectsMultipleSecrets() throws {
        let contents = """
        OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123
        STRIPE_SECRET_KEY=sk_test_abcdefghijklmnopqrstuvwxyz
        APP_NAME=MyApp
        """
        let (tempDir, filePath) = try makeTempEnv(contents: contents)
        defer { cleanup(tempDir) }

        let findings = EnvFileScanner.scanFile(at: filePath)
        #expect(findings.count >= 2)
        #expect(findings.contains { $0.description.contains("OpenAI") })
        #expect(findings.contains { $0.description.contains("Stripe") })
    }

    // MARK: - Skip Rules

    @Test("Skips op:// references")
    func skipsOpReferences() throws {
        let contents = """
        OPENAI_API_KEY=op://vault/openai/key
        DATABASE_URL=op://vault/db/connection
        """
        let (tempDir, filePath) = try makeTempEnv(contents: contents)
        defer { cleanup(tempDir) }

        let findings = EnvFileScanner.scanFile(at: filePath)
        #expect(findings.isEmpty)
    }

    @Test("Skips commented lines")
    func skipsCommentedLines() throws {
        let contents = """
        # OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123
        # This is a comment with STRIPE_SECRET=sk_test_abcdefghijklmnopqrstuvwxyz
        APP_NAME=MyApp
        """
        let (tempDir, filePath) = try makeTempEnv(contents: contents)
        defer { cleanup(tempDir) }

        let findings = EnvFileScanner.scanFile(at: filePath)
        #expect(findings.isEmpty)
    }

    @Test("Skips empty lines without errors")
    func skipsEmptyLines() throws {
        let contents = """
        APP_NAME=MyApp

        DEBUG=false

        REGION=us-east-1
        """
        let (tempDir, filePath) = try makeTempEnv(contents: contents)
        defer { cleanup(tempDir) }

        let findings = EnvFileScanner.scanFile(at: filePath)
        #expect(findings.isEmpty)
    }

    // MARK: - Line Number Accuracy

    @Test("Finding includes correct line number")
    func findingHasCorrectLineNumber() throws {
        let contents = """
        APP_NAME=MyApp
        DEBUG=false
        OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123
        REGION=us-east-1
        """
        let (tempDir, filePath) = try makeTempEnv(contents: contents)
        defer { cleanup(tempDir) }

        let findings = EnvFileScanner.scanFile(at: filePath)
        let openAIFindings = findings.filter { $0.description.contains("OpenAI") }
        #expect(!openAIFindings.isEmpty)
        #expect(openAIFindings.first?.lineNumber == 3)
    }

    // MARK: - Stable ID

    @Test("Finding ID is stable across multiple scans of same file")
    func findingIDIsStable() throws {
        let contents = """
        OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123
        """
        let (tempDir, filePath) = try makeTempEnv(contents: contents)
        defer { cleanup(tempDir) }

        let findings1 = EnvFileScanner.scanFile(at: filePath)
        let findings2 = EnvFileScanner.scanFile(at: filePath)

        #expect(!findings1.isEmpty)
        #expect(!findings2.isEmpty)

        // IDs must be stable (same file, same line, same pattern)
        let ids1 = Set(findings1.map { $0.id })
        let ids2 = Set(findings2.map { $0.id })
        #expect(ids1 == ids2)
    }

    // MARK: - Finding Fields

    @Test("Finding contains non-empty secret preview")
    func findingHasSecretPreview() throws {
        let contents = """
        OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123
        """
        let (tempDir, filePath) = try makeTempEnv(contents: contents)
        defer { cleanup(tempDir) }

        let findings = EnvFileScanner.scanFile(at: filePath)
        #expect(!findings.isEmpty)
        let f = try #require(findings.first)
        #expect(!f.secretPreview.isEmpty)
        // Preview should be masked (contain ****)
        #expect(f.secretPreview.contains("****"))
    }

    @Test("Finding module is .env")
    func findingModuleIsEnv() throws {
        let contents = """
        OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123
        """
        let (tempDir, filePath) = try makeTempEnv(contents: contents)
        defer { cleanup(tempDir) }

        let findings = EnvFileScanner.scanFile(at: filePath)
        #expect(!findings.isEmpty)
        #expect(findings.allSatisfy { $0.module == .env })
    }

    @Test("Finding filePath matches scanned file")
    func findingFilePathMatches() throws {
        let contents = """
        OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123
        """
        let (tempDir, filePath) = try makeTempEnv(contents: contents)
        defer { cleanup(tempDir) }

        let findings = EnvFileScanner.scanFile(at: filePath)
        #expect(!findings.isEmpty)
        #expect(findings.allSatisfy { $0.filePath == filePath })
    }

    // MARK: - Quote Stripping

    @Test("Strips double quotes from value before pattern matching")
    func stripsDoubleQuotes() throws {
        let contents = """
        OPENAI_API_KEY="sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123"
        """
        let (tempDir, filePath) = try makeTempEnv(contents: contents)
        defer { cleanup(tempDir) }

        let findings = EnvFileScanner.scanFile(at: filePath)
        #expect(!findings.isEmpty)
    }

    @Test("Strips single quotes from value before pattern matching")
    func stripsSingleQuotes() throws {
        let contents = """
        OPENAI_API_KEY='sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123'
        """
        let (tempDir, filePath) = try makeTempEnv(contents: contents)
        defer { cleanup(tempDir) }

        let findings = EnvFileScanner.scanFile(at: filePath)
        #expect(!findings.isEmpty)
    }

    // MARK: - EnvFileScanner module property

    @Test("Scanner module property returns .env")
    func scannerModuleProperty() {
        let scanner = EnvFileScanner()
        #expect(scanner.module == .env)
    }
}
