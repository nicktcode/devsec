import Testing
import Foundation
@testable import DevsecCore

@Suite("DocumentScanner")
struct DocumentScannerTests {

    // MARK: - Helpers

    private func makeTempFile(
        contents: String,
        filename: String = "notes.txt"
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

    @Test("Detects API key in text file")
    func detectsAPIKeyInTextFile() throws {
        let contents = """
        Meeting notes:
        - Discussed API integration
        - Temp key for testing: sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123
        - Follow up next week
        """
        let (tempDir, filePath) = try makeTempFile(contents: contents)
        defer { cleanup(tempDir) }

        let findings = DocumentScanner.scanFile(at: filePath)
        #expect(!findings.isEmpty)
        #expect(findings.contains { $0.description.contains("OpenAI") })
    }

    @Test("Detects AWS key in text file")
    func detectsAWSKeyInTextFile() throws {
        let contents = """
        AWS credentials backup:
        Access Key: AKIAIOSFODNN7EXAMPLE
        Secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
        """
        let (tempDir, filePath) = try makeTempFile(contents: contents, filename: "aws_backup.txt")
        defer { cleanup(tempDir) }

        let findings = DocumentScanner.scanFile(at: filePath)
        #expect(!findings.isEmpty)
    }

    @Test("Skips clean files with no secrets")
    func skipsCleanFiles() throws {
        let contents = """
        This is a plain text file.
        It contains no secrets.
        Just some meeting notes:
        - Task 1: Review PR
        - Task 2: Deploy to staging
        """
        let (tempDir, filePath) = try makeTempFile(contents: contents)
        defer { cleanup(tempDir) }

        let findings = DocumentScanner.scanFile(at: filePath)
        #expect(findings.isEmpty)
    }

    @Test("Detects GitHub token in document")
    func detectsGitHubToken() throws {
        let contents = "Backup token: ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        let (tempDir, filePath) = try makeTempFile(contents: contents, filename: "tokens.txt")
        defer { cleanup(tempDir) }

        let findings = DocumentScanner.scanFile(at: filePath)
        #expect(!findings.isEmpty)
        #expect(findings.contains { $0.description.contains("GitHub") })
    }

    @Test("Finding has .documents module")
    func findingHasDocumentsModule() throws {
        let contents = "key=sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123"
        let (tempDir, filePath) = try makeTempFile(contents: contents)
        defer { cleanup(tempDir) }

        let findings = DocumentScanner.scanFile(at: filePath)
        #expect(!findings.isEmpty)
        #expect(findings.allSatisfy { $0.module == .documents })
    }

    @Test("Finding ID uses doc prefix")
    func findingIDUsesDocPrefix() throws {
        let contents = "key=sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123"
        let (tempDir, filePath) = try makeTempFile(contents: contents)
        defer { cleanup(tempDir) }

        let findings = DocumentScanner.scanFile(at: filePath)
        #expect(!findings.isEmpty)
        #expect(findings.allSatisfy { $0.id.hasPrefix("doc:") })
    }

    @Test("Skips 1Password op:// references")
    func skipsOpReferences() throws {
        let contents = """
        API_KEY=op://vault/openai/key
        DB_URL=op://vault/postgres/connection
        """
        let (tempDir, filePath) = try makeTempFile(contents: contents, filename: "config.txt")
        defer { cleanup(tempDir) }

        let findings = DocumentScanner.scanFile(at: filePath)
        #expect(findings.isEmpty)
    }

    @Test("DocumentScanner module property returns .documents")
    func scannerModuleProperty() {
        let scanner = DocumentScanner()
        #expect(scanner.module == .documents)
    }

    @Test("Returns empty array for non-existent file")
    func returnsEmptyForNonExistentFile() {
        let findings = DocumentScanner.scanFile(at: "/tmp/nonexistent_\(UUID().uuidString).txt")
        #expect(findings.isEmpty)
    }
}
