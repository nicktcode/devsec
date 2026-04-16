import Testing
import Foundation
@testable import DevsecCore

@Suite("SpotlightEngine")
struct SpotlightEngineTests {

    // MARK: - Helpers

    private func makeTempDir() throws -> URL {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("SpotlightEngineTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        return tmp
    }

    private func removeTempDir(_ url: URL) {
        try? FileManager.default.removeItem(at: url)
    }

    // MARK: - checkHealth

    @Test("checkHealth returns a result")
    func checkHealthReturnsResult() async {
        let health = await SpotlightEngine.checkHealth()
        // checked must always be true after calling checkHealth
        #expect(health.checked == true)
        // message must be non-empty
        #expect(!health.message.isEmpty)
    }

    // MARK: - findFiles(named:)

    @Test("findFiles by filename finds file via fallback")
    func findFilesByNameFallback() async throws {
        let dir = try makeTempDir()
        defer { removeTempDir(dir) }

        let fileName = "spotlight-test-\(UUID().uuidString).txt"
        let fileURL = dir.appendingPathComponent(fileName)
        try "hello world".write(to: fileURL, atomically: true, encoding: .utf8)

        // Use fallback directly to avoid Spotlight indexing delay
        let results = await SpotlightEngine.fallbackFindFiles(named: fileName, searchPath: dir.path)
        #expect(results.contains(fileURL.path))
    }

    @Test("fallbackFindFiles by name returns matching files only")
    func fallbackFindByNameMatchesCorrectly() async throws {
        let dir = try makeTempDir()
        defer { removeTempDir(dir) }

        let targetName = "secret-key-\(UUID().uuidString).env"
        let otherName = "other-file-\(UUID().uuidString).txt"

        let targetURL = dir.appendingPathComponent(targetName)
        let otherURL = dir.appendingPathComponent(otherName)

        try "KEY=value".write(to: targetURL, atomically: true, encoding: .utf8)
        try "nothing".write(to: otherURL, atomically: true, encoding: .utf8)

        let results = await SpotlightEngine.fallbackFindFiles(named: targetName, searchPath: dir.path)
        #expect(results.contains(targetURL.path))
        #expect(!results.contains(otherURL.path))
    }

    // MARK: - findFiles(matchingGlob:)

    @Test("fallbackFindFiles by glob matches pattern")
    func fallbackFindByGlobMatchesPattern() async throws {
        let dir = try makeTempDir()
        defer { removeTempDir(dir) }

        let uniqueSuffix = UUID().uuidString
        let envFile = dir.appendingPathComponent(".env.\(uniqueSuffix)")
        let txtFile = dir.appendingPathComponent("notes-\(uniqueSuffix).txt")

        try "SECRET=abc".write(to: envFile, atomically: true, encoding: .utf8)
        try "nothing".write(to: txtFile, atomically: true, encoding: .utf8)

        let results = await SpotlightEngine.fallbackFindFiles(matchingGlob: ".env.*", searchPath: dir.path)
        #expect(results.contains(envFile.path))
        #expect(!results.contains(txtFile.path))
    }

    // MARK: - findFiles(containingText:)

    @Test("findFiles by content finds file via fallback")
    func findFilesByContentFallback() async throws {
        let dir = try makeTempDir()
        defer { removeTempDir(dir) }

        let uniqueToken = "DEVSEC_TEST_TOKEN_\(UUID().uuidString.prefix(8))"
        let fileURL = dir.appendingPathComponent("secrets.txt")
        try "api_key=\(uniqueToken)".write(to: fileURL, atomically: true, encoding: .utf8)

        let results = await SpotlightEngine.fallbackFindFiles(containingText: uniqueToken, searchPath: dir.path)
        #expect(results.contains(fileURL.path))
    }

    @Test("fallbackFindFiles by content does not return files without the text")
    func fallbackFindByContentExcludesNonMatching() async throws {
        let dir = try makeTempDir()
        defer { removeTempDir(dir) }

        let uniqueToken = "DEVSEC_UNIQUE_\(UUID().uuidString.prefix(8))"
        let matchFile = dir.appendingPathComponent("match.txt")
        let noMatchFile = dir.appendingPathComponent("nomatch.txt")

        try "contains \(uniqueToken) here".write(to: matchFile, atomically: true, encoding: .utf8)
        try "nothing special in here".write(to: noMatchFile, atomically: true, encoding: .utf8)

        let results = await SpotlightEngine.fallbackFindFiles(containingText: uniqueToken, searchPath: dir.path)
        #expect(results.contains(matchFile.path))
        #expect(!results.contains(noMatchFile.path))
    }

    // MARK: - parseLines (via observable behavior)

    @Test("findFiles returns empty array for non-existent search path")
    func findFilesEmptyForMissingPath() async {
        let results = await SpotlightEngine.fallbackFindFiles(
            named: "anything.txt",
            searchPath: "/nonexistent/path/\(UUID().uuidString)"
        )
        #expect(results.isEmpty)
    }

    // MARK: - SpotlightHealth struct properties

    @Test("SpotlightHealth struct fields are readable")
    func spotlightHealthFields() {
        let health = SpotlightEngine.SpotlightHealth(
            checked: true,
            available: true,
            message: "Indexing enabled"
        )
        #expect(health.checked == true)
        #expect(health.available == true)
        #expect(health.message == "Indexing enabled")
    }
}
