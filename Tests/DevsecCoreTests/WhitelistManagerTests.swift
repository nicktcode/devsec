import Testing
import Foundation
@testable import DevsecCore

@Suite("WhitelistManager")
struct WhitelistManagerTests {

    // MARK: - Helpers

    private func makeManager(configPath: String? = nil) -> WhitelistManager {
        let path = configPath ?? (NSTemporaryDirectory() + "damit-test-\(UUID().uuidString).json")
        return WhitelistManager(configPath: path)
    }

    private func makeFinding(
        id: String = "test-\(UUID().uuidString)",
        filePath: String? = nil,
        secretPreview: String = "secret"
    ) -> Finding {
        Finding(
            id: id,
            module: .env,
            severity: .high,
            gitRisk: .high,
            localRisk: .medium,
            filePath: filePath,
            description: "Test finding",
            secretPreview: secretPreview,
            recommendation: "Remove it"
        )
    }

    // MARK: - Empty whitelist

    @Test("Empty whitelist matches nothing")
    func emptyWhitelistMatchesNothing() {
        let manager = makeManager()
        let finding = makeFinding(filePath: "/some/file.env")
        #expect(manager.isFileWhitelisted("/some/file.env") == false)
        #expect(manager.isDirWhitelisted("/some/dir/file.txt") == false)
        #expect(manager.isWhitelisted(findingId: finding.id) == false)
        #expect(manager.isSafePattern("sk-realkey123") == false)
        #expect(manager.isWhitelistedByAnyRule(finding: finding) == false)
    }

    // MARK: - File whitelisting

    @Test("Whitelist file by exact path")
    func whitelistFileByPath() {
        let manager = makeManager()
        manager.addFile("/home/user/.env")
        #expect(manager.isFileWhitelisted("/home/user/.env") == true)
        #expect(manager.isFileWhitelisted("/home/user/.env.local") == false)
        #expect(manager.isFileWhitelisted("/other/.env") == false)
    }

    @Test("Whitelist file prevents duplicates")
    func whitelistFileNoDuplicates() {
        let manager = makeManager()
        manager.addFile("/some/file.txt")
        manager.addFile("/some/file.txt")
        manager.addFile("/some/file.txt")
        #expect(manager.isFileWhitelisted("/some/file.txt") == true)
    }

    // MARK: - Directory whitelisting

    @Test("Whitelist directory matches files inside")
    func whitelistDirectoryMatchesChildren() {
        let manager = makeManager()
        manager.addDir("/Users/nick/projects/myapp")
        #expect(manager.isDirWhitelisted("/Users/nick/projects/myapp/src/main.swift") == true)
        #expect(manager.isDirWhitelisted("/Users/nick/projects/myapp/.env") == true)
        #expect(manager.isDirWhitelisted("/Users/nick/projects/otherapp/.env") == false)
    }

    // MARK: - Finding ID whitelisting

    @Test("Whitelist finding by ID")
    func whitelistFindingById() {
        let manager = makeManager()
        manager.addFinding("env:/path:3:AWS")
        #expect(manager.isWhitelisted(findingId: "env:/path:3:AWS") == true)
        #expect(manager.isWhitelisted(findingId: "env:/path:5:OTHER") == false)
    }

    @Test("Remove finding from whitelist")
    func removeFinding() {
        let manager = makeManager()
        manager.addFinding("test-finding-1")
        #expect(manager.isWhitelisted(findingId: "test-finding-1") == true)
        manager.removeFinding("test-finding-1")
        #expect(manager.isWhitelisted(findingId: "test-finding-1") == false)
    }

    @Test("allFindings computed property")
    func allFindingsProperty() {
        let manager = makeManager()
        manager.addFinding("id-1")
        manager.addFinding("id-2")
        let all = manager.allFindings
        #expect(all.contains("id-1"))
        #expect(all.contains("id-2"))
        #expect(all.count == 2)
    }

    // MARK: - Safe pattern matching

    @Test("Safe pattern matching with prefix glob")
    func safePatternPrefixGlob() {
        let manager = makeManager()
        #expect(manager.isSafePattern("sk-test-abc123") == true)
        #expect(manager.isSafePattern("sk-test-") == true)
        #expect(manager.isSafePattern("sk-prod-abc123") == false)
    }

    @Test("Safe pattern matching with suffix glob")
    func safePatternSuffixGlob() {
        let manager = makeManager()
        manager.addSafePattern("*-placeholder")
        #expect(manager.isSafePattern("my-placeholder") == true)
        #expect(manager.isSafePattern("placeholder") == false)
    }

    @Test("Safe pattern exact match")
    func safePatternExactMatch() {
        let manager = makeManager()
        manager.addSafePattern("changeme")
        #expect(manager.isSafePattern("changeme") == true)
        #expect(manager.isSafePattern("changeme123") == false)
    }

    @Test("Default safe patterns are loaded")
    func defaultSafePatterns() {
        let manager = makeManager()
        #expect(manager.isSafePattern("sk-test-anything") == true)
        #expect(manager.isSafePattern("pk_test_xyz") == true)
        #expect(manager.isSafePattern("AKIAIOSFODNN7EXAMPLE") == true)
        #expect(manager.isSafePattern("django-insecure-abc") == true)
        #expect(manager.isSafePattern("your-api-key-here") == true)
        #expect(manager.isSafePattern("changeme") == true)
    }

    // MARK: - isWhitelistedByAnyRule

    @Test("isWhitelistedByAnyRule checks file path")
    func whitelistedByAnyRuleFile() {
        let manager = makeManager()
        manager.addFile("/app/.env")
        let finding = makeFinding(filePath: "/app/.env")
        #expect(manager.isWhitelistedByAnyRule(finding: finding) == true)
    }

    @Test("isWhitelistedByAnyRule checks directory")
    func whitelistedByAnyRuleDir() {
        let manager = makeManager()
        manager.addDir("/app/fixtures")
        let finding = makeFinding(filePath: "/app/fixtures/test.env")
        #expect(manager.isWhitelistedByAnyRule(finding: finding) == true)
    }

    @Test("isWhitelistedByAnyRule checks finding ID")
    func whitelistedByAnyRuleId() {
        let manager = makeManager()
        manager.addFinding("specific-finding")
        let finding = makeFinding(id: "specific-finding")
        #expect(manager.isWhitelistedByAnyRule(finding: finding) == true)
    }

    @Test("isWhitelistedByAnyRule checks safe pattern")
    func whitelistedByAnyRulePattern() {
        let manager = makeManager()
        let finding = makeFinding(secretPreview: "changeme")
        #expect(manager.isWhitelistedByAnyRule(finding: finding) == true)
    }

    // MARK: - filterFindings

    @Test("filterFindings removes whitelisted items")
    func filterFindingsRemovesWhitelisted() {
        let manager = makeManager()
        manager.addFinding("id-1")
        manager.addFile("/app/.env")

        let findings = [
            makeFinding(id: "id-1"),
            makeFinding(id: "id-2", filePath: "/app/.env"),
            makeFinding(id: "id-3", filePath: "/other/file.txt"),
        ]

        let filtered = manager.filterFindings(findings)
        #expect(filtered.count == 1)
        #expect(filtered[0].id == "id-3")
    }

    @Test("filterFindings returns all when nothing whitelisted")
    func filterFindingsReturnAll() {
        let manager = makeManager()
        let findings = [makeFinding(), makeFinding()]
        let filtered = manager.filterFindings(findings)
        #expect(filtered.count == 2)
    }

    // MARK: - Persistence

    @Test("Persists and loads config from disk")
    func persistsAndLoads() throws {
        let path = NSTemporaryDirectory() + "damit-persist-\(UUID().uuidString).json"

        let manager1 = WhitelistManager(configPath: path)
        manager1.addFile("/some/file.txt")
        manager1.addDir("/some/dir")
        manager1.addFinding("persist-finding")
        manager1.addSafePattern("custom-pattern*")
        try manager1.save()

        let manager2 = WhitelistManager(configPath: path)
        try manager2.load()

        #expect(manager2.isFileWhitelisted("/some/file.txt") == true)
        #expect(manager2.isDirWhitelisted("/some/dir/nested.txt") == true)
        #expect(manager2.isWhitelisted(findingId: "persist-finding") == true)
        #expect(manager2.isSafePattern("custom-pattern-xyz") == true)
    }

    @Test("scanInterval default value")
    func scanIntervalDefault() {
        let manager = makeManager()
        #expect(manager.scanInterval == 300)
    }
}
