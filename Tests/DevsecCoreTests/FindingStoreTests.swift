import Testing
import Foundation
@testable import DevsecCore

@Suite("FindingStore")
struct FindingStoreTests {

    // MARK: - Helpers

    private func tempStorePath() -> String {
        NSTemporaryDirectory() + "devsec-findingstore-\(UUID().uuidString).json"
    }

    private func makeFinding(id: String = "test-\(UUID().uuidString)") -> Finding {
        Finding(
            id: id,
            module: .env,
            severity: .high,
            gitRisk: .high,
            localRisk: .medium,
            filePath: "/some/file.env",
            description: "Test finding",
            secretPreview: "secret",
            recommendation: "Remove it"
        )
    }

    @Test("Fresh findings are marked isNew=true")
    func freshFindingsAreNew() {
        let store = FindingStore(storePath: tempStorePath())
        let findings = [makeFinding(), makeFinding()]
        let marked = store.markNewVsKnown(findings)
        #expect(marked.count == 2)
        #expect(marked[0].isNew == true)
        #expect(marked[1].isNew == true)
    }

    @Test("Previously seen findings are marked isNew=false after save and reload")
    func previouslySeenFindingsAreNotNew() throws {
        let path = tempStorePath()
        let id1 = "finding-1"
        let id2 = "finding-2"

        let store1 = FindingStore(storePath: path)
        store1.recordFindings([makeFinding(id: id1), makeFinding(id: id2)])
        try store1.save()

        let store2 = FindingStore(storePath: path)
        try store2.load()
        let marked = store2.markNewVsKnown([makeFinding(id: id1), makeFinding(id: id2)])

        #expect(marked.count == 2)
        #expect(marked[0].isNew == false)
        #expect(marked[1].isNew == false)
    }

    @Test("Mix of known and new findings is correctly counted")
    func mixedKnownAndNewFindings() throws {
        let path = tempStorePath()

        let store1 = FindingStore(storePath: path)
        store1.recordFindings([makeFinding(id: "known-1")])
        try store1.save()

        let store2 = FindingStore(storePath: path)
        try store2.load()
        let marked = store2.markNewVsKnown([makeFinding(id: "known-1"), makeFinding(id: "new-1")])

        let knownMarked = marked.first { $0.id == "known-1" }
        let newMarked = marked.first { $0.id == "new-1" }
        #expect(knownMarked?.isNew == false)
        #expect(newMarked?.isNew == true)
        #expect(marked.filter { $0.isNew }.count == 1)
    }

    @Test("Empty findings list returns empty result")
    func emptyFindingsReturnsEmpty() {
        let store = FindingStore(storePath: tempStorePath())
        let marked = store.markNewVsKnown([])
        #expect(marked.isEmpty)
    }

    @Test("recordFindings accumulates IDs across multiple calls")
    func recordFindingsAccumulates() throws {
        let path = tempStorePath()
        let store = FindingStore(storePath: path)
        store.recordFindings([makeFinding(id: "acc-1")])
        store.recordFindings([makeFinding(id: "acc-2")])
        try store.save()

        let store2 = FindingStore(storePath: path)
        try store2.load()
        let marked = store2.markNewVsKnown([makeFinding(id: "acc-1"), makeFinding(id: "acc-2")])
        #expect(marked.filter { $0.isNew }.count == 0)
    }
}
