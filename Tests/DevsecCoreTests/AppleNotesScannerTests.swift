import Testing
import Foundation
@testable import DevsecCore

@Suite("AppleNotesScanner")
struct AppleNotesScannerTests {

    // MARK: - HTML Stripping

    @Test("Strips simple HTML tags")
    func stripsSimpleTags() {
        let html = "<p>Hello <b>world</b></p>"
        let plain = AppleNotesScanner.htmlToPlainText(html)
        #expect(plain.contains("Hello world"))
    }

    @Test("Converts block-level tags to newlines")
    func blockTagsBecomeNewlines() {
        let html = "<div>line one</div><div>line two</div>"
        let plain = AppleNotesScanner.htmlToPlainText(html)
        let lines = plain.split(separator: "\n", omittingEmptySubsequences: true)
        #expect(lines.count == 2)
        #expect(lines[0].trimmingCharacters(in: .whitespaces) == "line one")
        #expect(lines[1].trimmingCharacters(in: .whitespaces) == "line two")
    }

    @Test("Handles <br> breaks")
    func handlesBreakTag() {
        let html = "first<br>second<br/>third<br />fourth"
        let plain = AppleNotesScanner.htmlToPlainText(html)
        let lines = plain.split(separator: "\n", omittingEmptySubsequences: true)
        #expect(lines.count == 4)
    }

    @Test("Decodes common HTML entities")
    func decodesEntities() {
        let html = "<p>a&nbsp;b &amp; c &lt;d&gt; &quot;e&quot; &#39;f&#39;</p>"
        let plain = AppleNotesScanner.htmlToPlainText(html)
        #expect(plain.contains("a b & c <d> \"e\" 'f'"))
    }

    // MARK: - Secret Detection in Note Text

    @Test("Flags API key found in note text")
    func findsApiKeyInNote() {
        let text = "My AWS key: AKIAQZ3K7HMNRFPVUYDX please dont share"
        let findings = AppleNotesScanner.scanNoteText(text, noteId: "x-id-1", noteName: "Work creds")
        #expect(findings.contains { $0.description.contains("AWS Access Key") })
        #expect(findings.contains { $0.description.contains("Work creds") })
    }

    @Test("Crypto recovery phrase in note is critical severity")
    func cryptoPhraseIsCritical() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        let findings = AppleNotesScanner.scanNoteText(phrase, noteId: "wallet-id", noteName: "Wallet Backup")
        #expect(findings.contains { $0.severity == .critical })
        #expect(findings.contains { $0.description.contains("Crypto Recovery Phrase") })
    }

    @Test("Finding has stable ID using note ID and pattern name")
    func stableFindingId() {
        let text = "AKIAQZ3K7HMNRFPVUYDX"
        let a = AppleNotesScanner.scanNoteText(text, noteId: "abc", noteName: "n")
        let b = AppleNotesScanner.scanNoteText(text, noteId: "abc", noteName: "n")
        #expect(a.first?.id == b.first?.id)
        #expect(a.first?.id.hasPrefix("notes:abc:") == true)
    }

    @Test("Empty text produces no findings")
    func emptyText() {
        let findings = AppleNotesScanner.scanNoteText("", noteId: "x", noteName: "empty")
        #expect(findings.isEmpty)
    }

    // MARK: - Index Decoding

    @Test("Decodes JXA listing JSON")
    func decodesIndex() {
        let json = #"[{"id":"note://1","name":"One","mod":1700000000000},{"id":"note://2","name":"Two","mod":1700000001000}]"#
        let items = AppleNotesScanner.decodeIndex(json)
        #expect(items.count == 2)
        #expect(items[0].id == "note://1")
        #expect(items[0].name == "One")
        #expect(abs(items[0].modificationDate.timeIntervalSince1970 - 1_700_000_000) < 0.001)
    }

    @Test("Tolerates garbage JXA output")
    func decodesGarbage() {
        #expect(AppleNotesScanner.decodeIndex("not json at all").isEmpty)
        #expect(AppleNotesScanner.decodeIndex("").isEmpty)
    }

    // MARK: - Cache

    @Test("Cache round-trip persists and reloads entries")
    func cacheRoundTrip() throws {
        let tmp = NSTemporaryDirectory() + "damit-notes-cache-test-\(UUID().uuidString).json"
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        let cache = AppleNotesCache(storePath: tmp)
        let finding = Finding(
            id: "notes:abc:AWS:AKIA",
            module: .appleNotes,
            severity: .high,
            gitRisk: .none,
            localRisk: .high,
            filePath: nil,
            lineNumber: nil,
            description: "test",
            secretPreview: "AKIA****",
            recommendation: "...",
            isNew: true
        )
        let now = Date()
        cache.setEntry(
            AppleNotesCache.Entry(modificationDate: now, findings: [finding]),
            for: "note-1"
        )
        try cache.save()

        let reloaded = AppleNotesCache(storePath: tmp)
        let entry = reloaded.entry(for: "note-1")
        #expect(entry != nil)
        #expect(entry?.findings.count == 1)
        #expect(entry?.findings.first?.id == "notes:abc:AWS:AKIA")
    }

    @Test("Cache prune drops entries not in present set")
    func cachePrune() {
        let tmp = NSTemporaryDirectory() + "damit-notes-cache-test-\(UUID().uuidString).json"
        defer { try? FileManager.default.removeItem(atPath: tmp) }
        let cache = AppleNotesCache(storePath: tmp)

        cache.setEntry(AppleNotesCache.Entry(modificationDate: Date(), findings: []), for: "keep-1")
        cache.setEntry(AppleNotesCache.Entry(modificationDate: Date(), findings: []), for: "keep-2")
        cache.setEntry(AppleNotesCache.Entry(modificationDate: Date(), findings: []), for: "drop-me")

        let dropped = cache.pruneToIds(["keep-1", "keep-2"])
        #expect(dropped == 1)
        #expect(cache.entry(for: "drop-me") == nil)
        #expect(cache.entry(for: "keep-1") != nil)
        #expect(cache.entry(for: "keep-2") != nil)
    }
}
