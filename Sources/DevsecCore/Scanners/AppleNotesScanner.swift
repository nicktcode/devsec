import Foundation

// MARK: - AppleNotesScanner

/// Scans **unlocked** Apple Notes for secrets.
///
/// Many people copy API keys, wallet recovery phrases, and passwords into Apple
/// Notes for convenience. Notes that aren't password-protected are plaintext as
/// far as any process with Automation access is concerned. so damit can
/// surface those exposures the same way it surfaces a plaintext `.env` file.
///
/// **Password-protected notes are skipped by design.** Apple does not expose
/// their decrypted contents to AppleScript/JXA, and we don't try to work around
/// that. a locked note is, by the user's explicit choice, out of scope for
/// this scanner.
///
/// ## Permissions
///
/// Running the Notes app via JXA requires a one-time Automation permission
/// prompt on first invocation. If the user denies it, the scanner emits a
/// single `.info` finding explaining how to grant access instead of silently
/// returning zero results.
///
/// ## Incremental scanning
///
/// A first-run scan of a large Notes library can take tens of seconds because
/// each note body has to be fetched via Apple Events and HTML-stripped. After
/// the first run, ``AppleNotesCache`` remembers the per-note modification date
/// and the findings that were produced. Subsequent scans only re-scan notes
/// whose modification date has advanced; for unchanged notes, the cached
/// findings are replayed. Deleted notes have their cache entries pruned.
public struct AppleNotesScanner: Scanner {

    public init() {}

    // MARK: - Scanner Protocol

    public var module: ScanModule { .appleNotes }

    public func scan(onProgress: ScanProgressHandler? = nil) async throws -> ScanResult {
        let start = Date()
        let cache = AppleNotesCache()

        // Phase 1: cheap index listing (id + modification date + name) for every
        // unlocked note. This single JXA call avoids the cost of fetching bodies
        // up front so we can filter down to actually-changed notes.
        onProgress?("Listing Apple Notes")
        let listResult = Self.runJXA(script: Self.listScript)
        switch listResult {
        case .permissionDenied:
            return ScanResult(
                module: .appleNotes,
                findings: [Self.permissionDeniedFinding()],
                duration: Date().timeIntervalSince(start)
            )
        case .failure(let message):
            return ScanResult(
                module: .appleNotes,
                findings: [Self.failureFinding(message: message)],
                duration: Date().timeIntervalSince(start)
            )
        case .success(let output):
            let index = Self.decodeIndex(output)
            return try await runWithIndex(index, cache: cache, start: start, onProgress: onProgress)
        }
    }

    // MARK: - Phase 2

    private func runWithIndex(
        _ index: [NoteIndexItem],
        cache: AppleNotesCache,
        start: Date,
        onProgress: ScanProgressHandler?
    ) async throws -> ScanResult {

        // Prune cache entries for notes that no longer exist.
        let presentIds = Set(index.map(\.id))
        cache.pruneToIds(presentIds)

        // Partition into "need rescan" vs "replay from cache".
        var toRescan: [NoteIndexItem] = []
        var replayed: [Finding] = []
        for item in index {
            if let cached = cache.entry(for: item.id),
               cached.modificationDate == item.modificationDate {
                replayed.append(contentsOf: cached.findings)
            } else {
                toRescan.append(item)
            }
        }

        onProgress?("\(toRescan.count) changed / \(replayed.count) cached findings")

        // Phase 3: for each note that needs rescanning, fetch body + scan.
        // We keep this serial to be nice to Apple Events IPC. parallelism via
        // multiple osascript processes would produce race-prone system prompts
        // and doesn't actually speed up Notes.app.
        var newFindings: [Finding] = []
        for (i, item) in toRescan.enumerated() {
            let shortTitle = item.name.isEmpty ? "(untitled)" : item.name
            onProgress?("[\(i+1)/\(toRescan.count)] \(shortTitle)")

            let bodyResult = Self.runJXA(script: Self.bodyScript(for: item.id))
            guard case .success(let bodyJSON) = bodyResult else { continue }
            guard let html = Self.decodeBody(bodyJSON) else { continue }
            let plainText = Self.htmlToPlainText(html)

            let findings = Self.scanNoteText(
                plainText,
                noteId: item.id,
                noteName: item.name
            )
            newFindings.append(contentsOf: findings)
            cache.setEntry(
                AppleNotesCache.Entry(
                    modificationDate: item.modificationDate,
                    findings: findings
                ),
                for: item.id
            )
        }

        try? cache.save()

        let duration = Date().timeIntervalSince(start)
        return ScanResult(
            module: .appleNotes,
            findings: replayed + newFindings,
            duration: duration
        )
    }

    // MARK: - Finding Construction

    static func scanNoteText(_ text: String, noteId: String, noteName: String) -> [Finding] {
        let matches = PatternDatabase.findSecrets(in: text)
        guard !matches.isEmpty else { return [] }

        var findings: [Finding] = []
        for match in matches {
            let preview8 = String(match.matchedText.prefix(8))
            let findingId = "notes:\(noteId):\(match.patternName):\(preview8)"
            let displayTitle = noteName.isEmpty ? "(untitled note)" : noteName

            // Apple Notes findings carry high severity because these are
            // plaintext credentials in a cloud-synced data store. We don't set
            // a filePath (no filesystem location) but stash the notes:// URL in
            // the preview so the user can copy it.
            let severity: Severity
            let gitRisk: RiskLevel
            let localRisk: RiskLevel
            if match.patternName == "Crypto Recovery Phrase" || match.patternName == "Private Key" {
                severity = .critical
                gitRisk = .none
                localRisk = .critical
            } else {
                severity = .high
                gitRisk = .none
                localRisk = .high
            }

            findings.append(Finding(
                id: findingId,
                module: .appleNotes,
                severity: severity,
                gitRisk: gitRisk,
                localRisk: localRisk,
                filePath: nil,
                lineNumber: nil,
                description: "\(match.patternName) found in Apple Note: \"\(displayTitle)\"",
                secretPreview: PatternDatabase.maskSecret(match.matchedText),
                recommendation: "Move this secret to a password manager (1Password, Keychain) and delete it from the note, or lock the note with a password.",
                isNew: true
            ))
        }
        return findings
    }

    // MARK: - Permission Probe

    /// Triggers the TCC Automation permission prompt for Notes.app.
    ///
    /// Call this when the user first opts in to Apple Notes scanning so the
    /// macOS permission dialog appears immediately, instead of waiting until
    /// the next scheduled scan fires. Runs a minimal `osascript` that simply
    /// counts notes. the system prompt is triggered by the first Apple Event
    /// sent to Notes.app, regardless of the script's content.
    ///
    /// Returns the probe's ``JXAResult`` so callers can log / surface outcomes
    /// if they want. Running multiple times is harmless: once the user has
    /// answered the prompt, subsequent probes just return quickly.
    @discardableResult
    public static func requestAccess() -> JXAResult {
        runJXA(script: "Application('Notes').notes().length;")
    }

    // MARK: - JXA Runner

    public enum JXAResult: Sendable {
        case success(String)
        case permissionDenied
        case failure(String)
    }

    public static func runJXA(script: String) -> JXAResult {
        let process = Process()
        let stdout = Pipe()
        let stderr = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-l", "JavaScript", "-e", script]
        process.standardOutput = stdout
        process.standardError = stderr
        do {
            try process.run()
        } catch {
            return .failure("osascript failed to launch: \(error.localizedDescription)")
        }
        process.waitUntilExit()

        let outData = stdout.fileHandleForReading.readDataToEndOfFile()
        let errData = stderr.fileHandleForReading.readDataToEndOfFile()
        let outString = String(data: outData, encoding: .utf8) ?? ""
        let errString = String(data: errData, encoding: .utf8) ?? ""

        if process.terminationStatus != 0 {
            // TCC-denied Apple Events produce a recognizable error. Detect it
            // so the UI can guide the user to System Settings rather than show
            // a generic failure.
            let combined = (errString + outString).lowercased()
            if combined.contains("not authorized")
                || combined.contains("not authorised")
                || combined.contains("-1743")
                || combined.contains("errauthorizationdenied") {
                return .permissionDenied
            }
            return .failure(errString.isEmpty ? "osascript exited with status \(process.terminationStatus)" : errString)
        }

        return .success(outString)
    }

    // MARK: - JXA Scripts

    /// Lists every unlocked note as JSON. Each element has `id`, `name`, and
    /// `mod` (epoch milliseconds).
    static let listScript: String = """
    const Notes = Application('Notes');
    const out = [];
    const all = Notes.notes();
    for (let i = 0; i < all.length; i++) {
        const n = all[i];
        try {
            if (n.passwordProtected()) continue;
            out.push({
                id: n.id(),
                name: n.name(),
                mod: n.modificationDate().getTime()
            });
        } catch (e) {
            // Skip notes that error out (can happen during sync).
        }
    }
    JSON.stringify(out);
    """

    /// Returns a script that fetches the HTML body of a single note by ID.
    static func bodyScript(for noteId: String) -> String {
        // JSON-escape the ID via Foundation rather than string splicing to
        // defend against pathological (though unlikely) Apple IDs.
        let escaped = (try? JSONSerialization.data(withJSONObject: [noteId], options: []))
            .flatMap { String(data: $0, encoding: .utf8) }
            .map { String($0.dropFirst().dropLast()) } // strip [ ]
            ?? "\"\(noteId)\""

        return """
        const Notes = Application('Notes');
        const targetId = \(escaped);
        const all = Notes.notes();
        let body = null;
        for (let i = 0; i < all.length; i++) {
            try {
                if (all[i].id() === targetId) {
                    body = all[i].body();
                    break;
                }
            } catch (e) {}
        }
        JSON.stringify({body: body});
        """
    }

    // MARK: - JSON Decoding

    struct NoteIndexItem: Sendable {
        let id: String
        let name: String
        let modificationDate: Date
    }

    static func decodeIndex(_ jsonString: String) -> [NoteIndexItem] {
        let trimmed = jsonString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let data = trimmed.data(using: .utf8) else { return [] }
        guard let array = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
            return []
        }
        return array.compactMap { dict in
            guard let id = dict["id"] as? String else { return nil }
            let name = (dict["name"] as? String) ?? ""
            // Epoch milliseconds → Date.
            let modMs: Double
            if let d = dict["mod"] as? Double { modMs = d }
            else if let i = dict["mod"] as? Int { modMs = Double(i) }
            else { return nil }
            return NoteIndexItem(
                id: id,
                name: name,
                modificationDate: Date(timeIntervalSince1970: modMs / 1000.0)
            )
        }
    }

    static func decodeBody(_ jsonString: String) -> String? {
        let trimmed = jsonString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let data = trimmed.data(using: .utf8) else { return nil }
        guard let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        return dict["body"] as? String
    }

    // MARK: - HTML Stripping

    /// Minimal HTML → plaintext converter. Good enough for scanning purposes:
    /// we need the textual content of the note, preserving line boundaries so
    /// that per-line secret patterns still match correctly.
    static func htmlToPlainText(_ html: String) -> String {
        var text = html
        // Line-breaking tags become newlines *before* we strip tags.
        text = text.replacingOccurrences(
            of: #"<br\s*/?>"#,
            with: "\n",
            options: .regularExpression
        )
        text = text.replacingOccurrences(
            of: #"</(?:p|div|li|tr|h[1-6])>"#,
            with: "\n",
            options: .regularExpression
        )
        // Strip remaining tags.
        text = text.replacingOccurrences(
            of: #"<[^>]+>"#,
            with: "",
            options: .regularExpression
        )
        // Decode common HTML entities.
        let entities: [(String, String)] = [
            ("&nbsp;", " "),
            ("&amp;", "&"),
            ("&lt;", "<"),
            ("&gt;", ">"),
            ("&quot;", "\""),
            ("&#39;", "'"),
            ("&apos;", "'"),
        ]
        for (entity, replacement) in entities {
            text = text.replacingOccurrences(of: entity, with: replacement)
        }
        // Numeric entities (&#1234;). decode a handful of the most common.
        text = text.replacingOccurrences(
            of: #"&#(\d+);"#,
            with: "",
            options: .regularExpression
        )
        return text
    }

    // MARK: - Synthetic Findings

    static func permissionDeniedFinding() -> Finding {
        Finding(
            id: "notes:permission-denied",
            module: .appleNotes,
            severity: .info,
            gitRisk: .none,
            localRisk: .none,
            filePath: nil,
            lineNumber: nil,
            description: "Apple Notes access not granted",
            secretPreview: "",
            recommendation: "Grant permission in System Settings → Privacy & Security → Automation → damit → Notes, then re-run the scan.",
            isNew: true
        )
    }

    static func failureFinding(message: String) -> Finding {
        Finding(
            id: "notes:scanner-failure",
            module: .appleNotes,
            severity: .info,
            gitRisk: .none,
            localRisk: .none,
            filePath: nil,
            lineNumber: nil,
            description: "Apple Notes scan failed",
            secretPreview: "",
            recommendation: "Could not read notes: \(message). Make sure the Notes app is installed and reachable.",
            isNew: true
        )
    }
}
