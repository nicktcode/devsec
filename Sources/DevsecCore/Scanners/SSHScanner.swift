import Foundation

// MARK: - SSHScanner

/// Scans the filesystem for SSH private keys, checking for:
/// - Private key material stored in unsafe locations
/// - Incorrect file permissions (should be 0600)
/// - Keys referenced in SSH config via IdentityFile directives
public struct SSHScanner: Scanner {

    public init() {}

    // MARK: - Scanner Protocol

    public var module: ScanModule { .ssh }

    public func scan(onProgress: ScanProgressHandler? = nil) async throws -> ScanResult {
        let start = Date()
        let home = FileManager.default.homeDirectoryForCurrentUser.path

        // Content-based discovery: files containing private key headers
        let keyHeaders = [
            "BEGIN OPENSSH PRIVATE KEY",
            "BEGIN RSA PRIVATE KEY",
            "BEGIN EC PRIVATE KEY",
            "BEGIN PGP PRIVATE KEY BLOCK",
            "BEGIN DSA PRIVATE KEY",
        ]

        // Parallelize the 5 header queries instead of running them in
        // sequence. each one is a ~second-long NSMetadataQuery. Running
        // together is ~5× faster and avoids the "stuck at 1/5" feel.
        onProgress?("Searching key headers [0/\(keyHeaders.count)]")
        var headerDone = 0
        let contentPaths: [String] = await withTaskGroup(of: [String].self) { group in
            for header in keyHeaders {
                group.addTask {
                    await SpotlightEngine.findFiles(containingText: header, searchPath: home)
                }
            }
            var acc: [String] = []
            for await paths in group {
                headerDone += 1
                onProgress?("Searching key headers [\(headerDone)/\(keyHeaders.count)]")
                acc.append(contentsOf: paths)
            }
            return acc
        }

        // Filename-based discovery
        let keyFilenames = ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "id_ecdsa_sk", "id_ed25519_sk"]
        onProgress?("Searching by filename")
        var namePaths: [String] = []
        for name in keyFilenames {
            let found = await SpotlightEngine.findFiles(named: name, searchPath: home)
            namePaths.append(contentsOf: found)
        }

        // SSH config IdentityFile discovery
        let sshConfigPath = "\(home)/.ssh/config"
        var identityFilePaths: [String] = []
        let (configText, _) = SafeFileReader.readAll(at: sshConfigPath)
        if let configContent = configText {
            identityFilePaths = SSHScanner.parseIdentityFiles(from: configContent)
        }

        // Tier-4 sweep: every top-level entry in ~/.ssh/ that isn't a
        // known non-key file. Lets us catch `my-old-key`, `prod`,
        // `staging.pem` at low severity even when the contents don't
        // parse as anything recognizable. The classifier below will
        // still reject files that match the allowlist.
        var sshDirPaths: [String] = []
        let sshDir = "\(home)/.ssh"
        if let entries = try? FileManager.default.contentsOfDirectory(atPath: sshDir) {
            for entry in entries {
                let full = "\(sshDir)/\(entry)"
                var isDir: ObjCBool = false
                if FileManager.default.fileExists(atPath: full, isDirectory: &isDir), !isDir.boolValue {
                    sshDirPaths.append(full)
                }
            }
        }

        // Deduplicate all discovered paths
        var seen = Set<String>()
        var allPaths: [String] = []
        for path in contentPaths + namePaths + identityFilePaths + sshDirPaths {
            if seen.insert(path).inserted {
                allPaths.append(path)
            }
        }

        let fm = FileManager.default
        // Apply user-defined exclusions and damit's built-in path rules
        // (node_modules, site-packages, venv, etc.). Without this filter,
        // Python packages like pycryptodome ship real-looking PEM test
        // fixtures that flood the report. 80+ false positives per user
        // with an active Python environment.
        let existingPaths = allPaths.filter { path in
            guard fm.fileExists(atPath: path) else { return false }
            if BuiltInScanExclusions.isExcluded(path) { return false }
            if ScanExclusions.isExcluded(path) { return false }
            return true
        }
        onProgress?("Found \(existingPaths.count) SSH key files")

        var allFindings: [Finding] = []
        var offloadedPaths: [String] = []
        for (i, path) in existingPaths.enumerated() {
            let filename = (path as NSString).lastPathComponent
            let dir = ((path as NSString).deletingLastPathComponent as NSString).lastPathComponent
            onProgress?("[\(i+1)/\(existingPaths.count)] \(dir)/\(filename)")
            let outcome = SSHScanner.scanKeyFileDetailed(at: path)
            allFindings.append(contentsOf: outcome.findings)
            if outcome.skipped == .cloudPlaceholder {
                offloadedPaths.append(path)
            }
        }

        let duration = Date().timeIntervalSince(start)
        return ScanResult(
            module: .ssh,
            findings: allFindings,
            duration: duration,
            offloadedPaths: offloadedPaths
        )
    }

    // MARK: - Static Key File Scanner

    public struct FileScanOutcome: Sendable {
        public let findings: [Finding]
        public let skipped: SafeFileReader.SkipReason?
    }

    /// Back-compat wrapper. Prefer ``scanKeyFileDetailed(at:)``.
    public static func scanKeyFile(at path: String) -> [Finding] {
        scanKeyFileDetailed(at: path).findings
    }

    /// Inspects an SSH key file for private key content, bad permissions, and unsafe location.
    /// Uses ``SafeFileReader`` so iCloud placeholders aren't materialized.
    public static func scanKeyFileDetailed(at path: String) -> FileScanOutcome {
        let (contentsOpt, summary) = SafeFileReader.readAll(at: path)
        // When SafeFileReader returns nil (iCloud placeholder, binary,
        // too large) the tier-3 ~/.ssh/ sweep can still fire because it
        // only needs the path. Fall through with empty contents.
        let contents = contentsOpt ?? ""

        // Multi-tier classification. Each tier is strictly more
        // permissive than the one above; we take the strongest signal
        // available so the UI shows the right severity.
        //
        //  tier 1  Real PEM: BEGIN + END + ≥100 base64 chars.
        //  tier 2  Headerless key with DER / openssh-key-v1 magic
        //          bytes AND a canonical id_* filename.
        //  tier 3  Unknown file inside ~/.ssh/ that isn't one of the
        //          well-known non-key entries (handled in scan()).
        let classification = SSHScanner.classify(path: path, contents: contents)
        guard classification != .notAKey else {
            return FileScanOutcome(findings: [], skipped: summary.skipped)
        }

        var findings: [Finding] = []
        let filename = URL(fileURLWithPath: path).lastPathComponent

        // Check for unsafe location (Desktop, Downloads, Documents)
        let unsafeLocations = ["/Desktop/", "/Downloads/", "/Documents/"]
        let isUnsafe = unsafeLocations.contains { path.contains($0) }

        // Tier-adjusted severity: a confirmed PEM in /Downloads/ is
        // `critical`, a headerless-but-DER-shaped id_rsa in ~/.ssh/ is
        // `high`, and an unrecognized file in ~/.ssh/ is `low`.
        let severity: Severity
        let gitRisk: RiskLevel
        let localRisk: RiskLevel
        let description: String
        let preview: String
        let recommendation: String

        switch classification {
        case .pemBlock:
            if isUnsafe {
                severity = .critical; gitRisk = .critical; localRisk = .critical
                description = "SSH private key in unsafe location: \(filename)"
                recommendation = "Move this key to ~/.ssh/ and set permissions to 0600: mv \"\(path)\" ~/.ssh/\(filename) && chmod 600 ~/.ssh/\(filename)"
            } else {
                severity = .high; gitRisk = .high; localRisk = .high
                description = "SSH private key found: \(filename)"
                recommendation = "Ensure this key is protected. Set permissions to 0600: chmod 600 \"\(path)\""
            }
            preview = "-----BEGIN...-----"
        case .derHeaderless:
            severity = .high; gitRisk = .high; localRisk = .high
            description = "Possible SSH private key (no PEM envelope): \(filename)"
            preview = "DER/openssh-key-v1 body"
            recommendation = "File has the binary signature of a private key but no PEM armor. Verify it's a real key, then re-export with proper headers: ssh-keygen -p -f \"\(path)\"."
        case .sshDirUnknown:
            severity = .low; gitRisk = .low; localRisk = .low
            description = "Unrecognized file in ~/.ssh/: \(filename)"
            preview = ""
            recommendation = "damit couldn't positively identify this as a key, but files in ~/.ssh/ are usually key-adjacent. Review and move non-key files out of this directory."
        case .notAKey:
            return FileScanOutcome(findings: [], skipped: nil)
        }

        findings.append(Finding(
            id: "ssh:key:\(path)",
            module: .ssh,
            severity: severity,
            gitRisk: gitRisk,
            localRisk: localRisk,
            filePath: path,
            lineNumber: nil,
            description: description,
            secretPreview: preview,
            recommendation: recommendation,
            isNew: true
        ))

        // Check file permissions
        if let attrs = try? FileManager.default.attributesOfItem(atPath: path),
           let posixPermissions = attrs[.posixPermissions] as? Int {
            // 0o600 = 384 decimal; anything more permissive is a risk
            let isTooBroad = (posixPermissions & 0o077) != 0
            if isTooBroad {
                let octal = String(posixPermissions, radix: 8)
                let finding = Finding(
                    id: "ssh:perms:\(path)",
                    module: .ssh,
                    severity: .high,
                    gitRisk: .none,
                    localRisk: .high,
                    filePath: path,
                    lineNumber: nil,
                    description: "SSH private key has insecure permissions (\(octal)): \(filename)",
                    secretPreview: "mode=0\(octal)",
                    recommendation: "Fix permissions immediately: chmod 600 \"\(path)\"",
                    isNew: true
                )
                findings.append(finding)
            }
        }

        return FileScanOutcome(findings: findings, skipped: nil)
    }

    // MARK: - Key Classification

    /// Classification result for a candidate key file. Tiers are ordered
    /// from highest confidence (a real PEM block) to lowest (file just
    /// lives in ~/.ssh and isn't one of the well-known non-key entries).
    enum Classification: Sendable, Equatable {
        case pemBlock
        case derHeaderless
        case sshDirUnknown
        case notAKey
    }

    /// Decides whether `contents` at `path` should be treated as a
    /// private key, and if so at what confidence tier.
    static func classify(path: String, contents: String) -> Classification {
        if containsRealPrivateKey(contents) { return .pemBlock }
        if looksLikeHeaderlessKey(path: path, contents: contents) { return .derHeaderless }
        if isUnknownInSSHDir(path: path) { return .sshDirUnknown }
        return .notAKey
    }

    /// Returns true when `contents` has a PEM private-key block whose body
    /// is plausibly real. i.e. a BEGIN … PRIVATE KEY … header paired with
    /// a matching END footer, with at least ~100 characters of base64
    /// material between them. A plain mention of the header string in
    /// documentation or source code will not match because it has no
    /// footer and no base64 body.
    static func containsRealPrivateKey(_ contents: String) -> Bool {
        let pattern = #"-----BEGIN (?:OPENSSH |RSA |EC |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:[A-Za-z0-9+/=]\s*){100,}[\s\S]*?-----END (?:OPENSSH |RSA |EC |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----"#
        return contents.range(of: pattern, options: .regularExpression) != nil
    }

    /// Tier-2 check: a file named like a canonical SSH private key
    /// (`id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa`, `id_*_sk`) whose
    /// raw bytes start with a recognizable key signature.
    ///
    /// Signatures we accept:
    ///  - `-----BEGIN`. already covered by the PEM path, included
    ///    here as a belt-and-suspenders fallback when the body is too
    ///    short for the tier-1 regex.
    ///  - `openssh-key-v1\0`. the modern OpenSSH private-key binary
    ///    container used by Ed25519 and ECDSA keys exported without
    ///    PEM armor.
    ///  - `0x30 0x82`. ASN.1 DER `SEQUENCE` tag with a 2-byte length.
    ///    This is how every raw DER-encoded RSA/PKCS#8 private key
    ///    starts on disk.
    static func looksLikeHeaderlessKey(path: String, contents: String) -> Bool {
        let filename = (path as NSString).lastPathComponent.lowercased()
        guard isCanonicalKeyFilename(filename) else { return false }

        // Read the first 16 bytes of the raw file. The `contents`
        // parameter is a String (what the caller already read via
        // SafeFileReader); for byte-magic we want the unmodified file.
        guard let data = try? Data(
            contentsOf: URL(fileURLWithPath: path),
            options: [.alwaysMapped]
        ), data.count >= 100 else {
            return false
        }

        // openssh-key-v1 magic header for headerless binary keys.
        if data.starts(with: Array("openssh-key-v1\0".utf8)) { return true }

        // ASN.1 SEQUENCE with a 2-byte length. universal for DER keys.
        if data.count >= 4, data[data.startIndex] == 0x30, data[data.startIndex + 1] == 0x82 {
            return true
        }

        // PEM text without enough base64 body to satisfy tier 1.
        if contents.contains("-----BEGIN") { return true }

        return false
    }

    /// Tier-4 check: a file inside the user's ~/.ssh/ that isn't one of
    /// the well-known non-key entries. Designed as a catch-all for
    /// things like stray `.pem`, `my-old-key`, `prod`, `staging`. users
    /// rarely keep random junk under ~/.ssh/, so surfacing it at low
    /// severity is fair signal even when we can't parse it as a key.
    static func isUnknownInSSHDir(path: String) -> Bool {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let sshDir = home + "/.ssh/"
        guard path.hasPrefix(sshDir) else { return false }

        let relative = path.dropFirst(sshDir.count)
        // Anything in a subdirectory. e.g. ~/.ssh/sockets/. is out of
        // scope for this sweep. Only sweep the top level.
        if relative.contains("/") { return false }

        let filename = String(relative).lowercased()
        return !Self.sshDirAllowlist.contains(filename)
            && !filename.hasSuffix(".pub")
    }

    /// Files that are expected to live at the top level of ~/.ssh/ and
    /// are not themselves private keys. Extending this list is cheaper
    /// than teaching the sweep how to parse each format. anything not
    /// on it that lacks `.pub` will surface as a low-severity "unknown
    /// file in ~/.ssh/" finding.
    private static let sshDirAllowlist: Set<String> = [
        "authorized_keys", "authorized_keys2",
        "known_hosts", "known_hosts.old",
        "config", "environment", "rc",
        ".ds_store",
    ]

    /// True for the canonical set of OpenSSH private-key filenames plus
    /// their FIDO2 security-key variants (id_*_sk). Public keys ending
    /// in `.pub` are always excluded.
    private static func isCanonicalKeyFilename(_ filename: String) -> Bool {
        if filename.hasSuffix(".pub") { return false }
        let canonical: Set<String> = [
            "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
            "id_ecdsa_sk", "id_ed25519_sk",
        ]
        return canonical.contains(filename)
    }

    // MARK: - SSH Config Parser

    /// Parses IdentityFile directives from an SSH config file content.
    /// Expands the `~/` home directory prefix.
    public static func parseIdentityFiles(from sshConfig: String) -> [String] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        var paths: [String] = []

        let lines = sshConfig.components(separatedBy: "\n")
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            // Case-insensitive match for IdentityFile directive
            guard trimmed.lowercased().hasPrefix("identityfile") else { continue }

            // Extract the path after "IdentityFile"
            let afterKeyword = trimmed.dropFirst("identityfile".count)
                .trimmingCharacters(in: .whitespaces)
            guard !afterKeyword.isEmpty else { continue }

            // Expand ~/
            let expanded: String
            if afterKeyword.hasPrefix("~/") {
                expanded = home + afterKeyword.dropFirst(1)
            } else if afterKeyword.hasPrefix("%d/") {
                expanded = home + afterKeyword.dropFirst(2)
            } else {
                expanded = afterKeyword
            }

            paths.append(expanded)
        }

        return paths
    }
}
