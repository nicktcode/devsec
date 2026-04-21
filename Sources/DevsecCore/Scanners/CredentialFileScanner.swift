import Foundation

// MARK: - CredentialFileScanner

/// Scans the filesystem for credential files such as password manager exports,
/// certificate stores, and other high-risk credential containers.
public struct CredentialFileScanner: Scanner {

    // MARK: - Dangerous Pattern Definitions

    /// Exact filenames that are always dangerous regardless of location.
    public static let dangerousFilenames: Set<String> = [
        "passwords.csv",
        "logins.csv",
        "logins.json",
        "passwords.json",
        "passwords.txt",
        ".htpasswd",
        "wp-config.php",
        "netrc",
        ".netrc",
    ]

    /// Filename prefix fragments that indicate password manager exports.
    public static let dangerousPrefixes: [String] = [
        "1password-export",
        "bitwarden-export",
        "lastpass-export",
        "keepass-export",
        "dashlane-export",
        "enpass-export",
        "passwords_export",
        "password-export",
    ]

    /// File extensions that indicate certificate or keystore files.
    public static let dangerousExtensions: Set<String> = [
        "pfx",
        "p12",
        "keystore",
        "jks",
        "ks",
    ]

    // MARK: - Scanner Protocol

    public init() {}

    public var module: ScanModule { .credentialFiles }

    public func scan(onProgress: ScanProgressHandler? = nil) async throws -> ScanResult {
        let start = Date()
        let home = FileManager.default.homeDirectoryForCurrentUser.path

        var allPaths: [String] = []

        // Search for exact dangerous filenames
        onProgress?("Discovering credential files")
        for filename in CredentialFileScanner.dangerousFilenames {
            let found = await SpotlightEngine.findFiles(named: filename, searchPath: home)
            allPaths.append(contentsOf: found)
        }

        // Search for prefix-based patterns using glob
        for prefix in CredentialFileScanner.dangerousPrefixes {
            // Search for CSV, JSON, TXT variants
            for ext in ["csv", "json", "txt", "xml"] {
                let found = await SpotlightEngine.findFiles(
                    matchingGlob: "\(prefix)*.\(ext)",
                    searchPath: home
                )
                allPaths.append(contentsOf: found)
            }
        }

        // Search for dangerous extensions
        for ext in CredentialFileScanner.dangerousExtensions {
            let found = await SpotlightEngine.findFiles(matchingGlob: "*.\(ext)", searchPath: home)
            allPaths.append(contentsOf: found)
        }

        // Deduplicate
        var seen = Set<String>()
        var uniquePaths: [String] = []
        for path in allPaths {
            if seen.insert(path).inserted {
                uniquePaths.append(path)
            }
        }

        let fm = FileManager.default
        // Apply both user-defined exclusions and damit's canonical built-in
        // exclusions (e.g. Chromium apps ship zxcvbn's `passwords.txt`
        // dictionary under `ZxcvbnData/`; that's a common-passwords wordlist
        // used for strength checking, not the user's credentials).
        let existingPaths = uniquePaths.filter { path in
            guard fm.fileExists(atPath: path) else { return false }
            if BuiltInScanExclusions.isExcluded(path) { return false }
            if ScanExclusions.isExcluded(path) { return false }
            return true
        }
        onProgress?("Found \(existingPaths.count) credential files")

        var allFindings: [Finding] = []
        for (i, path) in existingPaths.enumerated() {
            let filename = (path as NSString).lastPathComponent
            let dir = ((path as NSString).deletingLastPathComponent as NSString).lastPathComponent
            onProgress?("[\(i+1)/\(existingPaths.count)] \(dir)/\(filename)")
            let findings = CredentialFileScanner.scanFile(at: path)
            allFindings.append(contentsOf: findings)
        }

        let duration = Date().timeIntervalSince(start)
        return ScanResult(module: .credentialFiles, findings: allFindings, duration: duration)
    }

    // MARK: - Static File Scanner

    /// Checks a file against dangerous filename patterns and returns a finding if it matches.
    public static func scanFile(at path: String) -> [Finding] {
        let url = URL(fileURLWithPath: path)
        let filename = url.lastPathComponent.lowercased()
        let ext = url.pathExtension.lowercased()

        let isDangerous = dangerousFilenames.contains(filename)
            || dangerousPrefixes.contains { filename.hasPrefix($0) }
            || dangerousExtensions.contains(ext)

        guard isDangerous else { return [] }

        // Peek at the file's contents/format to decide whether it's a
        // genuinely plaintext dump or an encrypted container. This changes
        // how RiskClassifier grades the finding (critical vs. medium).
        let inspection = CredentialFileInspector.inspect(path: path)
        let assessment = RiskClassifier.classifyCredentialFile(
            filePath: path,
            inspection: inspection
        )

        // Prefix the description with the detected format so the user can
        // see at a glance whether damit thinks it's encrypted.
        let description: String
        if inspection.isEncrypted {
            description = "Credential file (\(inspection.format)): \(url.lastPathComponent)"
        } else {
            description = "Credential file found: \(url.lastPathComponent)"
        }

        let finding = Finding(
            id: "cred:\(path)",
            module: .credentialFiles,
            severity: assessment.severity,
            gitRisk: assessment.gitRisk,
            localRisk: assessment.localRisk,
            filePath: path,
            lineNumber: nil,
            description: description,
            secretPreview: url.lastPathComponent,
            recommendation: assessment.recommendation,
            isNew: true
        )

        return [finding]
    }
}
