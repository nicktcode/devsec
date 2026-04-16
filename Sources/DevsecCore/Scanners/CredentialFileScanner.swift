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

    public func scan() async throws -> ScanResult {
        let start = Date()
        let home = FileManager.default.homeDirectoryForCurrentUser.path

        var allPaths: [String] = []

        // Search for exact dangerous filenames
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

        var allFindings: [Finding] = []
        let fm = FileManager.default
        for path in uniquePaths where fm.fileExists(atPath: path) {
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

        let assessment = RiskClassifier.classifyCredentialFile(filePath: path)

        let finding = Finding(
            id: "cred:\(path)",
            module: .credentialFiles,
            severity: assessment.severity,
            gitRisk: assessment.gitRisk,
            localRisk: assessment.localRisk,
            filePath: path,
            lineNumber: nil,
            description: "Credential file found: \(url.lastPathComponent)",
            secretPreview: url.lastPathComponent,
            recommendation: assessment.recommendation,
            isNew: true
        )

        return [finding]
    }
}
