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

    public func scan() async throws -> ScanResult {
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

        async let contentResults: [[String]] = withTaskGroup(of: [String].self) { group in
            for header in keyHeaders {
                group.addTask {
                    await SpotlightEngine.findFiles(containingText: header, searchPath: home)
                }
            }
            var all: [[String]] = []
            for await result in group {
                all.append(result)
            }
            return all
        }

        // Filename-based discovery
        let keyFilenames = ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "id_ecdsa_sk", "id_ed25519_sk"]
        async let nameResults: [[String]] = withTaskGroup(of: [String].self) { group in
            for name in keyFilenames {
                group.addTask {
                    await SpotlightEngine.findFiles(named: name, searchPath: home)
                }
            }
            var all: [[String]] = []
            for await result in group {
                all.append(result)
            }
            return all
        }

        // SSH config IdentityFile discovery
        let sshConfigPath = "\(home)/.ssh/config"
        var identityFilePaths: [String] = []
        if let configContent = try? String(contentsOfFile: sshConfigPath, encoding: .utf8) {
            identityFilePaths = SSHScanner.parseIdentityFiles(from: configContent)
        }

        let (contentAll, nameAll) = await (contentResults, nameResults)

        // Deduplicate all discovered paths
        var seen = Set<String>()
        var allPaths: [String] = []
        for path in (contentAll.flatMap { $0 }) + (nameAll.flatMap { $0 }) + identityFilePaths {
            if seen.insert(path).inserted {
                allPaths.append(path)
            }
        }

        var allFindings: [Finding] = []
        let fm = FileManager.default
        for path in allPaths where fm.fileExists(atPath: path) {
            let findings = SSHScanner.scanKeyFile(at: path)
            allFindings.append(contentsOf: findings)
        }

        let duration = Date().timeIntervalSince(start)
        return ScanResult(module: .ssh, findings: allFindings, duration: duration)
    }

    // MARK: - Static Key File Scanner

    /// Inspects an SSH key file for private key content, bad permissions, and unsafe location.
    public static func scanKeyFile(at path: String) -> [Finding] {
        guard let contents = try? String(contentsOfFile: path, encoding: .utf8) else {
            return []
        }

        let privateKeyHeaders = [
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "-----BEGIN DSA PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
        ]

        let containsPrivateKey = privateKeyHeaders.contains { contents.contains($0) }
        guard containsPrivateKey else { return [] }

        var findings: [Finding] = []
        let filename = URL(fileURLWithPath: path).lastPathComponent

        // Check for unsafe location (Desktop, Downloads, Documents)
        let unsafeLocations = ["/Desktop/", "/Downloads/", "/Documents/"]
        let isUnsafe = unsafeLocations.contains { path.contains($0) }

        if isUnsafe {
            let finding = Finding(
                id: "ssh:key:\(path)",
                module: .ssh,
                severity: .critical,
                gitRisk: .critical,
                localRisk: .critical,
                filePath: path,
                lineNumber: nil,
                description: "SSH private key in unsafe location: \(filename)",
                secretPreview: "-----BEGIN...-----",
                recommendation: "Move this key to ~/.ssh/ and set permissions to 0600: mv \"\(path)\" ~/.ssh/\(filename) && chmod 600 ~/.ssh/\(filename)",
                isNew: true
            )
            findings.append(finding)
        } else {
            let finding = Finding(
                id: "ssh:key:\(path)",
                module: .ssh,
                severity: .high,
                gitRisk: .high,
                localRisk: .high,
                filePath: path,
                lineNumber: nil,
                description: "SSH private key found: \(filename)",
                secretPreview: "-----BEGIN...-----",
                recommendation: "Ensure this key is protected. Set permissions to 0600: chmod 600 \"\(path)\"",
                isNew: true
            )
            findings.append(finding)
        }

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

        return findings
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
