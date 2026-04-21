import Testing
import Foundation
@testable import DevsecCore

@Suite("SSHScanner")
struct SSHScannerTests {

    // MARK: - Helpers

    // Fixtures must carry enough base64 body for SSHScanner to accept the
    // file as a real PEM block (≥100 base64-looking chars between BEGIN
    // and END). The payload contents are arbitrary. what matters is that
    // the envelope looks like a real key, not a documentation reference.
    private let samplePrivateKey = """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQy
    NTUxOQAAACA2Xyj6l5e8Pj5JxSfaKWB7v2CoKQ2ZFyuFXqB9WeaPnAAAAJi8mX3ovJl96AAA
    AAtzc2gtZWQyNTUxOQAAACA2Xyj6l5e8Pj5JxSfaKWB7v2CoKQ2ZFyuFXqB9WeaPnAAAAEBu
    uRCQELXH3vUnFmAl3lQyW7hDjZ0PGRxQWkWNmoNsaDZfKPqXl7w+PknFJ9opYHu/YKgpDZkX
    K4VeoH1Z5o+cAAAAEHRlc3RAZXhhbXBsZS5jb20BAgMEBQ==
    -----END OPENSSH PRIVATE KEY-----
    """

    private let sampleRSAKey = """
    -----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4mZhA9VA8yPzHZRfn6ucFqX2m0xKnwbLmBH
    bEqZGtR04fR7pXOHwpQnDHhzJc9e5yxYYzCk3vRdyJ6QmqC2c+LGa0xYEKpHnnkrLZwOfbN4
    g6TtYoY8Fq9I8TnDvVrS1w2b2Xlzo3mqQ3eT9b3LfPq4wYnR8pXq4mHbOaJz9PvXoCgXhJCf
    fakebutlongenoughbase64payloadcontentforteststAA==
    -----END RSA PRIVATE KEY-----
    """

    private func makeTempKeyFile(
        contents: String,
        filename: String = "id_ed25519",
        permissions: Int = 0o600,
        inSubdir: String? = nil
    ) throws -> (tempDir: URL, filePath: String) {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        let targetDir: URL
        if let subdir = inSubdir {
            targetDir = tempDir.appendingPathComponent(subdir)
        } else {
            targetDir = tempDir
        }
        try FileManager.default.createDirectory(at: targetDir, withIntermediateDirectories: true)
        let fileURL = targetDir.appendingPathComponent(filename)
        try contents.write(to: fileURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: permissions],
            ofItemAtPath: fileURL.path
        )
        return (tempDir, fileURL.path)
    }

    private func cleanup(_ tempDir: URL) {
        try? FileManager.default.removeItem(at: tempDir)
    }

    // MARK: - Private Key Detection

    @Test("Detects OpenSSH private key file by content")
    func detectsOpenSSHPrivateKey() throws {
        let (tempDir, filePath) = try makeTempKeyFile(contents: samplePrivateKey)
        defer { cleanup(tempDir) }

        let findings = SSHScanner.scanKeyFile(at: filePath)
        #expect(!findings.isEmpty)
        #expect(findings.contains { $0.id.contains("ssh:key:") })
    }

    @Test("Detects RSA private key file by content")
    func detectsRSAPrivateKey() throws {
        let (tempDir, filePath) = try makeTempKeyFile(
            contents: sampleRSAKey,
            filename: "id_rsa"
        )
        defer { cleanup(tempDir) }

        let findings = SSHScanner.scanKeyFile(at: filePath)
        #expect(!findings.isEmpty)
    }

    @Test("Returns empty array for file without private key content")
    func returnsEmptyForNonKeyFile() throws {
        let contents = "This is just a regular text file with no private key content."
        let (tempDir, filePath) = try makeTempKeyFile(contents: contents, filename: "readme.txt")
        defer { cleanup(tempDir) }

        let findings = SSHScanner.scanKeyFile(at: filePath)
        #expect(findings.isEmpty)
    }

    // MARK: - Permission Detection

    @Test("Detects insecure permissions on SSH key")
    func detectsBadPermissions() throws {
        // Write key with 0644 permissions (too broad)
        let (tempDir, filePath) = try makeTempKeyFile(
            contents: samplePrivateKey,
            permissions: 0o644
        )
        defer { cleanup(tempDir) }

        let findings = SSHScanner.scanKeyFile(at: filePath)
        let permFindings = findings.filter { $0.id.contains("ssh:perms:") }
        #expect(!permFindings.isEmpty)
    }

    @Test("No permission finding for key with 0600 permissions")
    func noPermissionFindingForSecureKey() throws {
        let (tempDir, filePath) = try makeTempKeyFile(
            contents: samplePrivateKey,
            permissions: 0o600
        )
        defer { cleanup(tempDir) }

        let findings = SSHScanner.scanKeyFile(at: filePath)
        let permFindings = findings.filter { $0.id.contains("ssh:perms:") }
        #expect(permFindings.isEmpty)
    }

    // MARK: - Unsafe Location Detection

    @Test("Detects SSH key in Downloads subdirectory as critical")
    func detectsKeyInUnsafeLocation() throws {
        // Simulate a file path that contains /Downloads/
        // We create the key in a subdirectory named "Downloads"
        let (tempDir, filePath) = try makeTempKeyFile(
            contents: samplePrivateKey,
            inSubdir: "Downloads"
        )
        defer { cleanup(tempDir) }

        let findings = SSHScanner.scanKeyFile(at: filePath)
        let keyFinding = findings.first { $0.id.contains("ssh:key:") }
        #expect(keyFinding != nil)
        #expect(keyFinding?.severity == .critical)
    }

    @Test("SSH key not in unsafe location gets high (not critical) severity")
    func keyInSafeLocationGetsHighSeverity() throws {
        // Use a plain temp directory (no Desktop/Downloads/Documents in path)
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("safedir_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let fileURL = tempDir.appendingPathComponent("id_ed25519")
        try samplePrivateKey.write(to: fileURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: fileURL.path
        )
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let findings = SSHScanner.scanKeyFile(at: fileURL.path)
        let keyFinding = findings.first { $0.id.contains("ssh:key:") }
        #expect(keyFinding != nil)
        #expect(keyFinding?.severity == .high)
    }

    // MARK: - SSH Config Parsing

    @Test("Parses IdentityFile paths from SSH config")
    func parsesIdentityFilePaths() {
        let config = """
        Host github.com
            User git
            IdentityFile ~/.ssh/id_ed25519
            IdentityFile ~/.ssh/github_key

        Host work
            HostName work.example.com
            IdentityFile ~/.ssh/work_rsa
        """
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let paths = SSHScanner.parseIdentityFiles(from: config)
        #expect(paths.count == 3)
        #expect(paths.contains("\(home)/.ssh/id_ed25519"))
        #expect(paths.contains("\(home)/.ssh/github_key"))
        #expect(paths.contains("\(home)/.ssh/work_rsa"))
    }

    @Test("Parses IdentityFile with case-insensitive matching")
    func parsesIdentityFileCaseInsensitive() {
        let config = """
        IDENTITYFILE ~/.ssh/id_rsa
        identityfile ~/.ssh/id_dsa
        IdentityFile ~/.ssh/id_ecdsa
        """
        let paths = SSHScanner.parseIdentityFiles(from: config)
        #expect(paths.count == 3)
    }

    @Test("Returns empty array for config without IdentityFile directives")
    func returnsEmptyForConfigWithoutIdentityFile() {
        let config = """
        Host github.com
            User git
            StrictHostKeyChecking no
        """
        let paths = SSHScanner.parseIdentityFiles(from: config)
        #expect(paths.isEmpty)
    }

    @Test("Expands tilde in IdentityFile paths")
    func expandsTildeInIdentityFilePaths() {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let config = "IdentityFile ~/.ssh/id_ed25519\n"
        let paths = SSHScanner.parseIdentityFiles(from: config)
        #expect(paths.count == 1)
        #expect(paths.first?.hasPrefix(home) == true)
        #expect(paths.first?.contains("~") == false)
    }

    // MARK: - Module and ID

    @Test("Finding has .ssh module")
    func findingHasSSHModule() throws {
        let (tempDir, filePath) = try makeTempKeyFile(contents: samplePrivateKey)
        defer { cleanup(tempDir) }

        let findings = SSHScanner.scanKeyFile(at: filePath)
        #expect(!findings.isEmpty)
        #expect(findings.allSatisfy { $0.module == .ssh })
    }

    @Test("SSHScanner module property returns .ssh")
    func scannerModuleProperty() {
        let scanner = SSHScanner()
        #expect(scanner.module == .ssh)
    }

    // MARK: - PEM Body Validation

    @Test("Header-only documentation mention does not count as a key")
    func rejectsHeaderOnlyMention() {
        // This is how damit's own source and docs end up in the report:
        // the string `-----BEGIN OPENSSH PRIVATE KEY-----` appears as a
        // pattern literal with no matching footer or base64 body.
        let doc = """
        This scanner looks for '-----BEGIN OPENSSH PRIVATE KEY-----'
        headers in files on disk.
        """
        #expect(!SSHScanner.containsRealPrivateKey(doc))
    }

    @Test("BEGIN with tiny body does not count as a key")
    func rejectsTinyBody() {
        // A BEGIN/END pair with only a handful of base64 chars. below the
        // ≥100 threshold. Common in documentation/examples.
        let shortPem = """
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA0Z3V...
        -----END RSA PRIVATE KEY-----
        """
        #expect(!SSHScanner.containsRealPrivateKey(shortPem))
    }

    @Test("Real PEM block with full base64 body is detected")
    func acceptsRealPemBlock() {
        #expect(SSHScanner.containsRealPrivateKey(samplePrivateKey))
        #expect(SSHScanner.containsRealPrivateKey(sampleRSAKey))
    }
}
