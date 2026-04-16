import Testing
import Foundation
@testable import DevsecCore

@Suite("CredentialFileScanner")
struct CredentialFileScannerTests {

    // MARK: - Helpers

    private func makeTempFile(
        contents: String = "some,data,here",
        filename: String
    ) throws -> (tempDir: URL, filePath: String) {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let fileURL = tempDir.appendingPathComponent(filename)
        try contents.write(to: fileURL, atomically: true, encoding: .utf8)
        return (tempDir, fileURL.path)
    }

    private func cleanup(_ tempDir: URL) {
        try? FileManager.default.removeItem(at: tempDir)
    }

    // MARK: - Dangerous Filename Detection

    @Test("Detects passwords.csv as a credential file")
    func detectsPasswordsCSV() throws {
        let (tempDir, filePath) = try makeTempFile(
            contents: "url,username,password\nhttps://example.com,user,p@ssw0rd",
            filename: "passwords.csv"
        )
        defer { cleanup(tempDir) }

        let findings = CredentialFileScanner.scanFile(at: filePath)
        #expect(!findings.isEmpty)
        #expect(findings.contains { $0.id == "cred:\(filePath)" })
    }

    @Test("Detects logins.csv as a credential file")
    func detectsLoginsCSV() throws {
        let (tempDir, filePath) = try makeTempFile(
            contents: "url,username,password\nhttps://bank.com,user,secret",
            filename: "logins.csv"
        )
        defer { cleanup(tempDir) }

        let findings = CredentialFileScanner.scanFile(at: filePath)
        #expect(!findings.isEmpty)
    }

    @Test("Detects .htpasswd as a credential file")
    func detectsHtpasswd() throws {
        let (tempDir, filePath) = try makeTempFile(
            contents: "admin:$apr1$xyz$hashedpassword",
            filename: ".htpasswd"
        )
        defer { cleanup(tempDir) }

        let findings = CredentialFileScanner.scanFile(at: filePath)
        #expect(!findings.isEmpty)
    }

    // MARK: - Password Manager Export Detection

    @Test("Detects 1Password export file")
    func detects1PasswordExport() throws {
        let (tempDir, filePath) = try makeTempFile(
            contents: "title,username,password,url\nGmail,user@gmail.com,p@ssw0rd,https://gmail.com",
            filename: "1password-export-20240101.csv"
        )
        defer { cleanup(tempDir) }

        let findings = CredentialFileScanner.scanFile(at: filePath)
        #expect(!findings.isEmpty)
    }

    @Test("Detects Bitwarden export file")
    func detectsBitwardenExport() throws {
        let (tempDir, filePath) = try makeTempFile(
            contents: "{\"encrypted\":false,\"items\":[]}",
            filename: "bitwarden-export-12345678.json"
        )
        defer { cleanup(tempDir) }

        let findings = CredentialFileScanner.scanFile(at: filePath)
        #expect(!findings.isEmpty)
    }

    @Test("Detects LastPass export file")
    func detectsLastPassExport() throws {
        let (tempDir, filePath) = try makeTempFile(
            contents: "url,username,password,totp,extra,name,grouping,fav",
            filename: "lastpass-export.csv"
        )
        defer { cleanup(tempDir) }

        let findings = CredentialFileScanner.scanFile(at: filePath)
        #expect(!findings.isEmpty)
    }

    // MARK: - Dangerous Extension Detection

    @Test("Detects .p12 certificate file")
    func detectsP12File() throws {
        let (tempDir, filePath) = try makeTempFile(
            contents: "binary certificate data",
            filename: "my-certificate.p12"
        )
        defer { cleanup(tempDir) }

        let findings = CredentialFileScanner.scanFile(at: filePath)
        #expect(!findings.isEmpty)
    }

    @Test("Detects .pfx file")
    func detectsPFXFile() throws {
        let (tempDir, filePath) = try makeTempFile(
            contents: "binary pfx data",
            filename: "server.pfx"
        )
        defer { cleanup(tempDir) }

        let findings = CredentialFileScanner.scanFile(at: filePath)
        #expect(!findings.isEmpty)
    }

    @Test("Detects .keystore file")
    func detectsKeystoreFile() throws {
        let (tempDir, filePath) = try makeTempFile(
            contents: "keystore data",
            filename: "release.keystore"
        )
        defer { cleanup(tempDir) }

        let findings = CredentialFileScanner.scanFile(at: filePath)
        #expect(!findings.isEmpty)
    }

    // MARK: - Skip Non-Credential Files

    @Test("Skips regular files that are not credential files")
    func skipsNonCredentialFiles() throws {
        let (tempDir, filePath) = try makeTempFile(
            contents: "name,email,age\nJohn,john@example.com,30",
            filename: "users.csv"
        )
        defer { cleanup(tempDir) }

        let findings = CredentialFileScanner.scanFile(at: filePath)
        #expect(findings.isEmpty)
    }

    @Test("Skips regular text files")
    func skipsRegularTextFiles() throws {
        let (tempDir, filePath) = try makeTempFile(
            contents: "This is just a readme file.",
            filename: "README.txt"
        )
        defer { cleanup(tempDir) }

        let findings = CredentialFileScanner.scanFile(at: filePath)
        #expect(findings.isEmpty)
    }

    @Test("Skips regular JSON files")
    func skipsRegularJSONFiles() throws {
        let (tempDir, filePath) = try makeTempFile(
            contents: "{\"name\": \"myapp\", \"version\": \"1.0.0\"}",
            filename: "package.json"
        )
        defer { cleanup(tempDir) }

        let findings = CredentialFileScanner.scanFile(at: filePath)
        #expect(findings.isEmpty)
    }

    // MARK: - Finding Fields

    @Test("Finding has .credentialFiles module")
    func findingHasCredentialFilesModule() throws {
        let (tempDir, filePath) = try makeTempFile(filename: "passwords.csv")
        defer { cleanup(tempDir) }

        let findings = CredentialFileScanner.scanFile(at: filePath)
        #expect(!findings.isEmpty)
        #expect(findings.allSatisfy { $0.module == .credentialFiles })
    }

    @Test("Finding has critical severity")
    func findingHasCriticalSeverity() throws {
        let (tempDir, filePath) = try makeTempFile(filename: "passwords.csv")
        defer { cleanup(tempDir) }

        let findings = CredentialFileScanner.scanFile(at: filePath)
        #expect(!findings.isEmpty)
        let f = try #require(findings.first)
        #expect(f.severity == .critical)
    }

    @Test("Finding ID uses cred prefix")
    func findingIDUsesCREDPrefix() throws {
        let (tempDir, filePath) = try makeTempFile(filename: "passwords.csv")
        defer { cleanup(tempDir) }

        let findings = CredentialFileScanner.scanFile(at: filePath)
        #expect(!findings.isEmpty)
        #expect(findings.allSatisfy { $0.id.hasPrefix("cred:") })
    }

    @Test("CredentialFileScanner module property returns .credentialFiles")
    func scannerModuleProperty() {
        let scanner = CredentialFileScanner()
        #expect(scanner.module == .credentialFiles)
    }

    // MARK: - Static Sets Content

    @Test("Dangerous filenames set contains expected entries")
    func dangerousFilenamesContainsExpectedEntries() {
        #expect(CredentialFileScanner.dangerousFilenames.contains("passwords.csv"))
        #expect(CredentialFileScanner.dangerousFilenames.contains("logins.csv"))
        #expect(CredentialFileScanner.dangerousFilenames.contains(".htpasswd"))
    }

    @Test("Dangerous prefixes list contains password manager exports")
    func dangerousPrefixesContainsExportPrefixes() {
        #expect(CredentialFileScanner.dangerousPrefixes.contains("1password-export"))
        #expect(CredentialFileScanner.dangerousPrefixes.contains("bitwarden-export"))
        #expect(CredentialFileScanner.dangerousPrefixes.contains("lastpass-export"))
    }

    @Test("Dangerous extensions set contains certificate extensions")
    func dangerousExtensionsContainsCertExtensions() {
        #expect(CredentialFileScanner.dangerousExtensions.contains("p12"))
        #expect(CredentialFileScanner.dangerousExtensions.contains("pfx"))
        #expect(CredentialFileScanner.dangerousExtensions.contains("keystore"))
        #expect(CredentialFileScanner.dangerousExtensions.contains("jks"))
    }
}
