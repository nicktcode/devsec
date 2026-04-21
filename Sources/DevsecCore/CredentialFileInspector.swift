import Foundation

// MARK: - CredentialFileInspector

/// Inspects credential-shaped files to decide whether they are encrypted
/// containers (low-risk on their own) or plaintext password dumps
/// (high-risk). Used by ``RiskClassifier`` and ``CredentialFileScanner`` to
/// avoid flagging every `.p12` or every Firefox profile as "Critical, 
/// plaintext credentials".
///
/// We never try to *decrypt* anything. We only peek at well-known headers
/// and structure so we can distinguish:
///  - Encrypted-by-spec containers (PKCS#12 `.p12`/`.pfx`, Java keystores).
///  - Encrypted-by-reference stores (Firefox `logins.json` wraps NSS
///    ciphertexts in JSON. useless without `key4.db` and/or the profile
///    master password).
///  - Actual plaintext exports (CSV/JSON/TXT dumps from password managers).
public enum CredentialFileInspector {

    // MARK: - Inspection

    public struct Inspection: Sendable, Equatable {
        /// True if the file's secret content is meaningfully protected at
        /// rest. Does not mean the file is *safe*. losing an encrypted
        /// keystore to a public repo still exposes its passphrase-protected
        /// private keys.
        public let isEncrypted: Bool
        /// Short human-readable name for the detected format, used in the
        /// UI and recommendation string.
        public let format: String

        public init(isEncrypted: Bool, format: String) {
            self.isEncrypted = isEncrypted
            self.format = format
        }
    }

    // MARK: - Public API

    /// Best-effort classification of a file's encryption state.
    /// Returns `(isEncrypted: false, format: "plaintext")` when the file
    /// does not match any known encrypted format.
    public static func inspect(path: String) -> Inspection {
        let filename = (path as NSString).lastPathComponent.lowercased()
        let ext = (filename as NSString).pathExtension

        // PKCS#12 (.p12, .pfx): by RFC 7292 the SafeContents may be unencrypted,
        // but in every practical case these files are password-protected, 
        // tools like `openssl pkcs12 -export`, Apple Keychain, and Java
        // keytool all produce encrypted output.
        if ext == "p12" || ext == "pfx" {
            return Inspection(isEncrypted: true, format: "PKCS#12 container")
        }

        // Java keystores (.keystore, .jks, .ks): always password-protected.
        // JKS magic is FE ED FE ED; JCEKS magic is CE CH ET A5. We accept
        // either. and even if the magic doesn't match (some .keystore
        // files are PKCS#12 under the hood), the format is still encrypted.
        if ext == "keystore" || ext == "jks" || ext == "ks" {
            return Inspection(isEncrypted: true, format: "Java keystore")
        }

        // Firefox / Thunderbird logins.json: the top-level `logins` array
        // has entries with `encryptedUsername`/`encryptedPassword` fields
        // holding base64-encoded NSS ciphertexts. Presence of those strings
        // in the first 64KB is a reliable marker.
        if filename == "logins.json" {
            if fileContainsAny(at: path, substrings: [
                "\"encryptedUsername\"",
                "\"encryptedPassword\"",
            ]) {
                return Inspection(isEncrypted: true, format: "Firefox NSS-encrypted logins")
            }
        }

        // Anything else we can't positively identify as encrypted. Treat as
        // plaintext so the risk classifier keeps its critical rating.
        return Inspection(isEncrypted: false, format: "plaintext")
    }

    // MARK: - Helpers

    /// Reads up to 64 KB from the start of the file and returns true if any
    /// of the given substrings appears. This is enough for JSON header
    /// sniffing without loading arbitrarily large password stores into RAM.
    private static func fileContainsAny(at path: String, substrings: [String]) -> Bool {
        guard let data = try? Data(
            contentsOf: URL(fileURLWithPath: path),
            options: [.alwaysMapped]
        ) else {
            return false
        }
        let slice = data.prefix(65536)
        guard let text = String(data: slice, encoding: .utf8) else { return false }
        return substrings.contains { text.contains($0) }
    }
}
