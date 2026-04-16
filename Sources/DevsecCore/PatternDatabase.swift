import Foundation

// MARK: - PatternDatabase

/// Central registry of secret detection patterns used by all scanners.
public enum PatternDatabase {

    // MARK: - Public Types

    public struct SecretMatch: Sendable {
        public let patternName: String
        public let matchedText: String
        public let range: Range<String.Index>
    }

    // MARK: - Public API

    /// Scans `text` against all registered patterns and returns every match found.
    /// Any value that starts with `op://` (1Password secret references) is skipped.
    public static func findSecrets(in text: String) -> [SecretMatch] {
        var results: [SecretMatch] = []
        for entry in patterns {
            var searchStart = text.startIndex
            while searchStart < text.endIndex {
                guard let range = text.range(of: entry.regex, options: .regularExpression, range: searchStart..<text.endIndex) else {
                    break
                }
                let matched = String(text[range])
                // Skip 1Password op:// references
                if !containsOpReference(matched) {
                    results.append(SecretMatch(patternName: entry.name, matchedText: matched, range: range))
                }
                // Advance past this match to avoid infinite loops on zero-length matches
                if range.upperBound > searchStart {
                    searchStart = range.upperBound
                } else {
                    searchStart = text.index(after: searchStart)
                }
            }
        }
        return results
    }

    /// Masks a secret: returns the first 4 characters (or all if shorter) followed by "****".
    public static func maskSecret(_ secret: String) -> String {
        let prefix = String(secret.prefix(4))
        return prefix + "****"
    }

    // MARK: - Spotlight Queries

    /// Key prefixes and distinctive strings suitable for Spotlight `kMDItemTextContent` queries.
    public static let spotlightContentQueries: [String] = [
        "AKIA",
        "sk-ant-api",
        "sk-proj-",
        "ghp_",
        "ghs_",
        "sk_live_",
        "sk_test_",
        "xoxb-",
        "xoxp-",
        "AIzaSy",
        "SG.",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    ]

    /// Filename strings for Spotlight `kMDItemDisplayName` queries.
    public static let spotlightFileQueries: [String] = [
        ".env",
        "credentials",
        "secret",
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        ".pem",
        ".p12",
        ".pfx",
        "htpasswd",
        "netrc",
        ".aws",
    ]

    /// Glob patterns for file-system scanning of credential files.
    public static let spotlightFileGlobs: [String] = [
        "**/.env",
        "**/.env.*",
        "**/credentials",
        "**/credentials.json",
        "**/credentials.csv",
        "**/secret.json",
        "**/secrets.json",
        "**/secrets.yaml",
        "**/secrets.yml",
        "**/*.pem",
        "**/*.p12",
        "**/*.pfx",
        "**/.netrc",
        "**/.htpasswd",
        "**/.aws/credentials",
        "**/.aws/config",
        "**/id_rsa",
        "**/id_ed25519",
        "**/id_ecdsa",
        "**/id_dsa",
        "**/*.key",
    ]

    // MARK: - Private Pattern Table

    private struct PatternEntry {
        let name: String
        let regex: String
    }

    /// Returns `true` when the matched text value resolves to a 1Password `op://` reference,
    /// meaning it is a placeholder rather than an actual credential.
    private static func containsOpReference(_ text: String) -> Bool {
        // Match op:// that appears after an assignment separator (=, :, whitespace) or at start
        let opPattern = #"(?:=|:\s*|\s)op://"#
        if text.range(of: opPattern, options: .regularExpression) != nil { return true }
        // Also catch bare op:// at the very start of the value
        if text.hasPrefix("op://") { return true }
        return false
    }

    // swiftlint:disable line_length
    private static let patterns: [PatternEntry] = [

        // MARK: API Keys

        PatternEntry(
            name: "AWS Access Key",
            // AKIA followed by exactly 16 uppercase alphanumeric characters
            regex: #"AKIA[0-9A-Z]{16}"#
        ),

        PatternEntry(
            name: "Anthropic API Key",
            // sk-ant-api followed by version digits, a dash, then a long base64url string
            regex: #"sk-ant-api\d{2}-[A-Za-z0-9\-_]{80,}"#
        ),

        PatternEntry(
            name: "OpenAI API Key",
            // sk-proj- followed by 40+ alphanumeric/dash chars (new project key format)
            regex: #"sk-proj-[A-Za-z0-9\-_]{40,}"#
        ),

        PatternEntry(
            name: "GitHub Token",
            // ghp_ (personal), ghs_ (server), ghr_ (refresh), or gho_ (oauth)
            regex: #"gh[psor]_[A-Za-z0-9]{36,}"#
        ),

        PatternEntry(
            name: "Stripe API Key",
            // sk_live_ or sk_test_ (secret keys) or rk_live_/rk_test_ (restricted)
            regex: #"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}"#
        ),

        PatternEntry(
            name: "Slack Token",
            // xox[bprs]- followed by segments of alphanumeric chars separated by dashes
            regex: #"xox[bprs]-[0-9A-Za-z\-]{20,}"#
        ),

        PatternEntry(
            name: "Google API Key",
            // AIzaSy followed by exactly 33 chars (URL-safe base64)
            regex: #"AIzaSy[A-Za-z0-9\-_]{33}"#
        ),

        PatternEntry(
            name: "SendGrid API Key",
            // SG. prefix followed by two base64url segments
            regex: #"SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{22,}"#
        ),

        PatternEntry(
            name: "Twilio Auth Token",
            // 32 lowercase hex characters (appears after account SID in assignments)
            regex: #"(?i)(?:twilio.{0,20})?[0-9a-f]{32}(?![0-9a-f])"#
        ),

        PatternEntry(
            name: "Mailgun API Key",
            regex: #"key-[0-9a-zA-Z]{32}"#
        ),

        PatternEntry(
            name: "Heroku API Key",
            // UUID-style key (8-4-4-4-12)
            regex: #"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"#
        ),

        PatternEntry(
            name: "Firebase Config",
            // Firebase project API keys start with AIzaSy but also appear in firebase config objects
            regex: #"\"apiKey\"\s*:\s*\"AIza[A-Za-z0-9\-_]{35}\""#
        ),

        // MARK: Private Keys

        PatternEntry(
            name: "Private Key",
            // Covers RSA, OpenSSH, EC, PGP, DSA, and generic PRIVATE KEY headers
            regex: #"-----BEGIN (?:RSA |OPENSSH |EC |PGP |DSA )?PRIVATE KEY(?:\sBLOCK)?-----"#
        ),

        // MARK: Password Assignments

        PatternEntry(
            name: "Password Assignment",
            // Matches: password=value, passwd: value, pwd=value, secret=value,
            //          api_key=value, token=value, auth=value etc. (not inside op:// refs)
            // Excludes placeholder-style values (YOUR_, <, >, {, })
            regex: #"(?i)(?:^|[\s,;'"&])?(?:password|passwd|pwd|secret|api_key|apikey|api_token|auth_token|access_token|token|auth)\s*[=:]\s*(?!op://|YOUR_|<|>|\{|\})[^\s"']{6,}"#
        ),

        // MARK: Connection Strings

        PatternEntry(
            name: "Connection String",
            // postgres, postgresql, mysql, mongodb, mongodb+srv, redis, rediss, amqp, amqps URLs with credentials
            regex: #"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis(?:s)?|amqps?)://[A-Za-z0-9%._\-+]+:[A-Za-z0-9%._\-+!@#$^&*()]+@[A-Za-z0-9.\-]+"#
        ),

        // MARK: Auth Headers

        PatternEntry(
            name: "Basic Auth Header",
            // Authorization: Basic <base64>
            regex: #"(?i)Authorization\s*:\s*Basic\s+[A-Za-z0-9+/=]{8,}"#
        ),

        PatternEntry(
            name: "Bearer Token",
            // Authorization: Bearer <token> — token must be at least 20 chars to avoid false positives
            regex: #"(?i)Authorization\s*:\s*Bearer\s+[A-Za-z0-9\-._~+/=]{20,}"#
        ),
    ]
    // swiftlint:enable line_length
}
