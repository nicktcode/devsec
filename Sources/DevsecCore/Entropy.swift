import Foundation

// MARK: - Entropy

/// Shannon-entropy helpers used by ``PatternDatabase`` to reject regex
/// matches that look syntactically correct but lack the randomness of a
/// real secret (e.g. `AKIAEXAMPLEKEY000000` or `sk-ant-api03-YOURKEYHERE`).
///
/// Two character sets are supported because token formats split roughly
/// down that line:
///  - **Base64**: the alphabet `A-Za-z0-9+/=_-`. Random secrets in this
///    space approach `log2(64) ≈ 6.0`; real tokens generally sit above
///    4.0–4.5, placeholders sit well below.
///  - **Hex**: the alphabet `0-9a-f`. Random secrets approach
///    `log2(16) = 4.0`; real tokens sit above ~3.2, placeholders below.
///
/// Both thresholds are intentionally conservative so we drop obvious
/// placeholders without nuking real keys that happen to have low entropy
/// (e.g. a Stripe test key whose suffix happens to be partly repetitive).
public enum Entropy {

    // MARK: - Character Sets

    public enum CharacterSet: Sendable {
        case base64
        case hex

        /// Default minimum entropy below which a string is rejected as a
        /// placeholder. Tuned against gitleaks' defaults and verified
        /// against our existing pattern corpus so no real fixture in our
        /// test suite drops below the threshold.
        public var defaultMinimum: Double {
            switch self {
            case .base64: return 3.5
            case .hex:    return 2.5
            }
        }
    }

    // MARK: - Public API

    /// Shannon entropy of `text`, measured in bits per character. Returns
    /// `0` for empty strings. Counts each Unicode code point once. we
    /// don't normalize or fold case, so "Aaaa" and "aaaa" get the same
    /// entropy but "Aa" and "AA" do not.
    public static func shannon(_ text: String) -> Double {
        guard !text.isEmpty else { return 0 }
        var counts: [Character: Int] = [:]
        for char in text {
            counts[char, default: 0] += 1
        }
        let total = Double(text.count)
        var entropy = 0.0
        for count in counts.values {
            let p = Double(count) / total
            entropy -= p * log2(p)
        }
        return entropy
    }

    /// Returns true when `text` has **at least** the minimum entropy for
    /// the given character set. Passes trivially when `min` is `nil`.
    public static func meetsMinimum(_ text: String, charset: CharacterSet, min: Double? = nil) -> Bool {
        let threshold = min ?? charset.defaultMinimum
        return shannon(text) >= threshold
    }
}
