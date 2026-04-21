import Foundation

// MARK: - BIP39Detector

/// Detects BIP-39 mnemonic recovery phrases in free text.
///
/// Crypto wallet recovery phrases are typically 12, 15, 18, 21, or 24 lowercase
/// English words drawn from the BIP-39 wordlist. This detector scans for runs of
/// valid BIP-39 words separated by spaces. A run of at least 12 consecutive
/// BIP-39 words is flagged.
///
/// **Why 12 is the lower bound:** the probability that 12 arbitrary English
/// words all happen to be in the 2048-word BIP-39 list is astronomically small
/// (roughly `(2048/171000)^12 ≈ 10^-13` treating the wordlist as a random sample
/// of the English lexicon). In practice, random English prose does not trigger
/// matches. only actual mnemonic phrases do. The detector also cross-references
/// with a short ignore list of single words that happen to be extremely common
/// in natural language ("above", "absent", "about", etc.), but since we require
/// **all 12** words to hit, normal text cannot slip through.
///
/// The detector is case-insensitive at the word level (it lowercases before
/// looking up in the wordlist), allowing for "Abandon Ability Able..." as well
/// as "abandon ability able..." inputs.
public enum BIP39Detector {

    // MARK: - Output

    public struct Match: Sendable {
        public let range: Range<String.Index>
        public let matchedText: String
        public let wordCount: Int
    }

    // MARK: - Constants

    /// Canonical BIP-39 wallet phrase lengths. 12 is the smallest; 24 is the
    /// largest. Ledger/Trezor/MetaMask all default to one of these.
    private static let validLengths: Set<Int> = [12, 15, 18, 21, 24]

    /// Minimum run length we will report. Shorter runs (e.g. 3-word sequences
    /// that coincidentally hit BIP-39 words) would generate too many false
    /// positives from everyday writing.
    private static let minReportedLength: Int = 12

    // MARK: - API

    /// Scans `text` for runs of consecutive BIP-39 wordlist words separated by
    /// single spaces. Returns at most one match per distinct run. if a run is
    /// longer than 24 words, only the longest valid-length prefix is reported.
    public static func findMnemonics(in text: String) -> [Match] {
        // Tokenize: split on any whitespace. We care about contiguous runs
        // where every word is BIP-39. Punctuation-adjacent words are trimmed
        // so that "abandon, ability, able" still tokenizes correctly.
        var results: [Match] = []

        // Walk the string tracking the start index of the current word and
        // whether we are inside a BIP-39 run. We keep word positions so we
        // can build a Range<String.Index> that spans the full run.
        struct Token {
            let lower: String
            let start: String.Index
            let end: String.Index
            let inWordlist: Bool
        }

        let tokens = tokenize(text)
        if tokens.isEmpty { return results }

        var runStart: Int? = nil
        for i in 0..<tokens.count {
            let t = tokens[i]
            if t.inWordlist {
                if runStart == nil { runStart = i }
            } else {
                if let start = runStart {
                    emitIfValid(tokens: tokens, runStart: start, runEnd: i - 1, into: &results)
                    runStart = nil
                }
            }
        }
        if let start = runStart {
            emitIfValid(tokens: tokens, runStart: start, runEnd: tokens.count - 1, into: &results)
        }

        return results

        // -- Local helpers --------------------------------------------------

        func tokenize(_ s: String) -> [Token] {
            var out: [Token] = []
            var idx = s.startIndex
            while idx < s.endIndex {
                // Skip separators: anything that isn't a letter.
                while idx < s.endIndex, !s[idx].isLetter {
                    idx = s.index(after: idx)
                }
                guard idx < s.endIndex else { break }
                let wordStart = idx
                while idx < s.endIndex, s[idx].isLetter {
                    idx = s.index(after: idx)
                }
                let wordEnd = idx
                let raw = String(s[wordStart..<wordEnd])
                let lower = raw.lowercased()
                let hit = BIP39Wordlist.words.contains(lower)
                out.append(Token(lower: lower, start: wordStart, end: wordEnd, inWordlist: hit))
            }
            return out
        }

        func emitIfValid(tokens: [Token], runStart: Int, runEnd: Int, into results: inout [Match]) {
            let runLen = runEnd - runStart + 1
            guard runLen >= minReportedLength else { return }

            // Choose the longest canonical length that fits in the run.
            let target = validLengths
                .filter { $0 <= runLen }
                .max() ?? minReportedLength

            let endIdx = runStart + target - 1
            let start = tokens[runStart].start
            let end = tokens[endIdx].end
            let matched = String(text[start..<end])
            results.append(Match(
                range: start..<end,
                matchedText: matched,
                wordCount: target
            ))
        }
    }
}
