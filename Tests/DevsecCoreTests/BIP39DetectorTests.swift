import Testing
@testable import DevsecCore

@Suite("BIP39Detector")
struct BIP39DetectorTests {

    // The canonical BIP-39 test vector from the BIPs repo. This is a well-known
    // public mnemonic used for testing, not a real wallet.
    private let sampleMnemonic12 =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    private let sampleMnemonic24 =
        "legal winner thank year wave sausage worth useful legal winner thank yellow " +
        "legal winner thank year wave sausage worth useful legal winner thank yellow"

    // MARK: - Positive cases

    @Test("Detects 12-word BIP-39 mnemonic")
    func detects12Word() {
        let matches = BIP39Detector.findMnemonics(in: sampleMnemonic12)
        #expect(matches.count == 1)
        #expect(matches.first?.wordCount == 12)
    }

    @Test("Detects 24-word BIP-39 mnemonic")
    func detects24Word() {
        let matches = BIP39Detector.findMnemonics(in: sampleMnemonic24)
        #expect(matches.count == 1)
        #expect(matches.first?.wordCount == 24)
    }

    @Test("Detects mnemonic embedded in surrounding text")
    func detectsEmbedded() {
        let text = "My recovery phrase is: \(sampleMnemonic12). do not share!"
        let matches = BIP39Detector.findMnemonics(in: text)
        #expect(matches.count == 1)
    }

    @Test("Detects mnemonic with mixed case words")
    func detectsMixedCase() {
        let text = "Abandon Abandon ABANDON abandon abandon abandon abandon abandon abandon abandon abandon about"
        let matches = BIP39Detector.findMnemonics(in: text)
        #expect(matches.count == 1)
    }

    @Test("Detects mnemonic separated by commas")
    func detectsCommaSeparated() {
        let text = "abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, abandon, about"
        let matches = BIP39Detector.findMnemonics(in: text)
        #expect(matches.count == 1)
    }

    // MARK: - Negative cases

    @Test("Does not flag normal English prose")
    func noFalsePositiveOnProse() {
        let text = "The quick brown fox jumps over the lazy dog. Lorem ipsum dolor sit amet."
        let matches = BIP39Detector.findMnemonics(in: text)
        #expect(matches.isEmpty)
    }

    @Test("Does not flag partial runs shorter than 12 words")
    func noMatchOnShortRun() {
        // 11 valid words in a row. below the threshold
        let text = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
        let matches = BIP39Detector.findMnemonics(in: text)
        #expect(matches.isEmpty)
    }

    @Test("Does not flag BIP-39 words interrupted by non-wordlist words")
    func noMatchWhenInterrupted() {
        // Six BIP-39 words, then a non-BIP-39 word, then six more
        let text = "abandon abandon abandon abandon abandon abandon NOTAWORD abandon abandon abandon abandon abandon abandon"
        let matches = BIP39Detector.findMnemonics(in: text)
        #expect(matches.isEmpty)
    }

    @Test("Integrates with PatternDatabase")
    func integratesWithPatternDatabase() {
        let matches = PatternDatabase.findSecrets(in: sampleMnemonic12)
        #expect(matches.contains { $0.patternName == "Crypto Recovery Phrase" })
    }
}
