import Foundation
import Security

/// Strength of a backup password, estimated like the meters in macOS apps: character
/// variety and length, minus what an attacker guesses first (common words, repeats,
/// keyboard and alphabet sequences). Exports require `.strong` or better.
enum BackupPassword {
    enum Strength: Int, Comparable {
        case veryWeak, weak, fair, strong, veryStrong
        static func < (a: Strength, b: Strength) -> Bool { a.rawValue < b.rawValue }
        var title: String {
            switch self {
            case .veryWeak: return "Muito fraca"
            case .weak: return "Fraca"
            case .fair: return "Razoável"
            case .strong: return "Forte"
            case .veryStrong: return "Muito forte"
            }
        }
    }

    struct Evaluation: Equatable {
        var bits: Double
        var strength: Strength
        /// What to change, most important first; empty when nothing obvious is left.
        var hints: [String]
        var acceptable: Bool { strength >= BackupPassword.required }
    }

    static let required = Strength.strong
    static let minimumLength = 12

    /// Guessed first by any cracking list (lowercased, accents removed). Includes the app's own words.
    static let commonWords = [
        "password", "passw0rd", "senha", "s3nha", "qwerty", "asdf", "zxcv", "admin", "root", "letmein", "welcome", "iloveyou",
        "monkey", "dragon", "master", "login", "abc123", "123456", "654321", "111111", "000000", "121212", "teste", "test",
        "brasil", "brazil", "amor", "deus", "jesus", "flamengo", "corinthians", "palmeiras", "mudar", "trocar", "segredo",
        "secret", "backup", "tunnelmac", "vpn", "fortinet", "openvpn", "wireguard", "macbook", "apple", "empresa", "trabalho",
    ]
    private static let keyboardRows = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]

    static func evaluate(_ password: String) -> Evaluation {
        let characters = Array(password)
        guard !characters.isEmpty else { return Evaluation(bits: 0, strength: .veryWeak, hints: ["Digite uma senha."]) }
        var hints: [String] = []

        let hasLower = characters.contains { $0.isLowercase }, hasUpper = characters.contains { $0.isUppercase }
        let hasDigit = characters.contains { $0.isNumber }
        let hasSymbol = characters.contains { !$0.isLetter && !$0.isNumber }
        let hasOther = characters.contains { $0.isLetter && !$0.isASCII }
        var pool = 0
        if hasLower { pool += 26 }
        if hasUpper { pool += 26 }
        if hasDigit { pool += 10 }
        if hasSymbol { pool += 33 }
        if hasOther { pool += 40 }
        let perCharacter = log2(Double(max(pool, 2)))

        // Common words count as one guess from a short list, wherever they appear.
        let folded = password.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: nil)
        let leet: [Character: Character] = ["0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"]
        let unleeted = String(folded.map { leet[$0] ?? $0 })
        var covered = [Bool](repeating: false, count: characters.count)
        var wordsFound = 0
        for word in commonWords.sorted(by: { $0.count > $1.count }) {
            for text in [folded, unleeted] where text.count == characters.count {
                var search = text.startIndex
                while let range = text.range(of: word, range: search..<text.endIndex) {
                    let start = text.distance(from: text.startIndex, to: range.lowerBound)
                    if !covered[start..<(start + word.count)].allSatisfy({ $0 }) { wordsFound += 1 }
                    for index in start..<(start + word.count) { covered[index] = true }
                    search = range.upperBound
                }
            }
        }

        // A run of 4+ letters cased like a word ("lago", "Dourado", "AZUL") is guessed from a
        // dictionary: about 2.5 bits per letter instead of the full alphabet.
        var wordLike = [Bool](repeating: false, count: characters.count)
        var runStart = 0
        for index in 0...characters.count {
            guard index == characters.count || !characters[index].isLetter else { continue }
            let run = characters[runStart..<index]
            if run.count >= 4 {
                let tail = run.dropFirst()
                if tail.allSatisfy({ $0.isLowercase }) || run.allSatisfy({ $0.isUppercase }) {
                    for position in runStart..<index { wordLike[position] = true }
                }
            }
            runStart = index + 1
        }
        // A four-digit year (1900–2039) is one guess from a short list, like a common word.
        var digitStart = 0
        for index in 0...characters.count {
            guard index == characters.count || !characters[index].isNumber else { continue }
            if index - digitStart == 4, let year = Int(String(characters[digitStart..<index])), (1900...2039).contains(year),
               !covered[digitStart..<index].contains(true) {
                wordsFound += 1
                for position in digitStart..<index { covered[position] = true }
            }
            digitStart = index + 1
        }
        var bits = Double(wordsFound) * 10
        var dictionaryWords = 0
        var repeats = 0, sequences = 0
        let lowered = Array(folded)
        for index in characters.indices where !covered[index] {
            if wordLike[index] {
                if index == 0 || !wordLike[index - 1] { dictionaryWords += 1 }
                bits += 2.5; continue
            }
            guard index > 0 else { bits += perCharacter; continue }
            let previous = lowered[index - 1], current = lowered[index]
            if previous == current { repeats += 1; bits += 1; continue }
            if let a = previous.unicodeScalars.first?.value, let b = current.unicodeScalars.first?.value,
               previous.isLetter == current.isLetter, previous.isNumber == current.isNumber,
               (previous.isLetter || previous.isNumber), abs(Int(a) - Int(b)) == 1 {
                sequences += 1; bits += 1; continue
            }
            if keyboardRows.contains(where: { $0.contains(String([previous, current])) }) { sequences += 1; bits += 1.5; continue }
            bits += perCharacter
        }

        if characters.count < minimumLength { hints.append("Use pelo menos \(minimumLength) caracteres.") }
        if wordsFound > 0 { hints.append("Evite palavras e senhas comuns, como \u{201C}senha\u{201D}, \u{201C}123456\u{201D} ou anos.") }
        if dictionaryWords > 0 && bits < 70 {
            hints.append("Palavras inteiras valem pouco: acrescente mais palavras ou troque letras por números e símbolos no meio delas.")
        }
        if repeats + sequences >= 2 { hints.append("Evite repetições e sequências, como \u{201C}aaa\u{201D}, \u{201C}abc\u{201D} ou \u{201C}qwe\u{201D}.") }
        if [hasLower, hasUpper, hasDigit, hasSymbol || hasOther].filter({ $0 }).count < 3 {
            hints.append("Misture letras maiúsculas e minúsculas, números e símbolos.")
        }

        var strength: Strength
        switch bits {
        case ..<30: strength = .veryWeak
        case ..<50: strength = .weak
        case ..<70: strength = .fair
        case ..<90: strength = .strong
        default: strength = .veryStrong
        }
        // Length is never optional: a short password stays below what an export accepts.
        if characters.count < minimumLength { strength = min(strength, .fair) }
        return Evaluation(bits: bits, strength: strength, hints: hints)
    }

    static func check(_ password: String) throws {
        let evaluation = evaluate(password)
        guard evaluation.acceptable else {
            throw AppFailure("Senha \(evaluation.strength.title.lowercased()) para o backup. " + (evaluation.hints.first ?? "Use uma senha mais longa."))
        }
    }

    /// Same shape as the strong passwords suggested by macOS: three groups of six
    /// letters and digits ("xKq7mt-baRv2d-…"), at least one capital and one digit,
    /// no look-alike characters. About 105 bits from the system's secure random source.
    static func generate() -> String {
        let lower = Array("abcdefghijkmnopqrstuvwxyz"), upper = Array("ABCDEFGHJKLMNPQRSTUVWXYZ"), digits = Array("23456789")
        let all = lower + upper + digits
        while true {
            var groups: [String] = []
            for _ in 0..<3 { groups.append(String((0..<6).map { _ in all[uniform(all.count)] })) }
            let text = groups.joined(separator: "-")
            if text.contains(where: { upper.contains($0) }), text.contains(where: { digits.contains($0) }),
               text.contains(where: { lower.contains($0) }), evaluate(text).acceptable { return text }
        }
    }

    /// Unbiased index from SecRandomCopyBytes (rejection sampling).
    private static func uniform(_ bound: Int) -> Int {
        let limit = UInt32.max - UInt32.max % UInt32(bound)
        while true {
            var value: UInt32 = 0
            let status = withUnsafeMutableBytes(of: &value) { SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
            precondition(status == errSecSuccess, "Gerador aleatório do sistema indisponível")
            if value < limit { return Int(value % UInt32(bound)) }
        }
    }
}
