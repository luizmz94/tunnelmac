import Foundation
import VPNHelperShared

/// Minimal Mach-O reader/patcher for the managed runtime copy.
/// Reads load commands of a thin 64-bit image of the host architecture and rewrites
/// dependency/rpath strings in place (only when the new string fits the existing
/// command, exactly like install_name_tool without header growth). Code and data
/// sections are never modified; the caller re-signs the result.
public struct MachOImage {
    enum Command: UInt32 {
        case loadDylib = 0xc, idDylib = 0xd, loadDylinker = 0xe, idDylinker = 0xf
        case lazyLoadDylib = 0x20, dyldEnvironment = 0x27
        case loadWeakDylib = 0x80000018, rpath = 0x8000001c, reexportDylib = 0x8000001f, loadUpwardDylib = 0x80000023
        var isDependency: Bool { [.loadDylib, .loadWeakDylib, .reexportDylib, .lazyLoadDylib, .loadUpwardDylib].contains(self) }
    }
    struct StringCommand {
        let command: Command
        let offset: Int       // start of the load command
        let size: Int         // cmdsize
        let stringOffset: Int // lc_str offset from the command start
        let value: String
    }

    static let executable: UInt32 = 2
    static let dylib: UInt32 = 6
    #if arch(arm64)
    static let hostCPU: UInt32 = 0x0100000C
    #else
    static let hostCPU: UInt32 = 0x01000007
    #endif

    public private(set) var data: Data
    public let fileType: UInt32
    private(set) var strings: [StringCommand] = []

    public var dependencies: [String] { strings.filter { $0.command.isDependency }.map(\.value) }
    public var rpaths: [String] { strings.filter { $0.command == .rpath }.map(\.value) }
    public var installName: String? { strings.first { $0.command == .idDylib }?.value }
    var dylinker: String? { strings.first { $0.command == .loadDylinker }?.value }
    var hasDyldEnvironment: Bool { strings.contains { $0.command == .dyldEnvironment } }

    /// Extracts the host slice from a fat file, or validates a thin one.
    public init(file: Data) throws {
        let thin = try Self.hostSlice(file)
        data = thin
        guard thin.count >= 32, Self.u32(thin, 0) == 0xfeedfacf else {
            throw failure(.runtimeRejected, "Somente executáveis Mach-O de 64 bits são aceitos.")
        }
        guard Self.u32(thin, 4) == Self.hostCPU else { throw failure(.runtimeRejected, "Arquitetura diferente da deste Mac.") }
        fileType = Self.u32(thin, 12)
        let count = Int(Self.u32(thin, 16)), total = Int(Self.u32(thin, 20))
        guard count > 0, count < 4096, 32 + total <= thin.count else { throw failure(.runtimeRejected, "Cabeçalho Mach-O inválido.") }
        var offset = 32
        for _ in 0..<count {
            guard offset + 8 <= 32 + total else { throw failure(.runtimeRejected, "Comandos Mach-O truncados.") }
            let raw = Self.u32(thin, offset), size = Int(Self.u32(thin, offset + 4))
            guard size >= 8, size % 8 == 0, offset + size <= 32 + total else { throw failure(.runtimeRejected, "Comando Mach-O inválido.") }
            if let command = Command(rawValue: raw) {
                guard size >= 16 else { throw failure(.runtimeRejected, "Comando Mach-O curto.") }
                let stringOffset = Int(Self.u32(thin, offset + 8))
                guard stringOffset >= 12, stringOffset < size else { throw failure(.runtimeRejected, "Texto de comando Mach-O inválido.") }
                let start = offset + stringOffset, end = offset + size
                let bytes = thin[start..<end]
                guard let terminator = bytes.firstIndex(of: 0) else { throw failure(.runtimeRejected, "Texto de comando Mach-O sem terminador.") }
                let value = String(decoding: thin[start..<terminator], as: UTF8.self)
                strings.append(StringCommand(command: command, offset: offset, size: size, stringOffset: stringOffset, value: value))
            }
            offset += size
        }
    }

    /// Rewrites every string command whose current value is a key of `replacements`.
    /// Fails closed when a replacement does not fit.
    mutating func rewrite(_ replacements: [String: String], commands: Set<Command>) throws {
        for entry in strings where commands.contains(entry.command) {
            guard let replacement = replacements[entry.value] else { continue }
            let capacity = entry.size - entry.stringOffset
            let bytes = Array(replacement.utf8)
            guard bytes.count + 1 <= capacity, !bytes.contains(0) else {
                throw failure(.runtimeRejected, "Caminho de dependência não cabe no comando Mach-O: \(entry.value)")
            }
            let start = entry.offset + entry.stringOffset
            data.replaceSubrange(start..<(start + capacity), with: bytes + [UInt8](repeating: 0, count: capacity - bytes.count))
        }
        self = try MachOImage(file: data)
    }

    /// Whether `replacement` fits every command in `commands` whose current value is `value`.
    func fits(_ replacement: String, for value: String, commands: Set<Command>) -> Bool {
        strings.allSatisfy { !commands.contains($0.command) || $0.value != value || replacement.utf8.count + 1 <= $0.size - $0.stringOffset }
    }

    static func u32(_ data: Data, _ offset: Int) -> UInt32 {
        let base = data.startIndex + offset
        return UInt32(data[base]) | UInt32(data[base + 1]) << 8 | UInt32(data[base + 2]) << 16 | UInt32(data[base + 3]) << 24
    }
    static func be32(_ data: Data, _ offset: Int) -> UInt32 { u32(data, offset).byteSwapped }
    static func be64(_ data: Data, _ offset: Int) -> UInt64 { UInt64(be32(data, offset)) << 32 | UInt64(be32(data, offset + 4)) }

    static func hostSlice(_ file: Data) throws -> Data {
        guard file.count >= 8 else { throw failure(.runtimeRejected, "Arquivo Mach-O inválido.") }
        let magic = be32(file, 0)
        guard magic == 0xcafebabe || magic == 0xcafebabf else { return Data(file) }
        let count = Int(be32(file, 4))
        let wide = magic == 0xcafebabf
        let entry = wide ? 32 : 20
        guard count > 0, count < 32, 8 + count * entry <= file.count else { throw failure(.runtimeRejected, "Cabeçalho universal inválido.") }
        for index in 0..<count {
            let base = 8 + index * entry
            guard be32(file, base) == hostCPU else { continue }
            guard let offset = Int(exactly: wide ? be64(file, base + 8) : UInt64(be32(file, base + 8))),
                  let size = Int(exactly: wide ? be64(file, base + 16) : UInt64(be32(file, base + 12))),
                  offset >= 8 + count * entry, size > 0, offset <= file.count, size <= file.count - offset else { throw failure(.runtimeRejected, "Fatia universal inválida.") }
            return file.subdata(in: (file.startIndex + offset)..<(file.startIndex + offset + size))
        }
        throw failure(.runtimeRejected, "O arquivo não contém a arquitetura deste Mac.")
    }

    public static func isMachO(_ file: Data) -> Bool {
        guard file.count >= 4 else { return false }
        return [0xfeedfacf, 0xfeedface].contains(u32(file, 0)) || [0xcafebabe, 0xcafebabf].contains(be32(file, 0))
    }
}
