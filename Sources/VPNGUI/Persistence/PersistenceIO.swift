import Foundation

/// Enqueue persistent mutations in UI request order, then perform all disk/Keychain work
/// on one worker. This also keeps a late cookie write ahead of a subsequent deletion.
@MainActor
enum PersistenceIO {
    private static let queue = DispatchQueue(label: "com.luiz.vpngui.persistence", qos: .userInitiated)
    static func run<T>(_ operation: @escaping @Sendable () throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { continuation.resume(with: Result { try operation() }) }
        }
    }
}
