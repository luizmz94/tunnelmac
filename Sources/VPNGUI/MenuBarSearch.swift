import Foundation

/// Filter and keyboard highlight of the menu's search. Results keep the list order
/// (`sortedConnections`): the list is short and a stable order is predictable.
enum MenuBarSearch {
    /// Name, server and type (and its client), ignoring case and accents; every word must match.
    static func matches(_ connection: Connection, _ query: String) -> Bool {
        let terms = query.split(whereSeparator: \.isWhitespace)
        guard !terms.isEmpty else { return true }
        let haystack = [connection.name, connection.endpoint, connection.kind.title, connection.kind.runtime.title].joined(separator: " ")
        return terms.allSatisfy { haystack.range(of: $0, options: [.caseInsensitive, .diacriticInsensitive]) != nil }
    }

    static func results(_ connections: [Connection], query: String) -> [Connection] {
        connections.filter { matches($0, query) }
    }

    static func isEmpty(_ query: String) -> Bool { query.allSatisfy(\.isWhitespace) }

    /// With text, the first result (Enter acts at once); without text, the only connection, if
    /// there is just one; otherwise nothing until the first arrow, so a stray Enter does nothing.
    static func initialHighlight(results: [Connection], query: String, total: Int) -> UUID? {
        if !isEmpty(query) { return results.first?.id }
        return total == 1 ? results.first?.id : nil
    }

    /// ↓/↑ move one row and stop at the ends (no wrapping); from nothing, the first row.
    static func move(_ current: UUID?, down: Bool, in results: [Connection]) -> UUID? {
        guard !results.isEmpty else { return nil }
        guard let current, let index = results.firstIndex(where: { $0.id == current }) else { return results.first?.id }
        let next = down ? min(index + 1, results.count - 1) : max(index - 1, 0)
        return results[next].id
    }

    /// After the results change: the same row if it is still there, else the first, else none.
    static func adjusted(_ current: UUID?, in results: [Connection]) -> UUID? {
        guard let current else { return nil }
        return results.contains { $0.id == current } ? current : results.first?.id
    }
}

/// Keys the menu handles while its search field has the focus.
enum MenuKey: Equatable {
    case up, down, enter, commandEnter, escape, find
}
