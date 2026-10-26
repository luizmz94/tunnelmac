import SwiftUI
import AppKit

// Small set of visual pieces shared by the main window, sheets and the menu bar.
// Liquid Glass (macOS 26+) is used on controls (glass button styles grouped in
// GlassEffectContainer); the sidebar uses a native material, while the toolbar and
// menu bar use system chrome. Forms and logs stay opaque for comfortable reading.

/// Semantic color of a state. Color is never the only signal: every use pairs it
/// with a distinct symbol and text.
enum StatusTone: Equatable {
    case neutral, progress, success, warning, danger
    var color: Color {
        switch self {
        case .neutral: return .secondary
        case .progress: return .orange
        case .success: return .green
        case .warning: return .orange
        case .danger: return .red
        }
    }
}

extension ConnectionState {
    var tone: StatusTone {
        switch self {
        case .connected: return .success
        case .failed: return .danger
        case .disconnected: return .neutral
        default: return .progress
        }
    }
    /// Between disconnected/failed and connected, in either direction.
    var inProgress: Bool { active && self != .connected }
    var symbol: String {
        switch self {
        case .connected: return "checkmark.circle.fill"
        case .disconnected: return "circle"
        case .failed: return "xmark.octagon.fill"
        case .disconnecting: return "stop.circle.fill"
        case .reconnecting: return "arrow.triangle.2.circlepath.circle.fill"
        case .waitingForSAML: return "hourglass.circle.fill"
        case .authorizing, .connecting, .authenticating: return "circle.dotted.circle.fill"
        }
    }
}

extension ServiceController.Health {
    var tone: StatusTone {
        switch self {
        case .ready: return .success
        case .checking: return .progress
        case .requiresApproval, .notRegistered, .runtimeMissing, .userNotAuthorized, .outdated: return .warning
        default: return .danger
        }
    }
}

enum Motion {
    /// A short, discreet animation; none when Reduce Motion is on.
    static func state(_ reduceMotion: Bool) -> Animation? { reduceMotion ? nil : .easeInOut(duration: 0.2) }
}

// MARK: - Status

/// State symbol with its color. In-progress states pulse gently (macOS 14+, not with Reduce Motion).
struct StatusSymbol: View {
    let symbol: String
    let tone: StatusTone
    var pulsing = false
    var size: CGFloat = 13
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        let image = Image(systemName: symbol)
            .symbolRenderingMode(.hierarchical)
            .font(.system(size: size, weight: .semibold))
            .foregroundStyle(tone.color)
            .frame(width: size + 6, height: size + 6)
            .accessibilityHidden(true)
        if #available(macOS 14, *) {
            image.symbolEffect(.pulse, options: .repeating, isActive: pulsing && !reduceMotion)
        } else {
            image
        }
    }
}

/// Larger badge used in headers: symbol on a soft tinted circle.
struct StatusBadge: View {
    let symbol: String
    let tone: StatusTone
    var pulsing = false
    var diameter: CGFloat = 44
    var body: some View {
        StatusSymbol(symbol: symbol, tone: tone, pulsing: pulsing, size: diameter * 0.45)
            .frame(width: diameter, height: diameter)
            .background(Circle().fill(tone.color.opacity(0.14)))
            .overlay(Circle().strokeBorder(tone.color.opacity(0.22), lineWidth: 1))
    }
}

/// Connected time, refreshed every second.
struct ElapsedTime: View {
    let start: Date
    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            Text(Session.duration(since: start, at: context.date)).monospacedDigit()
        }
        .accessibilityLabel("Conectada há")
    }
}

/// Compact capsule with the state name and, when connected, the elapsed time.
struct StatePill: View {
    let state: ConnectionState
    let connectedAt: Date?
    var body: some View {
        HStack(spacing: 5) {
            Circle().fill(state.tone.color).frame(width: 7, height: 7).accessibilityHidden(true)
            Text(state.rawValue)
            if let connectedAt, state == .connected {
                Text("·").foregroundStyle(.tertiary).accessibilityHidden(true)
                ElapsedTime(start: connectedAt)
            }
        }
        .font(.caption.weight(.medium))
        .foregroundStyle(state == .disconnected ? Color.secondary : Color.primary)
        .padding(.horizontal, 9).padding(.vertical, 4)
        .background(Capsule().fill(state.tone.color.opacity(state == .disconnected ? 0.10 : 0.16)))
        .accessibilityElement(children: .combine)
    }
}

// MARK: - Surfaces and buttons

extension View {
    /// Glass buttons on macOS 26+, bordered buttons before.
    @ViewBuilder func adaptiveButtonStyle(prominent: Bool = false) -> some View {
        if #available(macOS 26, *) {
            if prominent { buttonStyle(.glassProminent) } else { buttonStyle(.glass) }
        } else {
            if prominent { buttonStyle(.borderedProminent) } else { buttonStyle(.bordered) }
        }
    }
}

extension View {
    /// Content area of a split view. On macOS 26+ it is left to the system, so the sidebar floats
    /// as glass over it and the toolbar fades in with the scroll edge; before, an opaque window color.
    @ViewBuilder func contentBackground() -> some View {
        if #available(macOS 26, *) { self } else { background(Color(nsColor: .windowBackgroundColor)) }
    }
}

/// Groups related glass controls so they render and blend as one (macOS 26+).
struct GlassGroup<Content: View>: View {
    var spacing: CGFloat = 8
    @ViewBuilder var content: Content
    var body: some View {
        if #available(macOS 26, *) {
            GlassEffectContainer(spacing: spacing) { content }
        } else {
            content
        }
    }
}

/// Opaque, readable content panel (forms, logs, inventories).
struct ContentPanel: ViewModifier {
    var cornerRadius: CGFloat = 10
    func body(content: Content) -> some View {
        let shape = RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
        content
            .background(shape.fill(Color(nsColor: .textBackgroundColor)))
            .overlay(shape.strokeBorder(Color(nsColor: .separatorColor), lineWidth: 0.5))
            .clipShape(shape)
    }
}

extension View {
    func contentPanel(cornerRadius: CGFloat = 10) -> some View { modifier(ContentPanel(cornerRadius: cornerRadius)) }

    /// Grouped surface for a block of read-only details, like a System Settings group.
    func cardSurface(cornerRadius: CGFloat = 12) -> some View {
        let shape = RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
        return padding(.horizontal, 16).padding(.vertical, 12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(shape.fill(Color.primary.opacity(0.045)))
            .overlay(shape.strokeBorder(Color(nsColor: .separatorColor), lineWidth: 0.5))
    }
}

// MARK: - Messages

/// Inline message: warnings, errors and pending decisions, with optional actions.
struct InlineNotice<Actions: View>: View {
    let tone: StatusTone
    let symbol: String
    let title: String
    var message: String?
    @ViewBuilder var actions: Actions

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: 10, style: .continuous)
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: symbol)
                .symbolRenderingMode(.hierarchical)
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(tone.color)
                .frame(width: 18)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(message == nil ? .callout : .callout.weight(.semibold))
                    .fixedSize(horizontal: false, vertical: true)
                if let message {
                    Text(message).font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .accessibilityElement(children: .combine)
            actions.controlSize(.small)
        }
        .padding(.horizontal, 12).padding(.vertical, 10)
        .background(shape.fill(tone.color.opacity(0.09)))
        .overlay(shape.strokeBorder(tone.color.opacity(0.28), lineWidth: 0.75))
    }
}

extension InlineNotice where Actions == EmptyView {
    init(tone: StatusTone, symbol: String, title: String, message: String? = nil) {
        self.init(tone: tone, symbol: symbol, title: title, message: message) { EmptyView() }
    }
}

/// Centered empty or unavailable state (ContentUnavailableView requires macOS 14).
struct EmptyStateView<Actions: View>: View {
    let symbol: String
    let title: String
    var message: String?
    var tone: StatusTone = .neutral
    @ViewBuilder var actions: Actions

    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: symbol)
                .symbolRenderingMode(.hierarchical)
                .font(.system(size: 40, weight: .light))
                .foregroundStyle(tone == .neutral ? Color.secondary : tone.color)
                .padding(.bottom, 4)
                .accessibilityHidden(true)
            Text(title).font(.title3.weight(.semibold)).multilineTextAlignment(.center)
            if let message {
                Text(message).font(.callout).foregroundStyle(.secondary)
                    .multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: 360)
            }
            actions.padding(.top, 6)
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

extension EmptyStateView where Actions == EmptyView {
    init(symbol: String, title: String, message: String? = nil, tone: StatusTone = .neutral) {
        self.init(symbol: symbol, title: title, message: message, tone: tone) { EmptyView() }
    }
}

/// Header shared by sheets: badge, title and an optional subtitle.
struct SheetHeader: View {
    let symbol: String
    let tone: StatusTone
    let title: String
    var subtitle: String?
    var body: some View {
        HStack(alignment: .center, spacing: 14) {
            StatusBadge(symbol: symbol, tone: tone, diameter: 40)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.title3.weight(.semibold)).fixedSize(horizontal: false, vertical: true)
                if let subtitle {
                    Text(subtitle).font(.callout).foregroundStyle(.secondary)
                        .lineLimit(2).truncationMode(.middle)
                }
            }
            Spacer(minLength: 0)
        }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isHeader)
    }
}

/// Fixed footer bar of a sheet, on top of a hairline.
struct SheetFooter<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        VStack(spacing: 0) {
            Divider()
            HStack(spacing: 10) { content }
                .padding(.horizontal, 20).padding(.vertical, 14)
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }
}

// MARK: - Logs

/// Monospaced, selectable log on an opaque background. Follows new lines while the
/// view is shown; the parent caps the number of lines.
struct LogConsole: View {
    let lines: [String]
    private static let bottom = "log-bottom"

    var body: some View {
        Group {
            if lines.isEmpty {
                VStack(spacing: 6) {
                    Image(systemName: "text.alignleft").font(.system(size: 22, weight: .light)).foregroundStyle(.tertiary)
                        .accessibilityHidden(true)
                    Text("Nenhum registro nesta sessão").font(.callout).foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollViewReader { proxy in
                    ScrollView(.vertical) {
                        VStack(alignment: .leading, spacing: 0) {
                            Text(lines.joined(separator: "\n"))
                                .font(.system(.callout, design: .monospaced))
                                .lineSpacing(2)
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .topLeading)
                                .fixedSize(horizontal: false, vertical: true)
                            Color.clear.frame(height: 1).id(Self.bottom)
                        }
                        .padding(12)
                    }
                    .onAppear { proxy.scrollTo(Self.bottom, anchor: .bottom) }
                    .onChange(of: lines.count) { _ in proxy.scrollTo(Self.bottom, anchor: .bottom) }
                }
            }
        }
        .contentPanel(cornerRadius: 12)
        .accessibilityLabel(lines.isEmpty ? "Logs vazios" : "Logs da conexão")
    }
}

/// Mouse hover state for rows (also exposed to keyboard focus by the caller).
struct HoverHighlight: ViewModifier {
    var cornerRadius: CGFloat = 8
    @State private var hovering = false
    func body(content: Content) -> some View {
        content
            .background(RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                .fill(Color.primary.opacity(hovering ? 0.06 : 0)))
            .onHover { hovering = $0 }
    }
}
