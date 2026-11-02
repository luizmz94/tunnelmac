import SwiftUI
import AppKit
import Combine

// A small floating panel under the menu bar icon while connections start, connect or fail,
// whatever started them (menu, window, search, shortcut or an automatic reconnect). It never
// takes the focus; its buttons work with a click.

/// Cards of the progress panel. Pure: the clock is passed in.
struct ConnectionProgressModel: Equatable {
    static let maxVisible = 4
    /// A connected card disappears on its own after this.
    static let connectedLinger: TimeInterval = 2.5

    struct Card: Identifiable, Equatable {
        /// The connection's id.
        let id: UUID
        var name: String
        var endpoint: String
        var state: ConnectionState
        /// Reconnection attempt (1 to 3) while reconnecting.
        var attempt = 0
        /// Why it failed (already free of secrets: built from filtered logs).
        var reason: String?
        /// The gateway refused the credentials: Revisar… instead of Ver logs.
        var reviewable = false
        var dismissAt: Date?
    }

    /// Newest first.
    private(set) var cards: [Card] = []

    var visible: [Card] { Array(cards.prefix(Self.maxVisible)) }
    var overflow: Int { max(cards.count - Self.maxVisible, 0) }
    var nextDeadline: Date? { cards.compactMap(\.dismissAt).min() }

    /// A session changed state. A card starts when a connection goes from inactive to active,
    /// or when it starts reconnecting; it follows the session until it connects (and fades
    /// after 2.5 s), fails (and stays until closed) or is disconnected by the user (gone at once).
    mutating func apply(id: UUID, name: String, endpoint: String, from old: ConnectionState, to new: ConnectionState,
                        attempt: Int, failure: () -> (reason: String, reviewable: Bool), enabled: Bool, now: Date) {
        let index = cards.firstIndex { $0.id == id }
        switch new {
        case .disconnecting, .disconnected:
            if let index { cards.remove(at: index) }
        case .connected:
            guard let index else { return }
            cards[index].state = .connected
            cards[index].endpoint = endpoint
            cards[index].dismissAt = now.addingTimeInterval(Self.connectedLinger)
        case .failed:
            guard let index else { return }
            let failure = failure()
            cards[index].state = .failed
            cards[index].reason = failure.reason
            cards[index].reviewable = failure.reviewable
            cards[index].dismissAt = nil
        case .authorizing, .waitingForSAML, .connecting, .authenticating, .reconnecting:
            if let index {
                cards[index].state = new
                cards[index].attempt = attempt
                cards[index].reason = nil
                cards[index].dismissAt = nil
            } else if enabled, !old.active || new == .reconnecting {
                cards.insert(Card(id: id, name: name, endpoint: endpoint, state: new, attempt: attempt), at: 0)
            }
        }
    }

    /// Fechar on a failed card.
    mutating func dismiss(_ id: UUID) { cards.removeAll { $0.id == id } }

    /// Removes the connected cards whose time is up.
    mutating func expire(now: Date) { cards.removeAll { $0.dismissAt.map { $0 <= now } ?? false } }

    mutating func removeAll() { cards.removeAll() }

    /// The first of: credentials refused, untrusted gateway certificate, the last error line
    /// of the (filtered) log, or a generic text.
    static func failureReason(rejected: Bool, certificate: Bool, logs: [String]) -> String {
        if rejected { return String(localized: "Autenticação recusada") }
        if certificate { return String(localized: "Certificado do gateway não confiado") }
        let markers = ["error", "erro", "fail", "falh", "fatal", "denied", "negad", "recus", "refused", "[!]"]
        if let line = logs.last(where: { line in markers.contains { line.lowercased().contains($0) } }) {
            return line.trimmingCharacters(in: .whitespaces)
        }
        return String(localized: "A conexão terminou sem detalhes")
    }

    /// Visible only with something to show, the option on and the menu closed (the menu
    /// shows the same states, in the same place).
    static func shown(cards: Int, enabled: Bool, menuOpen: Bool) -> Bool { cards > 0 && enabled && !menuOpen }
}

/// Follows every session and keeps the cards; the coordinator owns it.
@MainActor
final class ConnectionProgressCenter: ObservableObject {
    @Published var model = ConnectionProgressModel()
    var now: () -> Date = Date.init
    var announce: (String) -> Void = { _ in }
    private var lastStates: [UUID: ConnectionState] = [:]
    private var timer: Timer?

    func sessionChanged(_ session: Session, to state: ConnectionState, connection: Connection?, enabled: Bool) {
        let old = lastStates[session.id] ?? .disconnected
        lastStates[session.id] = state
        guard old != state else { return }
        let name = connection?.name ?? ""
        model.apply(id: session.id, name: name, endpoint: connection?.endpoint ?? "", from: old, to: state,
                    attempt: session.reconnectAttempts,
                    failure: {
                        (ConnectionProgressModel.failureReason(rejected: session.authenticationRejected,
                                                               certificate: session.suggestedCertificate != nil, logs: session.logs),
                         session.authenticationRejected)
                    },
                    enabled: enabled, now: now())
        if let card = model.cards.first(where: { $0.id == session.id }) {
            switch card.state {
            case .connecting, .reconnecting, .connected: announce(String(localized: "\(name): \(card.state.title)"))
            case .failed: announce(String(localized: "\(name): falha. \(card.reason ?? "")"))
            default: break
            }
        }
        schedule()
    }

    func dismiss(_ id: UUID) { model.dismiss(id) }

    /// Turning the option off hides everything at once.
    func disable() { model.removeAll() }

    func tick() {
        model.expire(now: now())
        schedule()
    }

    private func schedule() {
        timer?.invalidate()
        timer = nil
        guard let deadline = model.nextDeadline else { return }
        timer = Timer.scheduledTimer(withTimeInterval: max(deadline.timeIntervalSince(now()), 0.05), repeats: false) { [weak self] _ in
            MainActor.assumeIsolated { self?.tick() }
        }
    }
}

/// Shows and hides the progress panel (a fake in the local checks).
@MainActor protocol ProgressPanelPresenter: AnyObject {
    var isShown: Bool { get }
    func show(anchor: MenuAnchor)
    func hide()
}

/// Never key, never main: it cannot take the keyboard from the app in front. A
/// non-activating panel still takes clicks.
final class ProgressPanel: NSPanel {
    override var canBecomeKey: Bool { false }
    override var canBecomeMain: Bool { false }
}

@MainActor
final class ConnectionProgressPanelController: ProgressPanelPresenter {
    static let width: CGFloat = 300
    let panel: ProgressPanel
    private let hosting: NSHostingView<ConnectionProgressView>
    private var anchor: MenuAnchor?
    private var observer: AnyCancellable?
    private(set) var isShown = false

    init(menuBar: MenuBarCoordinator) {
        hosting = NSHostingView(rootView: ConnectionProgressView(center: menuBar.progress, menuBar: menuBar))
        let size = NSSize(width: Self.width, height: 80)
        panel = ProgressPanel(contentRect: NSRect(origin: .zero, size: size), styleMask: [.nonactivatingPanel, .borderless],
                              backing: .buffered, defer: true)
        panel.isReleasedWhenClosed = false
        panel.level = .statusBar
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary, .ignoresCycle]
        panel.hidesOnDeactivate = false
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = false // each card has its own
        panel.isExcludedFromWindowsMenu = true
        panel.animationBehavior = .none
        hosting.frame = NSRect(origin: .zero, size: size)
        hosting.autoresizingMask = [.width, .height]
        panel.contentView = hosting
        observer = menuBar.progress.objectWillChange.sink { [weak self] in
            DispatchQueue.main.async { self?.fit(animated: false) }
        }
    }

    private var reduceMotion: Bool { NSWorkspace.shared.accessibilityDisplayShouldReduceMotion }

    func show(anchor: MenuAnchor) {
        self.anchor = anchor
        guard !isShown else { fit(animated: false); return }
        isShown = true
        fit(animated: false)
        guard !reduceMotion else { panel.alphaValue = 1; panel.orderFrontRegardless(); return }
        // The window fades in where it belongs; the cards come 8 pt from above (their transition).
        panel.alphaValue = 0
        panel.orderFrontRegardless()
        NSAnimationContext.runAnimationGroup({ context in
            context.duration = 0.2
            panel.animator().alphaValue = 1
        }, completionHandler: { [weak self] in
            MainActor.assumeIsolated { if let self, self.isShown { self.panel.alphaValue = 1 } }
        })
    }

    func hide() {
        guard isShown else { return }
        isShown = false
        guard !reduceMotion else { panel.orderOut(nil); return }
        NSAnimationContext.runAnimationGroup({ context in
            context.duration = 0.2
            panel.animator().alphaValue = 0
        }, completionHandler: { [weak self] in
            MainActor.assumeIsolated {
                guard let self, !self.isShown else { return }
                self.panel.orderOut(nil)
                self.panel.alphaValue = 1
            }
        })
    }

    private func fit(animated: Bool) {
        guard let anchor, isShown else { return }
        hosting.layoutSubtreeIfNeeded()
        let height = max(hosting.fittingSize.height, 1)
        let frame = MenuPanelPlacement.frame(size: NSSize(width: Self.width, height: height), anchor: anchor)
        if frame != panel.frame { panel.setFrame(frame, display: true, animate: animated && !reduceMotion) }
    }
}

// MARK: - View

struct ConnectionProgressView: View {
    @ObservedObject var center: ConnectionProgressCenter
    let menuBar: MenuBarCoordinator
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Namespace private var glass

    var body: some View {
        let model = center.model
        cards(model)
            .padding(10)
            .frame(width: ConnectionProgressPanelController.width)
            // The panel is never key; its buttons still take clicks, so they must not look disabled.
            .environment(\.controlActiveState, .key)
            .animation(Motion.state(reduceMotion), value: model)
    }

    @ViewBuilder private func cards(_ model: ConnectionProgressModel) -> some View {
        let content = VStack(spacing: 8) {
            ForEach(model.visible) { card in
                ProgressCardView(card: card, menuBar: menuBar, center: center)
                    .modifier(ProgressCardSurface(id: card.id, namespace: glass))
                    .transition(reduceMotion ? .opacity : .opacity.combined(with: .offset(y: -8)))
            }
            if model.overflow > 0 {
                Button { menuBar.showMenu() } label: {
                    Text("+\(model.overflow) em andamento").font(.callout).frame(maxWidth: .infinity)
                        .padding(.vertical, 8).contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .modifier(ProgressCardSurface(id: nil, namespace: glass))
                .help("Abrir o menu do TunnelMac")
            }
        }
        if #available(macOS 26, *) { GlassEffectContainer(spacing: 8) { content } } else { content }
    }
}

/// Liquid Glass on macOS 26+ (with an id for the enter and leave transitions); the HUD
/// material before.
private struct ProgressCardSurface: ViewModifier {
    let id: UUID?
    let namespace: Namespace.ID
    func body(content: Content) -> some View {
        let shape = RoundedRectangle(cornerRadius: 14, style: .continuous)
        if #available(macOS 26, *) {
            // On the menu material, like the menu: readable over any background.
            let card = content.background(VisualEffectBackground(material: .menu).clipShape(shape))
            if let id {
                card.glassEffect(.regular, in: shape).glassEffectID(id, in: namespace)
            } else {
                card.glassEffect(.regular, in: shape)
            }
        } else {
            content
                .background(VisualEffectBackground(material: .hudWindow).clipShape(shape))
                .overlay(shape.strokeBorder(Color.primary.opacity(0.08), lineWidth: 0.5))
                .shadow(color: .black.opacity(0.18), radius: 8, y: 3)
        }
    }
}

private struct VisualEffectBackground: NSViewRepresentable {
    let material: NSVisualEffectView.Material
    func makeNSView(context: Context) -> NSVisualEffectView {
        let view = NSVisualEffectView()
        view.material = material
        view.blendingMode = .behindWindow
        view.state = .active
        return view
    }
    func updateNSView(_ view: NSVisualEffectView, context: Context) { view.material = material }
}

struct ProgressCardView: View {
    let card: ConnectionProgressModel.Card
    let menuBar: MenuBarCoordinator
    let center: ConnectionProgressCenter
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        HStack(alignment: .center, spacing: 10) {
            indicator.frame(width: 22, height: 22).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(card.name).font(.callout.weight(.semibold)).lineLimit(1).truncationMode(.middle)
                Text(detail).font(.caption).foregroundStyle(card.state == .failed ? AnyShapeStyle(Color.red) : AnyShapeStyle(.secondary))
                    .lineLimit(2).fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .accessibilityElement(children: .combine)
            actions
        }
        .padding(.horizontal, 12).padding(.vertical, 10)
        .contentShape(Rectangle())
        .onTapGesture { if card.state == .connected { menuBar.showMenu() } }
    }

    /// The state in words (color is never the only signal).
    var detail: String { Self.detail(card) }

    static func detail(_ card: ConnectionProgressModel.Card) -> String {
        switch card.state {
        case .authenticating: return String(localized: "Aguardando SAML: conclua o login no navegador")
        case .reconnecting: return String(localized: "Reconectando: tentativa \(card.attempt) de 3")
        case .connected: return card.endpoint.isEmpty ? card.state.title : String(localized: "Conectada: \(card.endpoint)")
        case .failed: return String(localized: "Falha: \(card.reason ?? String(localized: "A conexão terminou sem detalhes"))")
        default: return card.state.title
        }
    }

    @ViewBuilder private var indicator: some View {
        switch card.state {
        case .waitingForSAML:
            Image(systemName: "clock").font(.system(size: 15, weight: .medium)).foregroundStyle(.orange)
        case .authenticating:
            Image(systemName: "globe").font(.system(size: 15, weight: .medium)).foregroundStyle(.orange)
        case .connected:
            let check = Image(systemName: "checkmark.circle.fill").font(.system(size: 17, weight: .semibold)).foregroundStyle(.green)
            if #available(macOS 14, *), !reduceMotion {
                check.symbolEffect(.bounce, value: card.state)
            } else {
                check
            }
        case .failed:
            Image(systemName: "xmark.octagon.fill").font(.system(size: 17, weight: .semibold)).foregroundStyle(.red)
        default:
            ProgressView().controlSize(.small)
        }
    }

    @ViewBuilder private var actions: some View {
        switch card.state {
        case .connected:
            EmptyView()
        case .failed:
            HStack(spacing: 6) {
                Button(card.reviewable ? String(localized: "Revisar…") : String(localized: "Ver logs")) {
                    center.dismiss(card.id)
                    menuBar.showMainWindow(selecting: card.id)
                }
                .controlSize(.small).adaptiveButtonStyle()
                Button { center.dismiss(card.id) } label: { Image(systemName: "xmark") }
                    .buttonStyle(.plain).foregroundStyle(.secondary)
                    .help("Fechar")
                    .accessibilityLabel("Fechar")
            }
        default:
            Button("Cancelar") { menuBar.cancelProgress(card.id) }
                .controlSize(.small).adaptiveButtonStyle()
                .help("Desconectar; cancela também reconexões e fila SAML")
                .accessibilityLabel("Cancelar \(card.name)")
        }
    }
}
