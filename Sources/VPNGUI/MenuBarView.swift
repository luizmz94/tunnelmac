import SwiftUI
import AppKit

extension MenuBarSummary {
    var tone: StatusTone {
        switch self {
        case .idle: return .neutral
        case .attention: return .warning
        case .transitioning: return .progress
        case .connected: return .success
        }
    }
}

struct MenuBarView: View {
    @ObservedObject var menuBar: MenuBarCoordinator
    /// Its own Liquid Glass (macOS 26+); off in the menu panel, whose window is the glass.
    var ownGlass = true
    @Environment(\.openWindow) private var openWindow
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var listHeight: CGFloat = 0
    @FocusState private var searchFocused: Bool
    private var model: AppModel { menuBar.model }
    /// Tall enough to use the screen; the panel itself never passes the visible frame.
    private static let maxListHeight: CGFloat = 620
    /// Two rows: the panel never shrinks below this while searching, so it does not jump.
    private static let minSearchHeight: CGFloat = 104

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header.padding(.horizontal, 14).padding(.top, 12).padding(.bottom, 10)
            MenuSearchField(text: Binding(get: { menuBar.searchText }, set: { menuBar.setSearch($0) }),
                            prompt: String(localized: "Buscar conexões"), focused: $searchFocused)
                .disabled(!menuBar.searchAvailable)
                .padding(.horizontal, 10).padding(.bottom, 10)
            Divider().padding(.horizontal, 10)
            content
            banners
            if let offer = menuBar.updates.offer { updateLine(offer) }
            Divider().padding(.horizontal, 10)
            footer.padding(.horizontal, 10).padding(.vertical, 10)
        }
        .frame(width: 360)
        .menuBarGlass(ownGlass)
        .animation(Motion.state(reduceMotion), value: menuBar.summary)
        .onChange(of: menuBar.searchFocusRequest) { _ in if menuBar.searchAvailable { searchFocused = true } }
        .onAppear {
            if menuBar.searchAvailable { searchFocused = true }
            // Backup only: the app's commands capture the openers first (see AppCommands).
            let open = openWindow
            menuBar.adoptWindowOpeners(main: { open(id: MenuBarCoordinator.sceneID) },
                                       settings: { open(id: MenuBarCoordinator.settingsSceneID) })
            if !model.service.busy { model.service.refresh() }
        }
    }

    private var header: some View {
        HStack(spacing: 10) {
            BrandSymbol(size: 32)
            VStack(alignment: .leading, spacing: 1) {
                Text("TunnelMac").font(.headline)
                Text(menuBar.summaryText).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
        }
        .accessibilityElement(children: .combine)
    }

    @ViewBuilder private var content: some View {
        if !model.ready {
            message(title: String(localized: "Não foi possível carregar as conexões"), symbol: "exclamationmark.triangle", tone: .warning,
                    detail: (model.error ?? String(localized: "O arquivo existente foi preservado.")) + String(localized: "\nAs ações de conexão ficam indisponíveis até o problema ser resolvido."))
        } else if model.data.connections.isEmpty {
            message(title: String(localized: "Nenhuma conexão cadastrada"), symbol: "network", tone: .neutral,
                    detail: String(localized: "Use Abrir TunnelMac para cadastrar uma conexão."))
        } else if menuBar.searchResults.isEmpty {
            message(title: String(localized: "Nenhuma conexão encontrada"), symbol: "magnifyingglass", tone: .neutral,
                    detail: String(localized: "Busque por nome, servidor ou tipo."))
                .frame(minHeight: Self.minSearchHeight, alignment: .top)
        } else {
            let duplicated = menuBar.duplicatedNames
            let searching = !menuBar.searchText.isEmpty
            ScrollViewReader { proxy in
                ScrollView(.vertical) {
                    let sections = menuBar.searchSections
                    VStack(spacing: 2) {
                        // Pinned and active connections on top, a separator, then the others.
                        ForEach(sections.top) { row($0, duplicated) }
                        if !sections.top.isEmpty && !sections.rest.isEmpty {
                            Divider().padding(.horizontal, 8).padding(.vertical, 4).accessibilityHidden(true)
                        }
                        ForEach(sections.rest) { row($0, duplicated) }
                    }
                    .padding(.horizontal, 6).padding(.vertical, 6)
                    .background(GeometryReader { proxy in
                        Color.clear.preference(key: MenuBarListHeight.self, value: proxy.size.height)
                    })
                }
                .frame(height: min(max(listHeight, searching ? Self.minSearchHeight : 1), Self.maxListHeight))
                .onPreferenceChange(MenuBarListHeight.self) { listHeight = $0 }
                .onChange(of: menuBar.highlightedID) { id in
                    guard let id else { return }
                    withAnimation(Motion.state(reduceMotion)) { proxy.scrollTo(id) }
                }
            }
        }
    }

    private func row(_ connection: Connection, _ duplicated: Set<String>) -> some View {
        MenuBarRow(connection: connection, session: model.manager.session(connection.id),
                   showsServer: duplicated.contains(connection.name.lowercased()), menuBar: menuBar,
                   highlighted: menuBar.highlightedID == connection.id, pinned: menuBar.isPinned(connection.id))
            .id(connection.id)
    }

    private func message(title: String, symbol: String, tone: StatusTone, detail: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: symbol).symbolRenderingMode(.hierarchical)
                .font(.system(size: 18, weight: .regular))
                .foregroundStyle(tone == .neutral ? Color.secondary : tone.color)
                .frame(width: 22)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.callout.weight(.semibold))
                Text(detail).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 14).padding(.vertical, 16)
        .accessibilityElement(children: .combine)
    }

    @ViewBuilder private var banners: some View {
        let showService = model.ready && !model.service.canConnect
        let error = model.ready ? model.error : nil
        if showService || error != nil {
            VStack(spacing: 8) {
                if showService {
                    InlineNotice(tone: model.service.health.tone == .danger ? .danger : .warning,
                                 symbol: model.service.health.symbol, title: model.service.health.title,
                                 message: String(localized: "Conectar fica indisponível até o serviço estar pronto.")) {
                        Button("Gerenciar…") { menuBar.showServiceManagement() }
                    }
                }
                if let error {
                    InlineNotice(tone: .danger, symbol: "exclamationmark.triangle.fill", title: error) {
                        Button("OK") { model.error = nil }.help("Dispensar esta mensagem")
                    }
                    .accessibilityLabel("Erro: \(error)")
                }
            }
            .padding(.horizontal, 10).padding(.bottom, 10)
            .transition(.opacity)
        }
    }

    /// Compact, only while an update is pending; the state icon of the VPNs is untouched.
    private func updateLine(_ offer: UpdateOffer) -> some View {
        Button { menuBar.showSettings(.updates) } label: {
            HStack(spacing: 8) {
                UpdateDot()
                Text("Atualização disponível: \(offer.version)").font(.callout)
                Spacer(minLength: 4)
                Image(systemName: "chevron.right").font(.caption.weight(.semibold)).foregroundStyle(.tertiary)
            }
            .contentShape(Rectangle())
            .padding(.horizontal, 8).padding(.vertical, 6)
        }
        .buttonStyle(.plain)
        .modifier(HoverHighlight(cornerRadius: 8))
        .padding(.horizontal, 6).padding(.bottom, 6)
        .help("Abrir Configurações › Atualizações")
        .accessibilityLabel("Atualização disponível: \(offer.version). Abrir Atualizações")
    }

    private var footer: some View {
        GlassGroup(spacing: 8) {
            HStack(spacing: 8) {
                Button { menuBar.showMainWindow() } label: { Label("Abrir TunnelMac", systemImage: "macwindow") }
                    .keyboardShortcut("o")
                    .help("Mostrar a janela principal para cadastro, certificados e logs (⌘O)")
                Spacer(minLength: 0)
                Button { menuBar.checkForUpdates() } label: { Label("Verificar atualizações…", systemImage: "arrow.triangle.2.circlepath") }
                    .labelStyle(.iconOnly)
                    .help("Verificar atualizações…")
                // Configurações also hold the privileged service tab (Gerenciar…).
                Button { menuBar.showSettings() } label: { Label("Configurações…", systemImage: "gearshape") }
                    .labelStyle(.iconOnly)
                    .keyboardShortcut(",")
                    .overlay(alignment: .topTrailing) {
                        if menuBar.updates.pending { UpdateDot().offset(x: 2, y: -2).allowsHitTesting(false) }
                    }
                    .help(menuBar.updates.pending ? "Configurações… (atualização disponível) (⌘,)" : "Configurações… (⌘,)")

                Button { NSApp.terminate(nil) } label: { Label("Sair", systemImage: "power") }
                    .keyboardShortcut("q")
                    .help("Encerrar o TunnelMac; conexões ativas exigem confirmação (⌘Q)")
            }
            .controlSize(.small)
            .adaptiveMenuFooterStyle()
        }
    }
}

private extension View {
    /// The window's own opaque panel gives way to Liquid Glass on macOS 26+.
    @ViewBuilder func menuBarGlass(_ enabled: Bool) -> some View {
        if #available(macOS 26, *), enabled {
            containerBackground(.clear, for: .window)
                .glassEffect(.regular, in: .rect(cornerRadius: 16, style: .continuous))
        } else {
            self
        }
    }

    /// Glass buttons on macOS 26+; the previous borderless look before.
    @ViewBuilder func adaptiveMenuFooterStyle() -> some View {
        if #available(macOS 26, *) { buttonStyle(.glass) } else { buttonStyle(.borderless) }
    }
}

/// Secondary text that reads as a link only on hover, like the client credit in the main window.
private struct QuietLink: View {
    let title: String
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) { Text(title).underline(hovering) }
            .buttonStyle(.plain)
            .foregroundStyle(.secondary)
            .onHover { inside in
                hovering = inside
                if inside { NSCursor.pointingHand.push() } else { NSCursor.pop() }
            }
    }
}

private struct MenuBarListHeight: PreferenceKey {
    static var defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value = max(value, nextValue()) }
}

struct MenuBarRow: View {
    let connection: Connection
    @ObservedObject var session: Session
    let showsServer: Bool
    let menuBar: MenuBarCoordinator
    /// The keyboard (or pointer) highlight of the search; the only hover look of the rows.
    var highlighted = false
    /// Pinned to the top by the user.
    var pinned = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        let action = MenuBarRowAction.of(session, ready: menuBar.model.ready, serviceReady: menuBar.model.service.canConnect)
        HStack(alignment: .center, spacing: 10) {
            ProtocolTile(kind: connection.kind, state: session.state, size: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text(connection.name).font(.body.weight(.medium)).lineLimit(2).truncationMode(.middle)
                if showsServer {
                    Text(connection.endpoint).font(.caption).foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.middle)
                }
                HStack(spacing: 5) {
                    Text(session.authenticationRejected && !session.state.active ? String(localized: "Autenticação recusada") : session.state.title)
                    if let start = session.connectedAt, session.state == .connected {
                        Text("·").foregroundStyle(.tertiary).accessibilityHidden(true)
                        ElapsedTime(start: start)
                    }
                    if showsLogsLink {
                        Text("·").foregroundStyle(.tertiary).accessibilityHidden(true)
                        QuietLink(title: String(localized: "Ver logs")) { showLogs() }
                            .help("Abrir a janela principal nos logs desta conexão")
                            .accessibilityHidden(true)
                    }
                }
                .font(.caption).foregroundStyle(session.state.tone == .danger ? AnyShapeStyle(Color.red) : AnyShapeStyle(.secondary))
                .lineLimit(1)
            }
            .help("\(connection.name) — \(connection.endpoint)")
            .accessibilityElement(children: .combine)
            .accessibilityAddTraits(highlighted ? .isSelected : [])
            .accessibilityAction(named: Text(pinned ? "Desafixar" : "Fixar no topo")) { menuBar.togglePin(connection.id) }
            .accessibilityAction(named: Text("Ver logs")) { if showsLogsLink { showLogs() } }
            Spacer(minLength: 6)
            pinButton
            VStack(alignment: .trailing, spacing: 3) {
                if action == .review {
                    Button("Revisar…") { menuBar.perform(connection) }
                        .controlSize(.small)
                        .adaptiveButtonStyle()
                        .help(help(for: action))
                        .accessibilityLabel("Revisar acesso de \(connection.name)")
                } else {
                    // Like Wi-Fi and VPN in Control Center: on while connected or on the way there.
                    Toggle(action.title, isOn: Binding(get: { session.state.active && action != .disconnecting },
                                                       set: { _ in menuBar.perform(connection) }))
                        .toggleStyle(.switch)
                        .labelsHidden()
                        .controlSize(.small)
                        .disabled(!action.enabled)
                        .help(help(for: action))
                        .accessibilityLabel(connection.name)
                        .accessibilityValue(session.state.title)
                }
                if !session.state.active, session.suggestedCertificate != nil {
                    Button("Conferir certificado…") { menuBar.showMainWindow(selecting: connection.id) }
                        .buttonStyle(.link).font(.caption)
                        .help("Abrir a janela principal para conferir o certificado; nada é aceito pelo menu")
                        .accessibilityLabel("Conferir certificado de \(connection.name)")
                }

            }
            .fixedSize()
        }
        .padding(.horizontal, 8).padding(.vertical, 7)
        .background(highlightShape.fill(Color.accentColor.opacity(highlighted ? (colorScheme == .dark ? 0.28 : 0.18) : 0)))
        .overlay(highlightShape.strokeBorder(Color.accentColor.opacity(highlighted ? 1 : 0), lineWidth: 1))
        .contentShape(Rectangle())
        .onContinuousHover { phase in
            if case .active = phase { menuBar.pointerHovered(connection.id) }
        }
        .contextMenu {
            Button(pinned ? "Desafixar" : "Fixar no topo") { menuBar.togglePin(connection.id) }
        }
        .animation(Motion.state(reduceMotion), value: session.state)
    }

    private var highlightShape: RoundedRectangle { RoundedRectangle(cornerRadius: 8, style: .continuous) }

    /// Filled while pinned; otherwise shown only on the highlighted row.
    private var pinButton: some View {
        Button { menuBar.togglePin(connection.id) } label: {
            Image(systemName: pinned ? "pin.fill" : "pin")
                .font(.system(size: 11, weight: .semibold))
                .rotationEffect(.degrees(45))
                .foregroundStyle(pinned ? AnyShapeStyle(Color.accentColor) : AnyShapeStyle(.secondary))
                .frame(width: 18, height: 18)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .opacity(pinned || highlighted ? 1 : 0)
        .help(pinned ? "Desafixar do topo" : "Fixar no topo do menu")
        .accessibilityHidden(true) // the row's own action
    }

    /// A failure says where its details are; review and certificate cases have their own action.
    private var showsLogsLink: Bool {
        session.state == .failed && !session.authenticationRejected && session.suggestedCertificate == nil
    }

    private func showLogs() { menuBar.showMainWindow(selecting: connection.id) }

    private func help(for action: MenuBarRowAction) -> String {
        switch action {
        case .connect: return String(localized: "Conectar \(connection.name)")
        case .disconnect: return String(localized: "Desconectar \(connection.name); cancela também reconexões e fila SAML")
        case .disconnecting: return String(localized: "Aguardando o encerramento e a limpeza de rotas e DNS")
        case .review: return String(localized: "A última autenticação foi recusada. Abra a janela para revisar o cadastro")
        case .unavailable: return menuBar.model.ready ? String(localized: "Serviço privilegiado indisponível; use Gerenciar…") : String(localized: "Os dados não foram carregados")
        }
    }

    static func symbol(_ state: ConnectionState) -> String { state.symbol }

    static func tint(_ state: ConnectionState) -> Color { state.tone.color }
}
