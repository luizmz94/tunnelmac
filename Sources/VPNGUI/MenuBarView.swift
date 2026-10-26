import SwiftUI
import AppKit

struct MenuBarLabel: View {
    @ObservedObject var menuBar: MenuBarCoordinator
    /// Rotation step while a connection is starting or stopping. The label is rendered into the
    /// status item as a still image, so SwiftUI animations do not run there: the frames are swapped
    /// by hand, and only during transitions, since each frame costs CPU.
    @State private var step = 0
    private static let steps = 24, interval: Duration = .milliseconds(125)
    private var spinning: Bool {
        menuBar.pendingCount > 0 && !NSWorkspace.shared.accessibilityDisplayShouldReduceMotion
    }
    var body: some View {
        HStack(spacing: 3) {
            if let image = BrandAssets.menuIcon(connected: menuBar.connectedCount > 0,
                                                angle: spinning ? CGFloat(step) * 360 / CGFloat(Self.steps) : 0,
                                                badge: menuBar.connectedCount) {
                Image(nsImage: image)
            } else {
                Image(systemName: "shield")
            }
            if menuBar.summary != .idle {
                Image(systemName: menuBar.summary.symbol)
                    .font(.system(size: 10, weight: .semibold))
            }
        }
            .accessibilityLabel(menuBar.accessibilityDescription)
            .help(menuBar.accessibilityDescription)
            .task(id: spinning) {
                guard spinning else { step = 0; return }
                while !Task.isCancelled {
                    try? await Task.sleep(for: Self.interval)
                    step = (step + 1) % Self.steps
                }
            }
    }
}

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
    @Environment(\.openWindow) private var openWindow
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var listHeight: CGFloat = 0
    private var model: AppModel { menuBar.model }
    private static let maxListHeight: CGFloat = 380

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header.padding(.horizontal, 14).padding(.top, 12).padding(.bottom, 10)
            Divider().padding(.horizontal, 10)
            content
            banners
            if let offer = menuBar.updates.offer { updateLine(offer) }
            Divider().padding(.horizontal, 10)
            footer.padding(.horizontal, 10).padding(.vertical, 10)
        }
        .frame(width: 360)
        .animation(Motion.state(reduceMotion), value: menuBar.summary)
        .onAppear {
            menuBar.openWindowFallback = { openWindow(id: MenuBarCoordinator.sceneID) }
            if menuBar.openSettingsFallback == nil {
                let open = openWindow
                menuBar.openSettingsFallback = { open(id: MenuBarCoordinator.settingsSceneID) }
            }
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
            message(title: "Não foi possível carregar as conexões", symbol: "exclamationmark.triangle", tone: .warning,
                    detail: (model.error ?? "O arquivo existente foi preservado.") + "\nAs ações de conexão ficam indisponíveis até o problema ser resolvido.")
        } else if model.data.connections.isEmpty {
            message(title: "Nenhuma conexão cadastrada", symbol: "network", tone: .neutral,
                    detail: "Use Abrir TunnelMac para cadastrar uma conexão.")
        } else {
            let duplicated = menuBar.duplicatedNames
            ScrollView(.vertical) {
                VStack(spacing: 2) {
                    ForEach(model.sortedConnections) { connection in
                        MenuBarRow(connection: connection, session: model.manager.session(connection.id),
                                   showsServer: duplicated.contains(connection.name.lowercased()), menuBar: menuBar)
                    }
                }
                .padding(.horizontal, 6).padding(.vertical, 6)
                .background(GeometryReader { proxy in
                    Color.clear.preference(key: MenuBarListHeight.self, value: proxy.size.height)
                })
            }
            .frame(height: min(max(listHeight, 1), Self.maxListHeight))
            .onPreferenceChange(MenuBarListHeight.self) { listHeight = $0 }
        }
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
                                 message: "Conectar fica indisponível até o serviço estar pronto.") {
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
    /// Glass buttons on macOS 26+; the previous borderless look before.
    @ViewBuilder func adaptiveMenuFooterStyle() -> some View {
        if #available(macOS 26, *) { buttonStyle(.glass) } else { buttonStyle(.borderless) }
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
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

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
                    Text(session.authenticationRejected && !session.state.active ? "Autenticação recusada" : session.state.rawValue)
                    if let start = session.connectedAt, session.state == .connected {
                        Text("·").foregroundStyle(.tertiary).accessibilityHidden(true)
                        ElapsedTime(start: start)
                    }
                }
                .font(.caption).foregroundStyle(session.state.tone == .danger ? AnyShapeStyle(Color.red) : AnyShapeStyle(.secondary))
                .lineLimit(1)
            }
            .help("\(connection.name) — \(connection.endpoint)")
            .accessibilityElement(children: .combine)
            Spacer(minLength: 6)
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
                        .accessibilityValue(session.state.rawValue)
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
        .modifier(HoverHighlight(cornerRadius: 8))
        .animation(Motion.state(reduceMotion), value: session.state)
    }

    private func help(for action: MenuBarRowAction) -> String {
        switch action {
        case .connect: return "Conectar \(connection.name)"
        case .disconnect: return "Desconectar \(connection.name); cancela também reconexões e fila SAML"
        case .disconnecting: return "Aguardando o encerramento e a limpeza de rotas e DNS"
        case .review: return "A última autenticação foi recusada. Abra a janela para revisar o cadastro"
        case .unavailable: return menuBar.model.ready ? "Serviço privilegiado indisponível; use Gerenciar…" : "Os dados não foram carregados"
        }
    }

    static func symbol(_ state: ConnectionState) -> String { state.symbol }

    static func tint(_ state: ConnectionState) -> Color { state.tone.color }
}
