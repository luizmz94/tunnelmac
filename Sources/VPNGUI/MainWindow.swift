import SwiftUI
import AppKit
import VPNHelperShared

struct MainView: View {
    @ObservedObject var model: AppModel
    let menuBar: MenuBarCoordinator
    @ObservedObject private var updates: UpdateChecker
    @State private var selected: UUID?
    @State private var editing: Connection?
    @State private var pendingImport: OpenVPNImport?
    @ObservedObject private var service: ServiceController
    @State private var deleting: Connection?
    @State private var query = ""
    @State private var rowHeight: CGFloat = 0
    @State private var sidebarHeight: CGFloat = 0
    @State private var onboarding = false
    /// Sidebar width that keeps the traffic lights and its three toolbar buttons visible.
    static let sidebarMinimum: CGFloat = 260
    @Environment(\.openWindow) private var openWindow
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    init(model: AppModel, menuBar: MenuBarCoordinator) {
        _model = ObservedObject(wrappedValue: model)
        self.menuBar = menuBar
        _updates = ObservedObject(wrappedValue: menuBar.updates)
        _service = ObservedObject(wrappedValue: model.service)
    }

    var body: some View {
        NavigationSplitView {
            sidebar
                .navigationSplitViewColumnWidth(min: Self.sidebarMinimum, ideal: 300, max: 400)
                .sheet(isPresented: $onboarding) {
                    ServiceOnboardingSheet(model: model) { completed in
                        if !completed { ServiceOnboarding.postponed = true }
                        onboarding = false
                    }
                }
                .withoutSidebarToggle()
                .toolbar {
                    // Declared in the sidebar column; the flexible spacer (macOS 26+) pushes the
                    // button to the sidebar's top right, next to the split.
                    if #available(macOS 26.0, *) { ToolbarSpacer(.flexible) }
                    ToolbarItem(placement: .primaryAction) {
                        Button { menuBar.showSettings() } label: { Label("Configurações", systemImage: "gearshape") }
                            .help("Configurações (⌘,)")
                    }
                    ToolbarItem(placement: .primaryAction) {
                        // Mostly a status light: green when the service and a client are approved.
                        Button { menuBar.showServiceManagement() } label: {
                            Label("Serviço privilegiado", systemImage: service.health.symbol)
                                .foregroundStyle(service.health.tone.color)
                        }
                        .help("Serviço privilegiado: \(service.health.title)")
                        .accessibilityLabel("Serviço privilegiado: \(service.health.title)")
                    }
                    ToolbarItem(placement: .primaryAction) {
                        Button { editing = Connection() } label: { Label("Nova conexão", systemImage: "plus") }
                            .help("Nova conexão: Fortinet, OpenVPN ou WireGuard (⌘N)")
                            .keyboardShortcut("n")
                            .disabled(!model.ready)
                    }
                }
        } detail: {
            VStack(spacing: 0) {
                if updates.showsCard, let offer = updates.offer {
                    UpdateCard(offer: offer, update: { menuBar.showSettings(.updates) },
                               later: { updates.postpone() })
                        .padding(.horizontal, 20).padding(.top, 14).padding(.bottom, 2)
                        .transition(reduceMotion ? .opacity : .move(edge: .top).combined(with: .opacity))
                }
                detail
            }
            .animation(Motion.state(reduceMotion), value: updates.showsCard)
            .frame(minWidth: 530, maxWidth: .infinity, maxHeight: .infinity)
            // With a connection selected, its name and state are a toolbar item of the detail.
            .navigationTitle(model.data.connections.contains { $0.id == selected } ? "" : "Conexões")
        }
        .navigationSplitViewStyle(.balanced)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onAppear {
            let open = openWindow
            if menuBar.openSettingsFallback == nil {
                menuBar.openSettingsFallback = { open(id: MenuBarCoordinator.settingsSceneID) }
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            // Back from System Settings: read the real status again (approval or revocation).
            if !model.service.busy { model.service.refresh() }
        }
        .onAppear { evaluateOnboarding(service.health) }
        .onChange(of: service.health) { evaluateOnboarding($0) }
        .sheet(item: $editing, onDismiss: { pendingImport = nil }) { connection in
            ConnectionEditor(model: model, connection: connection, pendingImport: pendingImport) { selected = connection.id }
        }
        .alert("Erro", isPresented: Binding(get: { model.error != nil }, set: { if !$0 { model.error = nil } })) {
            Button("OK") { model.error = nil }
        } message: { Text(model.error ?? "") }
        .alert(deleting.map { "Excluir “\($0.name)”?" } ?? "Excluir conexão?",
               isPresented: Binding(get: { deleting != nil }, set: { if !$0 { deleting = nil } })) {
            Button("Cancelar", role: .cancel) { deleting = nil }
            Button("Excluir", role: .destructive) {
                if let deleting {
                    Task {
                        do { try await model.deleteAsync(deleting); if selected == deleting.id { selected = nil } }
                        catch { model.error = error.localizedDescription }
                    }
                }
                deleting = nil
            }
        } message: {
            Text(deleteMessage(deleting))
        }
        .onReceive(menuBar.$pendingSelection) { id in
            // Selection requested by the menu bar (review access or certificate).
            guard let id else { return }
            DispatchQueue.main.async {
                if model.data.connections.contains(where: { $0.id == id }) { selected = id }
                menuBar.pendingSelection = nil
            }
        }
    }

    /// Shows the first-run guide while the service waits for activation or approval. The
    /// guide follows on to the client approval; a state it does not handle continues in
    /// Serviço privilegiado.
    private func evaluateOnboarding(_ health: ServiceController.Health) {
        if ServiceOnboarding.needed(health) {
            if !onboarding, !ServiceOnboarding.postponed, editing == nil { onboarding = true }
        } else if onboarding, health != .checking, ServiceOnboarding.step(health) == nil {
            onboarding = false
            menuBar.showServiceManagement()
        }
    }

    private func deleteMessage(_ connection: Connection?) -> String {
        switch connection?.kind {
        case .openvpn: return "O cadastro, a senha salva e a cópia privada do perfil OpenVPN serão removidos. O arquivo original não é alterado."
        case .wireguard: return "O cadastro e a cópia privada do perfil WireGuard, com a chave privada, serão removidos. O arquivo original não é alterado."
        default: return "O cadastro, a senha salva e a sessão SAML guardada serão removidos."
        }
    }

    // MARK: Sidebar

    /// The search field only appears once the list no longer fits (and stays while it filters).
    private var showsSearch: Bool {
        !query.isEmpty || ConnectionSearch.overflows(count: model.data.connections.count,
                                                     rowHeight: rowHeight, available: sidebarHeight)
    }

    private var sidebar: some View {
        VStack(spacing: 0) {
            if showsSearch {
                SidebarSearchField(text: $query)
                    .padding(.horizontal, 10).padding(.top, 6).padding(.bottom, 4)
                    .transition(.opacity)
            }
            List(selection: $selected) {
                ForEach(model.sortedConnections.filter { ConnectionSearch.matches($0, query) }) { connection in
                    let session = model.manager.session(connection.id)
                    ConnectionRow(connection: connection, session: session, model: model,
                                  showsServer: true, edit: { editing = connection })
                        .background(GeometryReader { Color.clear.preference(key: SidebarRowHeight.self, value: $0.size.height) })
                        .tag(connection.id)
                        .contextMenu { contextMenu(for: connection, session: session) }
                }
            }
            .listStyle(.sidebar)
            .overlay {
                if !query.isEmpty && !model.data.connections.contains(where: { ConnectionSearch.matches($0, query) }) {
                    Text("Nenhuma conexão encontrada").font(.callout).foregroundStyle(.secondary)
                }
            }
        }
        .background(GeometryReader { Color.clear.preference(key: SidebarHeight.self, value: $0.size.height) })
        .onPreferenceChange(SidebarRowHeight.self) { if $0 > 0 { rowHeight = $0 } }
        .onPreferenceChange(SidebarHeight.self) { sidebarHeight = $0 }
        .animation(Motion.state(reduceMotion), value: showsSearch)
        .onDeleteCommand {
            guard let connection = model.data.connections.first(where: { $0.id == selected }),
                  !model.manager.session(connection.id).state.active else { return }
            deleting = connection
        }
    }

    @ViewBuilder private func contextMenu(for connection: Connection, session: Session) -> some View {
        let action = MenuBarRowAction.of(session, ready: model.ready, serviceReady: model.service.canConnect)
        Button(action.title) { primaryAction(action, connection) }.disabled(!action.enabled)
        if !session.state.active, session.suggestedCertificate != nil {
            Button("Conferir certificado…") { selected = connection.id }
        }
        Divider()
        Button("Editar…") { editing = connection }.disabled(session.state.active)
        Button("Limpar logs") { session.clearLogs() }.disabled(session.logs.isEmpty)
        Divider()
        Button("Excluir…", role: .destructive) { deleting = connection }.disabled(session.state.active)
    }

    private func primaryAction(_ action: MenuBarRowAction, _ connection: Connection) {
        switch action {
        case .connect: model.connect(connection)
        case .disconnect: model.manager.disconnect(connection.id)
        case .review: editing = connection
        case .disconnecting, .unavailable: break
        }
    }

    // MARK: Detail

    @ViewBuilder private var detail: some View {
        if let connection = model.data.connections.first(where: { $0.id == selected }) {
            ConnectionDetail(connection: connection, session: model.manager.session(connection.id), model: model,
                             edit: { editing = connection }, delete: { deleting = connection },
                             manageService: { menuBar.showServiceManagement() })
                .id(connection.id)
        } else if !model.ready {
            EmptyStateView(symbol: "exclamationmark.triangle", title: "Não foi possível carregar as conexões",
                           message: (model.error ?? "O arquivo existente foi preservado.") + " As ações de conexão ficam indisponíveis até o problema ser resolvido.",
                           tone: .warning)
        } else if model.data.connections.isEmpty {
            EmptyStateView(symbol: "network.badge.shield.half.filled", title: "Nenhuma conexão cadastrada",
                           message: "Cadastre um gateway Fortinet ou importe um perfil OpenVPN ou WireGuard para conectar por aqui ou pela barra de menus.") {
                Button { editing = Connection() } label: { Label("Nova conexão", systemImage: "plus") }
                    .adaptiveButtonStyle(prominent: true)
                    .controlSize(.large)
            }
        } else {
            EmptyStateView(symbol: "sidebar.left", title: "Selecione uma conexão",
                           message: "Os detalhes, as ações e os logs aparecem aqui.")
        }
    }
}

// MARK: - Sidebar search

enum ConnectionSearch {
    /// Name, server and protocol, ignoring case and accents.
    static func matches(_ connection: Connection, _ query: String) -> Bool {
        let terms = query.split(whereSeparator: \.isWhitespace)
        guard !terms.isEmpty else { return true }
        let haystack = [connection.name, connection.endpoint, connection.kind.title].joined(separator: " ")
        return terms.allSatisfy { haystack.range(of: $0, options: [.caseInsensitive, .diacriticInsensitive]) != nil }
    }

    /// Whether the rows need more height than the sidebar has (the list would scroll).
    /// `rowHeight` is the measured row content; the list adds its own insets around it.
    static func overflows(count: Int, rowHeight: CGFloat, available: CGFloat) -> Bool {
        guard rowHeight > 0, available > 0 else { return false }
        return CGFloat(count) * (rowHeight + rowInsets) + listInsets > available
    }
    static let rowInsets: CGFloat = 8
    static let listInsets: CGFloat = 20
}

private struct SidebarRowHeight: PreferenceKey {
    static let defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value = max(value, nextValue()) }
}

private struct SidebarHeight: PreferenceKey {
    static let defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value = max(value, nextValue()) }
}

struct SidebarSearchField: View {
    @Binding var text: String
    @FocusState private var focused: Bool
    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary).accessibilityHidden(true)
            TextField("Buscar conexões", text: $text)
                .textFieldStyle(.plain)
                .focused($focused)
                .onExitCommand { text = "" }
            if !text.isEmpty {
                Button { text = ""; focused = true } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.borderless)
                    .foregroundStyle(.secondary)
                    .help("Limpar busca")
                    .accessibilityLabel("Limpar busca")
            }
        }
        .padding(.horizontal, 8).padding(.vertical, 6)
        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Color.primary.opacity(0.06)))
    }
}

// MARK: - Sidebar row

struct ConnectionRow: View {
    let connection: Connection
    @ObservedObject var session: Session
    @ObservedObject var model: AppModel
    @ObservedObject private var service: ServiceController
    let showsServer: Bool
    let edit: () -> Void
    @State private var hovering = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    init(connection: Connection, session: Session, model: AppModel, showsServer: Bool = true, edit: @escaping () -> Void) {
        self.connection = connection; self.edit = edit; self.showsServer = showsServer
        _session = ObservedObject(wrappedValue: session); _model = ObservedObject(wrappedValue: model)
        _service = ObservedObject(wrappedValue: model.service)
    }

    private var action: MenuBarRowAction {
        MenuBarRowAction.of(session, ready: model.ready, serviceReady: service.canConnect)
    }

    var body: some View {
        HStack(spacing: 10) {
            StatusSymbol(symbol: session.state.symbol, tone: session.state.tone,
                         pulsing: session.state.inProgress, size: 14)
            ProtocolIcon(kind: connection.kind, size: 18)
            VStack(alignment: .leading, spacing: 2) {
                Text(connection.name).font(.body.weight(.medium)).lineLimit(1).truncationMode(.tail)
                Text(subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            }
            .help("\(connection.name) — \(connection.kind.title) · \(connection.endpoint)")
            Spacer(minLength: 4)
            trailing
        }
        .padding(.vertical, 5)
        .contentShape(Rectangle())
        .onHover { hovering = $0 }
        .animation(Motion.state(reduceMotion), value: session.state)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(connection.name), \(session.state.rawValue)")
        .accessibilityAction(named: Text(action.title)) { perform() }
    }

    private var subtitle: String {
        if session.state.active && session.state != .connected { return session.state.rawValue }
        if session.authenticationRejected { return "Autenticação recusada" }
        if session.state == .failed { return "Falha · \(connection.endpoint)" }
        return showsServer ? connection.endpoint : session.state.rawValue
    }

    @ViewBuilder private var trailing: some View {
        if hovering && action.enabled {
            Button(action: perform) {
                Image(systemName: action == .disconnect ? "stop.fill" : action == .review ? "person.crop.circle.badge.exclamationmark" : "bolt.fill")
                    .font(.system(size: 10, weight: .bold))
                    .frame(width: 22, height: 22)
            }
            .buttonStyle(.borderless)
            .background(Circle().fill(Color.primary.opacity(0.08)))
            .help(action.title)
            .accessibilityLabel("\(action.title) \(connection.name)")
            .transition(.opacity)
        } else if let start = session.connectedAt, session.state == .connected {
            ElapsedTime(start: start).font(.caption).foregroundStyle(.secondary)
        } else if session.state.inProgress {
            ProgressView().controlSize(.small).scaleEffect(0.7).frame(width: 16, height: 16)
                .accessibilityHidden(true)
        }
    }

    private func perform() {
        switch action {
        case .connect: model.connect(connection)
        case .disconnect: model.manager.disconnect(connection.id)
        case .review: edit()
        case .disconnecting, .unavailable: break
        }
    }
}

// MARK: - Detail

struct ConnectionDetail: View {
    let connection: Connection
    @ObservedObject var session: Session
    @ObservedObject var model: AppModel
    @ObservedObject private var service: ServiceController
    @ObservedObject private var versions: ClientVersionChecker
    let edit: () -> Void
    let delete: () -> Void
    let manageService: () -> Void
    @State private var certificateToTrust: String?
    @State private var confirmingDigestFix: OpenVPNCompatibility.DigestFix?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    init(connection: Connection, session: Session, model: AppModel, edit: @escaping () -> Void,
         delete: @escaping () -> Void, manageService: @escaping () -> Void = {}) {
        self.connection = connection; self.edit = edit; self.delete = delete; self.manageService = manageService
        _session = ObservedObject(wrappedValue: session); _model = ObservedObject(wrappedValue: model)
        _service = ObservedObject(wrappedValue: model.service)
        _versions = ObservedObject(wrappedValue: model.clientVersions)
    }

    private var action: MenuBarRowAction {
        MenuBarRowAction.of(session, ready: model.ready, serviceReady: service.canConnect)
    }

    var body: some View {
        VStack(spacing: 0) {
            actions
                .padding(.horizontal, 28).padding(.top, 22).padding(.bottom, 4)
            content
            ClientCredit(kind: connection.kind.runtime, version: service.status?.runtime(connection.kind.runtime)?.version)
                .padding(.horizontal, 28).padding(.bottom, 10).padding(.top, 2)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .onAppear { versions.refresh(status: service.status) }
        .onChange(of: service.status) { versions.refresh(status: $0) }
        .toolbar {
            // Name and state in the window's title area, instead of a header in the content.
            ToolbarItem(placement: .navigation) {
                HStack(spacing: 10) {
                    Text(connection.name).font(.headline).lineLimit(1).truncationMode(.tail)
                        .accessibilityAddTraits(.isHeader)
                    StatePill(state: session.state, connectedAt: session.connectedAt)
                }
                // The toolbar draws a capsule around the item; keep the name off its edge.
                .padding(.horizontal, 12)
                .fixedSize()
            }
        }
    }

    /// Fixed layout: only the log console scrolls, and it takes whatever height is left.
    private var content: some View {
        VStack(alignment: .leading, spacing: 18) {
            notices
            facts
            logs
        }
        .padding(.horizontal, 28).padding(.top, 14).padding(.bottom, 24)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Color(nsColor: .windowBackgroundColor))
        .animation(Motion.state(reduceMotion), value: session.state)
        .animation(Motion.state(reduceMotion), value: session.suggestedCertificate)
        .sheet(item: Binding(get: { certificateToTrust.map(CertificateDigest.init) },
                             set: { certificateToTrust = $0?.value })) { digest in
            CertificateTrustSheet(connection: connection, digest: digest.value) {
                Task {
                    do { try await model.trustCertificateAsync(connection, digest: digest.value) }
                    catch { model.error = error.localizedDescription }
                }
            }
        }
        .confirmationDialog(confirmingDigestFix.map { "Trocar auth \($0.from) por \($0.to)?" } ?? "",
                            isPresented: Binding(get: { confirmingDigestFix != nil }, set: { if !$0 { confirmingDigestFix = nil } })) {
            Button("Corrigir e reconectar") {
                if let fix = confirmingDigestFix {
                    Task {
                        do { try await model.applyDigestFixAsync(connection, fix) } catch { model.error = error.localizedDescription }
                    }
                }
                confirmingDigestFix = nil
            }
            Button("Cancelar", role: .cancel) { confirmingDigestFix = nil }
        } message: {
            Text("auth define o HMAC dos pacotes e precisa coincidir com o servidor. \(confirmingDigestFix?.from ?? "") é um nome de assinatura que o OpenVPN 2.7 não aceita nessa diretiva; \(confirmingDigestFix?.to ?? "") é o equivalente usual. Só a cópia do perfil no app muda.")
        }
    }


    private var actions: some View {
        HStack(spacing: 10) {
            GlassGroup(spacing: 10) {
                HStack(spacing: 10) {
                    primaryButton
                    Button(action: edit) { Label("Editar", systemImage: "pencil") }
                        .adaptiveButtonStyle()
                        .disabled(session.state.active)
                        .help(session.state.active ? "Desconecte antes de editar" : "Editar esta conexão")
                    Button(role: .destructive, action: delete) { Label("Excluir", systemImage: "trash") }
                        .adaptiveButtonStyle()
                        .disabled(session.state.active)
                        .help(session.state.active ? "Desconecte antes de excluir" : "Excluir esta conexão")
                }
                .controlSize(.large)
            }
            Spacer(minLength: 8)
            ProtocolIcon(kind: connection.kind, size: 28)
                .help(connection.kind.title)
        }
    }

    @ViewBuilder private var primaryButton: some View {
        let button = Button {
            switch action {
            case .connect: model.connect(connection)
            case .disconnect: model.manager.disconnect(connection.id)
            case .review: edit()
            case .disconnecting, .unavailable: break
            }
        } label: {
            Label(action.title, systemImage: primarySymbol).frame(minWidth: 112)
        }
        .disabled(!action.enabled)
        switch action {
        case .disconnect, .disconnecting: button.adaptiveButtonStyle()
        case .review: button.adaptiveButtonStyle(prominent: true).tint(.orange)
        case .connect, .unavailable: button.adaptiveButtonStyle(prominent: true)
        }
    }

    private var primarySymbol: String {
        switch action {
        case .connect, .unavailable: return "bolt.fill"
        case .disconnect: return "stop.fill"
        case .disconnecting: return "hourglass"
        case .review: return "person.crop.circle.badge.exclamationmark"
        }
    }

    @ViewBuilder private var notices: some View {
        if !session.state.active, let fix = session.digestFix {
            InlineNotice(tone: .warning, symbol: "wrench.and.screwdriver",
                         title: "O OpenVPN recusou auth \(fix.from)",
                         message: "Nada foi alterado. O app pode trocar para auth \(fix.to) na cópia do perfil, se o servidor usar esse algoritmo.") {
                Button("Corrigir perfil…") { confirmingDigestFix = fix }
            }
            .transition(.opacity)
        }
        if !session.state.active, let digest = session.suggestedCertificate {
            InlineNotice(tone: .warning, symbol: "lock.trianglebadge.exclamationmark",
                         title: "O certificado do servidor precisa ser conferido",
                         message: "Nada é aceito automaticamente. Compare o SHA-256 com o administrador antes de confiar.") {
                Button("Conferir certificado…") { certificateToTrust = digest }
            }
            .transition(.opacity)
        }
        if session.authenticationRejected, !session.state.active {
            InlineNotice(tone: .danger, symbol: "person.crop.circle.badge.xmark",
                         title: "A última autenticação foi recusada",
                         message: "Confira o usuário e a senha antes de tentar de novo, para evitar o bloqueio da conta.")
                .transition(.opacity)
        } else if session.state == .failed, session.suggestedCertificate == nil {
            InlineNotice(tone: .danger, symbol: "xmark.octagon", title: "A última tentativa falhou",
                         message: "Os detalhes estão nos logs abaixo.")
                .transition(.opacity)
        }
        if let outdated = outdatedClient {
            InlineNotice(tone: .warning, symbol: "arrow.up.circle", title: outdated.title, message: outdated.message) {
                Button("Gerenciar…", action: manageService)
            }
            .transition(.opacity)
        }
        if !session.state.active && !service.canConnect {
            InlineNotice(tone: service.health.tone == .danger ? .danger : .warning, symbol: service.health.symbol,
                         title: "Conectar fica disponível quando o serviço privilegiado estiver pronto",
                         message: service.health.title) {
                Button("Gerenciar…", action: manageService)
            }
            .transition(.opacity)
        }
    }

    /// The approved copy this connection runs is older than Homebrew's latest. Connecting
    /// keeps working; the notice says how to move to the new release.
    private var outdatedClient: (title: String, message: String)? {
        let kind = connection.kind.runtime
        guard let approved = service.status?.runtime(kind),
              case .updateAvailable(_, let latest) = versions.state(kind, status: service.status) else { return nil }
        return ("\(kind.title) \(latest) disponível",
                "Esta conexão usa a cópia aprovada \(ClientVersion.clean(approved.version)). Atualize no Terminal com brew upgrade \(kind.executableName) e aprove a nova versão em Serviço privilegiado.")
    }

    @ViewBuilder private var facts: some View {
        switch connection.kind {
        case .fortinet: fortinetFacts
        case .openvpn: openVPNFacts
        case .wireguard: wireGuardFacts
        }
    }

    private var wireGuardFacts: some View {
        let summary = connection.wireGuard
        return VStack(alignment: .leading, spacing: 10) {
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 14, verticalSpacing: 7) {
                fact("Protocolo", "WireGuard")
                fact("Servidor", (summary?.endpoints ?? []).isEmpty ? "Sem endpoint" : (summary?.endpoints ?? []).joined(separator: ", "))
                fact("Endereço", (summary?.addresses ?? []).joined(separator: ", "))
                fact("Rotas", summary?.routesDescription ?? "—")
                fact("DNS", (summary?.dns ?? []).isEmpty ? "Não altera o DNS" : (summary?.dns ?? []).joined(separator: ", "))
                fact("Chave pública", summary?.publicKey ?? "—")
            }
            .font(.callout)
            exposedNotice(summary?.stillExposed ?? [], keys: "O arquivo original com a chave privada")
        }
    }

    /// Originals left in the source folder that others can read.
    @ViewBuilder private func exposedNotice(_ exposed: [String], keys: String) -> some View {
        if !exposed.isEmpty {
            InlineNotice(tone: .warning, symbol: "lock.open",
                         title: "\(keys) pode ser lido por outros usuários do Mac",
                         message: exposed.map { ($0 as NSString).lastPathComponent }.joined(separator: ", ")
                            + " ainda está na pasta de origem. A cópia do app é privada; apague o original ou use chmod 600.") {
                Button("Mostrar no Finder") {
                    NSWorkspace.shared.activateFileViewerSelecting(exposed.map { URL(fileURLWithPath: $0) })
                }
            }
        }
    }

    private var openVPNFacts: some View {
        VStack(alignment: .leading, spacing: 10) {
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 14, verticalSpacing: 7) {
                fact("Protocolo", "OpenVPN")
                fact("Servidores", (connection.openVPN?.remotes ?? []).map(\.display).joined(separator: ", "))
                fact("Usuário", connection.username.isEmpty ? "—" : connection.username)
                fact("Autenticação", connection.usesPassword ? "Certificado + usuário e senha" : "Certificado")
            }
            .font(.callout)
            // Only what still applies: originals left in the source folder that others can read.
            if let exposed = connection.openVPN?.stillExposed, !exposed.isEmpty {
                InlineNotice(tone: .warning, symbol: "lock.open",
                             title: "Chaves originais legíveis por outros usuários do Mac",
                             message: exposed.map { ($0 as NSString).lastPathComponent }.joined(separator: ", ")
                                + " ainda estão na pasta de origem. A cópia do app é privada; apague os originais ou use chmod 600.") {
                    Button("Mostrar no Finder") {
                        NSWorkspace.shared.activateFileViewerSelecting(exposed.map { URL(fileURLWithPath: $0) })
                    }
                }
            }
        }
    }

    private var fortinetFacts: some View {
        Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 14, verticalSpacing: 7) {
            fact("Servidor", connection.endpoint)
            fact("Usuário", connection.username.isEmpty ? "—" : connection.username)
            fact("Autenticação", connection.authentication.title)
            fact("Certificado", connection.trustedCertificate.isEmpty
                 ? "Validação padrão do sistema"
                 : "SHA-256 fixado · …\(connection.trustedCertificate.suffix(12))")
            if let client = connection.clientCertificate {
                fact("Certificado do cliente", client.name)
            }
        }
        .font(.callout)
    }

    private func fact(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary).gridColumnAlignment(.trailing)
            Text(value).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
        }
        .accessibilityElement(children: .combine)
    }

    private var logs: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                Text("Logs").font(.headline).accessibilityAddTraits(.isHeader)
                if !session.logs.isEmpty {
                    Text(session.logs.count == 1 ? "1 linha" : "\(session.logs.count) linhas")
                        .font(.caption).foregroundStyle(.secondary).monospacedDigit()
                }
                Spacer()
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(session.logs.joined(separator: "\n"), forType: .string)
                } label: { Label("Copiar", systemImage: "doc.on.doc") }
                    .buttonStyle(.borderless)
                    .controlSize(.small)
                    .help("Copiar os logs desta conexão")
                    .accessibilityLabel("Copiar os logs desta conexão")
                    .disabled(session.logs.isEmpty)
                Button { session.clearLogs() } label: { Label("Limpar", systemImage: "trash") }
                    .buttonStyle(.borderless)
                    .controlSize(.small)
                    .help("Limpar logs desta conexão")
                    .accessibilityLabel("Limpar logs desta conexão")
                    .disabled(session.logs.isEmpty)
            }
            LogConsole(lines: session.logs)
                .frame(minHeight: 80, maxHeight: .infinity)
        }
        .layoutPriority(-1)
    }
}

private struct CertificateDigest: Identifiable {
    let value: String
    var id: String { value }
}

/// Explicit review of the digest the server presented. Cancel is the default and the
/// keyboard shortcut; trusting needs a deliberate click.
struct CertificateTrustSheet: View {
    let connection: Connection
    let digest: String
    let trust: () -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 16) {
                SheetHeader(symbol: "lock.trianglebadge.exclamationmark", tone: .warning,
                            title: "Confiar neste certificado?", subtitle: "\(connection.server):\(String(connection.port))")
                VStack(alignment: .leading, spacing: 6) {
                    Text("SHA-256 apresentado pelo servidor").font(.callout.weight(.medium))
                    Text(Self.grouped(digest))
                        .font(.system(.body, design: .monospaced))
                        .lineSpacing(3)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(12)
                        .contentPanel(cornerRadius: 8)
                        .accessibilityLabel("Digest SHA-256: \(digest)")
                }
                if !connection.trustedCertificate.isEmpty {
                    InlineNotice(tone: .warning, symbol: "arrow.triangle.swap",
                                 title: "Este digest substituirá o certificado confiável já cadastrado.")
                }
                Text("Confira o digest com o administrador por um canal confiável. Ao confirmar, ele será salvo nesta conexão e uma nova tentativa será iniciada.")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            .padding(22)
            SheetFooter {
                Spacer()
                Button("Cancelar") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Confiar e reconectar") { trust(); dismiss() }
                    .adaptiveButtonStyle(prominent: true)
            }
        }
        .frame(width: 520)
    }

    /// Groups of 8 hex digits, 4 per line, for comparison by eye. Copying keeps the spaces.
    static func grouped(_ digest: String) -> String {
        let chars = Array(digest)
        let groups = stride(from: 0, to: chars.count, by: 8).map { String(chars[$0..<min($0 + 8, chars.count)]) }
        return stride(from: 0, to: groups.count, by: 4)
            .map { groups[$0..<min($0 + 4, groups.count)].joined(separator: " ") }
            .joined(separator: "\n")
    }
}

private extension View {
    /// The sidebar stays visible; the + button is its only toolbar item.
    @ViewBuilder func withoutSidebarToggle() -> some View {
        if #available(macOS 14.0, *) { toolbar(removing: .sidebarToggle) } else { self }
    }
}

/// Credit line: the tunnel is made by an independent open-source client; the app manages it.
struct ClientCredit: View {
    let kind: RuntimeKind
    let version: String?
    @State private var hovering = false

    private var project: (name: String, url: URL) {
        switch kind {
        case .openfortivpn: return ("openfortivpn", URL(string: "https://github.com/adrienverge/openfortivpn")!)
        case .openvpn: return ("OpenVPN", URL(string: "https://github.com/OpenVPN/openvpn")!)
        case .wireguard: return ("wireguard-go", URL(string: "https://git.zx2c4.com/wireguard-go")!)
        }
    }

    var body: some View {
        HStack {
            Spacer(minLength: 0)
            Link(destination: project.url) {
                Text(version.map { "\(project.name) · \($0)" } ?? project.name)
                    .underline(hovering)
            }
            .font(.caption)
            .onHover { inside in
                hovering = inside
                if inside { NSCursor.pointingHand.push() } else { NSCursor.pop() }
            }
            .help("A conexão é feita pelo \(project.name), um projeto open source independente; este app só gerencia. Abrir o projeto oficial: \(project.url.absoluteString)")
        }
    }
}
