import SwiftUI
import AppKit
import ServiceManagement
import VPNHelperShared

// Configurações: sidebar with tabs, sections in rounded cards, rows with a colored icon,
// title, secondary subtitle and a trailing control. Same visual language as the main
// window (quiet fills, InlineNotice, glass buttons on macOS 26 with fallbacks).

struct SettingsView: View {
    @ObservedObject var menuBar: MenuBarCoordinator
    /// Injected by the local checks; production looks only for the Caskroom directory.
    var installedByHomebrew = HomebrewInstall.detect()
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        NavigationSplitView {
            SettingsSidebar(menuBar: menuBar)
                .navigationSplitViewColumnWidth(min: 220, ideal: 235, max: 280)
        } detail: {
            SettingsDetail(menuBar: menuBar, installedByHomebrew: installedByHomebrew)
                .navigationTitle(menuBar.settingsTab.title)
        }
        .frame(minWidth: 640, minHeight: 440)
        .onAppear {
            let open = openWindow
            if menuBar.openSettingsFallback == nil {
                menuBar.openSettingsFallback = { open(id: MenuBarCoordinator.settingsSceneID) }
            }
            menuBar.loginItem.refresh()
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            menuBar.loginItem.refresh() // Back from System Settings.
        }
    }
}

struct SettingsSidebar: View {
    @ObservedObject var menuBar: MenuBarCoordinator
    var body: some View {
        List(selection: Binding<SettingsTab?>(get: { menuBar.settingsTab }, set: { if let tab = $0 { menuBar.settingsTab = tab } })) {
            ForEach(SettingsTab.allCases) { tab in
                HStack(spacing: 8) {
                    Label {
                        Text(tab.title)
                    } icon: {
                        SettingsIcon(symbol: tab.symbol, color: tab.tileColor, size: 22)
                    }
                    Spacer(minLength: 4)
                    indicator(for: tab)
                }
                .tag(tab)
            }
        }
        .listStyle(.sidebar)
        .settingsWithoutSidebarToggle()
        .safeAreaInset(edge: .bottom, spacing: 0) {
            Text("Versão \(HelperConstants.releaseVersion) (build \(HelperConstants.build))")
                .font(.caption).foregroundStyle(.secondary)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 16).padding(.vertical, 12)
        }
    }

    @ViewBuilder private func indicator(for tab: SettingsTab) -> some View {
        switch tab {
        case .updates where menuBar.updates.pending:
            UpdateDot().accessibilityLabel("Atualização disponível")
        case .service:
            StatusSymbol(symbol: menuBar.model.service.health.symbol, tone: menuBar.model.service.health.tone, size: 11)
                .help(menuBar.model.service.health.title)
                .accessibilityLabel(menuBar.model.service.health.title)
        default:
            EmptyView()
        }
    }
}

/// Small accent dot marking a pending update.
struct UpdateDot: View {
    var body: some View {
        Circle().fill(Color.accentColor).frame(width: 8, height: 8)
            .accessibilityElement()
            .accessibilityLabel("Atualização disponível")
    }
}

struct SettingsDetail: View {
    @ObservedObject var menuBar: MenuBarCoordinator
    let installedByHomebrew: Bool
    var body: some View {
        let tab = menuBar.settingsTab
        ScrollView(.vertical) {
            VStack(alignment: .leading, spacing: 22) {
                switch tab {
                case .general: GeneralSettings(menuBar: menuBar, preferences: menuBar.preferences, loginItem: menuBar.loginItem)
                case .updates: UpdateSettings(updates: menuBar.updates, installer: menuBar.installer,
                                              preferences: menuBar.preferences, installedByHomebrew: installedByHomebrew)
                case .service: ServiceSettings(model: menuBar.model)
                case .backup: BackupSettings(model: menuBar.model, preferences: menuBar.preferences)
                case .about: AboutSettings()
                }
            }
            .padding(.horizontal, 28).padding(.vertical, 24)
            .frame(maxWidth: 720, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        // Opaque on every version: the scrolling pane has no backdrop of its own.
        .background(Color(nsColor: .windowBackgroundColor))
        .id(tab) // Each tab starts at the top.
    }
}

// MARK: - Building blocks

/// Section: small title above a rounded card, optional footnote below.
struct SettingsSection<Content: View>: View {
    var title: String?
    var footer: String?
    @ViewBuilder var content: Content
    @Environment(\.colorSchemeContrast) private var contrast

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if let title {
                Text(title).font(.subheadline.weight(.semibold)).foregroundStyle(.secondary)
                    .padding(.leading, 4).accessibilityAddTraits(.isHeader)
            }
            let shape = RoundedRectangle(cornerRadius: 12, style: .continuous)
            VStack(alignment: .leading, spacing: 0) { content }
                .background(shape.fill(Color.primary.opacity(contrast == .increased ? 0.07 : 0.04)))
                .overlay(shape.strokeBorder(contrast == .increased ? Color.primary.opacity(0.5) : Color(nsColor: .separatorColor),
                                            lineWidth: contrast == .increased ? 1 : 0.5))
            if let footer {
                Text(footer).font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true).padding(.horizontal, 4)
            }
        }
    }
}

/// Hairline between rows, aligned with the row text.
struct SettingsDivider: View {
    var body: some View { Divider().padding(.leading, 52) }
}

/// SF Symbol on a rounded tile that follows the icon style chosen in System Settings ›
/// Appearance (Default, Dark, Clear or Tinted), like System Settings' own sidebar.
struct SettingsIcon: View {
    let symbol: String
    let color: Color
    var size: CGFloat = 26
    @Environment(\.colorScheme) private var scheme
    var body: some View {
        let shape = RoundedRectangle(cornerRadius: size * 0.26, style: .continuous)
        let style = IconStyle.current(dark: scheme == .dark)
        Image(systemName: symbol)
            .font(.system(size: size * 0.5, weight: style == .regular ? .semibold : .medium))
            .foregroundStyle(glyph(style))
            .frame(width: size, height: size)
            .background(shape.fill(tile(style)))
            .overlay(shape.strokeBorder(Color.primary.opacity(style == .regular ? 0 : 0.08), lineWidth: 0.5))
            .accessibilityHidden(true)
    }

    private func glyph(_ style: IconStyle) -> AnyShapeStyle {
        switch style {
        case .regular: return AnyShapeStyle(Color.white)
        case .dark: return AnyShapeStyle(color)
        case .clear: return AnyShapeStyle(Color.primary.opacity(0.85))
        case .tinted: return AnyShapeStyle(Color.accentColor)
        }
    }

    private func tile(_ style: IconStyle) -> AnyShapeStyle {
        switch style {
        case .regular: return AnyShapeStyle(color.gradient)
        case .dark: return AnyShapeStyle(Color.white.opacity(0.1))
        case .clear: return AnyShapeStyle(Color.primary.opacity(0.08))
        case .tinted: return AnyShapeStyle(Color.accentColor.opacity(0.16))
        }
    }
}

/// The icon style from System Settings › Appearance (macOS 26+). The key is not documented;
/// anything unknown falls back to the default, colored tiles.
enum IconStyle {
    case regular, dark, clear, tinted
    static func current(dark: Bool, defaults: UserDefaults = .standard) -> IconStyle {
        guard let theme = defaults.string(forKey: "AppleIconAppearanceTheme") else { return .regular }
        // "Automatic" variants follow the light/dark appearance.
        let darkVariant = theme.hasSuffix("Dark") || (theme.hasSuffix("Automatic") && dark)
        if theme.hasPrefix("Clear") { return .clear }
        if theme.hasPrefix("Tinted") { return .tinted }
        return darkVariant ? .dark : .regular
    }
}

/// Icon, title, secondary subtitle (up to two lines, or more for notes) and a trailing control.
struct SettingsRow<Control: View>: View {
    let symbol: String
    let color: Color
    let title: String
    var subtitle: String?
    var note: String?
    @ViewBuilder var control: Control

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            SettingsIcon(symbol: symbol, color: color)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.body)
                if let subtitle {
                    Text(subtitle).font(.caption).foregroundStyle(.secondary)
                        .lineLimit(3).fixedSize(horizontal: false, vertical: true)
                }
                if let note {
                    Text(note).font(.caption).foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .accessibilityElement(children: .combine)
            control
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
    }
}

extension SettingsRow where Control == EmptyView {
    init(symbol: String, color: Color, title: String, subtitle: String? = nil, note: String? = nil) {
        self.init(symbol: symbol, color: color, title: title, subtitle: subtitle, note: note) { EmptyView() }
    }
}

private extension View {
    /// The tabs are the whole navigation; hiding them would leave the window without it.
    @ViewBuilder func settingsWithoutSidebarToggle() -> some View {
        if #available(macOS 14.0, *) { toolbar(removing: .sidebarToggle) } else { self }
    }
}

private extension Toggle {
    func settingsSwitch(_ label: String) -> some View {
        toggleStyle(.switch).labelsHidden().controlSize(.small).accessibilityLabel(label)
    }
}

// MARK: - Geral

struct GeneralSettings: View {
    let menuBar: MenuBarCoordinator
    @ObservedObject var preferences: AppPreferences
    @ObservedObject var loginItem: LoginItemController

    var body: some View {
        SettingsSection(title: "Aplicativo") {
            SettingsRow(symbol: "menubar.rectangle", color: .blue, title: "Ícone na barra de menus",
                        subtitle: "Para conectar rapidamente.") {
                Toggle("Ícone na barra de menus", isOn: $preferences.showMenuBarIcon).settingsSwitch("Ícone na barra de menus")
            }
            SettingsDivider()
            SettingsRow(symbol: "dock.rectangle", color: .indigo, title: "Ocultar do Dock ao fechar a janela",
                        subtitle: "O app continua na barra de menus.",
                        note: preferences.showMenuBarIcon ? nil : "Precisa do ícone na barra de menus") {
                Toggle("Ocultar do Dock ao fechar a janela",
                       isOn: Binding(get: { preferences.hidesDockOnClose }, set: { preferences.hideDockOnClose = $0 }))
                    .settingsSwitch("Ocultar do Dock ao fechar a janela")
                    .disabled(!preferences.showMenuBarIcon)
            }
            SettingsDivider()
            SettingsRow(symbol: "power", color: .green, title: "Abrir ao iniciar o Mac", subtitle: loginItem.detail) {
                HStack(spacing: 8) {
                    if loginItem.status == .requiresApproval && loginItem.available {
                        Button("Abrir Ajustes…") { loginItem.openSystemSettings() }
                            .controlSize(.small).adaptiveButtonStyle()
                            .help("Ajustes do Sistema › Geral › Itens de Início")
                    }
                    Toggle("Abrir ao iniciar o Mac",
                           isOn: Binding(get: { loginItem.enabled }, set: { loginItem.setEnabled($0) }))
                        .settingsSwitch("Abrir ao iniciar o Mac")
                        .disabled(!loginItem.available)
                }
            }
        }
        InternetDNSSection(preferences: preferences)
    }
}

/// "DNS da internet": servers the service puts on the primary network while a VPN is
/// connected, restoring the previous ones afterwards. Presets plus entries typed by the user.
struct InternetDNSSection: View {
    @ObservedObject var preferences: AppPreferences
    @State private var adding = false

    var body: some View {
        SettingsSection(title: "Rede") {
            SettingsRow(symbol: "network", color: .teal, title: "DNS da internet",
                        subtitle: "Usado enquanto uma VPN está conectada.") {
                menu
            }
        }
        .sheet(isPresented: $adding) { AddInternetDNSSheet(preferences: preferences) }
    }

    private var selectedID: String {
        let id = preferences.internetDNSSelection
        return id == InternetDNSOption.offID || preferences.internetDNSOptions.contains { $0.id == id } ? id : InternetDNSOption.defaultID
    }

    private var selectedLabel: String {
        selectedID == InternetDNSOption.offID ? "Não alterar"
            : preferences.internetDNSOptions.first { $0.id == selectedID }?.label ?? InternetDNSOption.cloudflare.label
    }

    private var menu: some View {
        Menu {
            // Inline pickers get the native checkmark on the selected item.
            Picker("DNS da internet", selection: selection) {
                ForEach(preferences.internetDNSOptions) { Text($0.label).tag($0.id) }
            }
            .pickerStyle(.inline).labelsHidden()
            Divider()
            Picker("Não alterar", selection: selection) {
                Text("Não alterar o DNS").tag(InternetDNSOption.offID)
            }
            .pickerStyle(.inline).labelsHidden()
            Divider()
            Button("Adicionar mais…") { adding = true }
            if let custom = preferences.customInternetDNS.first(where: { $0.id == selectedID }) {
                Button("Remover \u{201C}\(custom.name)\u{201D}", role: .destructive) { preferences.removeCustomDNS(custom.id) }
            }
        } label: {
            Text(selectedLabel).lineLimit(1).truncationMode(.tail)
        }
        .menuStyle(.borderlessButton)
        .frame(maxWidth: 230, alignment: .trailing)
        .accessibilityLabel("DNS da internet")
    }

    private var selection: Binding<String> {
        Binding(get: { selectedID }, set: { preferences.internetDNSSelection = $0 })
    }
}

struct AddInternetDNSSheet: View {
    @ObservedObject var preferences: AppPreferences
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var servers = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Adicionar DNS").font(.headline)
            Form {
                TextField("Nome", text: $name, prompt: Text("Meu DNS"))
                TextField("Servidores", text: $servers, prompt: Text("9.9.9.9, 149.112.112.112"))
            }
            .formStyle(.grouped)
            Text("Até 4 endereços IPv4 ou IPv6, separados por vírgula.").font(.caption).foregroundStyle(.secondary)
            if let error { Text(error).font(.caption).foregroundStyle(.red) }
            HStack {
                Spacer()
                Button("Cancelar") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Adicionar") {
                    do { preferences.addCustomDNS(try InternetDNSOption.custom(name: name, servers: servers)); dismiss() }
                    catch { self.error = error.localizedDescription }
                }
                .keyboardShortcut(.defaultAction).adaptiveButtonStyle(prominent: true)
            }
        }
        .padding(20)
        .frame(width: 400)
    }
}

// MARK: - Atualizações

struct UpdateSettings: View {
    @ObservedObject var updates: UpdateChecker
    @ObservedObject var installer: AppUpdater
    @ObservedObject var preferences: AppPreferences
    let installedByHomebrew: Bool
    @State private var copied = false
    @State private var showsHomebrew = false

    var body: some View {
        SettingsSection(title: "Versão instalada") {
            SettingsRow(symbol: "shippingbox", color: .blue, title: "TunnelMac \(HelperConstants.releaseVersion)",
                        subtitle: lastCheckText) {
                HStack(spacing: 8) {
                    if updates.checking {
                        ProgressView().controlSize(.small).accessibilityLabel("Verificando")
                    }
                    Button("Verificar agora") { updates.checkNow() }
                        .controlSize(.small).adaptiveButtonStyle()
                        .disabled(updates.checking)
                }
            }
        }
        if !updates.checking {
            switch updates.outcome {
            case .failed:
                InlineNotice(tone: .warning, symbol: "wifi.exclamationmark", title: "Não foi possível verificar agora",
                             message: "Sem internet ou GitHub indisponível. Tenta de novo mais tarde.")
            case .upToDate:
                InlineNotice(tone: .success, symbol: "checkmark.circle", title: "Você está na versão mais recente")
            case .none, .available:
                EmptyView()
            }
        }
        if let offer = updates.offer { offerSection(offer) }
        SettingsSection(title: "Verificação") {
            SettingsRow(symbol: "clock.arrow.circlepath", color: .teal, title: "Verificar automaticamente",
                        subtitle: "Ao abrir o app e ao conectar.") {
                Toggle("Verificar automaticamente", isOn: $preferences.checkForUpdates).settingsSwitch("Verificar automaticamente")
            }
            SettingsDivider()
            SettingsRow(symbol: "testtube.2", color: .purple, title: "Incluir versões de teste") {
                Toggle("Incluir versões de teste", isOn: Binding(get: { preferences.includePrereleases },
                                                                  set: { preferences.includePrereleases = $0; updates.channelChanged() }))
                    .settingsSwitch("Incluir versões de teste")
            }
        }
    }

    private var lastCheckText: String {
        guard let last = preferences.lastUpdateSuccess else {
            return preferences.lastUpdateAttempt == nil ? "Ainda não verificado" : "Nenhuma verificação concluída ainda"
        }
        let formatter = RelativeDateTimeFormatter()
        formatter.locale = Locale(identifier: "pt_BR")
        formatter.unitsStyle = .full
        let now = updates.now()
        return now.timeIntervalSince(last) < 60 ? "Verificado há instantes" : "Verificado \(formatter.localizedString(for: last, relativeTo: now))"
    }

    @ViewBuilder private func offerSection(_ offer: UpdateOffer) -> some View {
        SettingsSection(title: "Nova versão") {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .center, spacing: 12) {
                    Image(nsImage: NSApp.applicationIconImage).resizable().frame(width: 40, height: 40).accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("TunnelMac \(offer.version)").font(.headline).textSelection(.enabled)
                        Text(subtitle(offer)).font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer(minLength: 8)
                    UpdateDot()
                }
                if !offer.notes.isEmpty {
                    ScrollView(.vertical) {
                        Text(offer.notes).font(.callout).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading).padding(10)
                    }
                    .frame(maxHeight: 150)
                    .contentPanel(cornerRadius: 8)
                }
                HStack(spacing: 8) {
                    Button { open(offer) } label: { Label("Ver no GitHub", systemImage: "arrow.up.right.square") }
                        .adaptiveButtonStyle()
                    Button("Pular esta versão") { updates.skipOffer() }
                        .adaptiveButtonStyle()
                        .help("Não oferecer mais a \(offer.version); uma versão maior volta a aparecer")
                }
                .controlSize(.small)
            }
            .padding(14)
        }
        SettingsSection(title: "Como atualizar") {
            VStack(alignment: .leading, spacing: 12) {
                if installer.available && installer.awaitingQuit {
                    Button { installer.install(offer) } label: { Label("Instalar e reabrir", systemImage: "arrow.clockwise.circle") }
                        .adaptiveButtonStyle(prominent: true).controlSize(.small)
                    Text("A versão \(offer.version) já foi baixada. Ela é instalada quando você fechar o app.")
                        .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                } else if installer.available {
                    HStack(spacing: 10) {
                        Button { installer.install(offer) } label: { Label("Atualizar agora", systemImage: "arrow.down.circle") }
                            .adaptiveButtonStyle(prominent: true).controlSize(.small) // Busy: brings Sparkle's window forward.
                        if installer.busy {
                            ProgressView().controlSize(.small).accessibilityLabel("Atualizando")
                            Text("Acompanhe na janela de atualização.").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    Text("Baixa a versão \(offer.version) e reabre o app. As VPNs são desconectadas; conexões e senhas ficam.")
                        .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    if installedByHomebrew {
                        DisclosureGroup("Prefiro atualizar pelo Homebrew", isExpanded: $showsHomebrew) {
                            VStack(alignment: .leading, spacing: 12) {
                                Text("Use o comando abaixo; o Homebrew não atualiza este app sozinho.")
                                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                                homebrewSteps
                            }
                            .padding(.top, 8)
                        }
                        .font(.callout)
                    }
                } else if installedByHomebrew {
                    homebrewSteps
                } else {
                    Text("Baixe a nova versão no GitHub e substitua o app com ele fechado.")
                        .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    Button { open(offer) } label: { Label("Baixar no GitHub", systemImage: "arrow.down.circle") }
                        .adaptiveButtonStyle(prominent: true).controlSize(.small)
                }
            }
            .padding(14)
        }
    }

    /// Quit, run the command, reopen: Homebrew refuses to upgrade while the app runs.
    @ViewBuilder private var homebrewSteps: some View {
        VStack(alignment: .leading, spacing: 4) {
            step(1, "Saia do TunnelMac com Sair (isso desconecta as VPNs).")
            step(2, "Cole o comando no Terminal.")
            step(3, "Abra o app de novo.")
        }
        Text(HomebrewInstall.upgradeCommand)
            .font(.system(.callout, design: .monospaced))
            .textSelection(.enabled)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(10)
            .contentPanel(cornerRadius: 8)
            .accessibilityLabel("Comando: \(HomebrewInstall.upgradeCommand)")
        HStack(spacing: 8) {
            Button {
                HomebrewInstall.copyCommand()
                copied = true
            } label: { Label(copied ? "Copiado" : "Copiar comando", systemImage: copied ? "checkmark" : "doc.on.doc") }
                .adaptiveButtonStyle(prominent: !installer.available)
            Button { HomebrewInstall.openTerminal() } label: { Label("Abrir Terminal", systemImage: "terminal") }
                .adaptiveButtonStyle()
        }
        .controlSize(.small)
    }

    private func step(_ number: Int, _ text: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Text("\(number).").monospacedDigit().foregroundStyle(.secondary)
            Text(text).fixedSize(horizontal: false, vertical: true)
        }
        .font(.callout)
    }

    private func subtitle(_ offer: UpdateOffer) -> String {
        var parts = [offer.prerelease ? "Versão de teste" : "Versão estável"]
        if let date = offer.publishedAt {
            parts.append("publicada em " + date.formatted(.dateTime.day().month(.wide).year().locale(Locale(identifier: "pt_BR"))))
        }
        return parts.joined(separator: " · ")
    }

    private func open(_ offer: UpdateOffer) {
        if let url = offer.pageURL { NSWorkspace.shared.open(url) }
    }
}

// MARK: - Serviço privilegiado

struct ServiceSettings: View {
    let model: AppModel
    /// Checked against SECURITY.md and VPNHelperCore: XPC peers must carry this app's
    /// identifier and Team ID, the helper only starts the approved, integrity-checked
    /// runtime copy, and passwords reach it per connection through file descriptors.
    static let explanation = "Cria o túnel da VPN e ajusta rotas e DNS sem pedir sua senha a cada conexão. Só aceita pedidos deste app e não guarda senhas."

    /// What to do first on top (state, approvals, actions); the explanation below.
    var body: some View {
        SettingsSection(title: "Estado") {
            ServicePanel(model: model).padding(16)
        }
        SettingsSection(title: "Para que serve",
                        footer: "Antes de desinstalar o app, use Remover serviço.") {
            HStack(alignment: .top, spacing: 12) {
                SettingsIcon(symbol: "lock.shield", color: .blue)
                Text(Self.explanation).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            .padding(14)
        }
    }
}

// MARK: - Sobre

struct AboutSettings: View {
    var body: some View {
        HStack(spacing: 16) {
            Image(nsImage: NSApp.applicationIconImage).resizable().frame(width: 72, height: 72).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text("TunnelMac").font(.title2.weight(.semibold))
                Text("Versão \(HelperConstants.releaseVersion) (build \(HelperConstants.build))")
                    .font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
                Text("Interface nativa de macOS para o openfortivpn, o OpenVPN e o WireGuard.").font(.callout).foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .combine)
        SettingsSection(title: "Links") {
            link("chevron.left.forwardslash.chevron.right", .gray, "Repositório", "github.com/\(UpdateFeed.repository)", UpdateFeed.repositoryPage)
            SettingsDivider()
            link("doc.text", .blue, "Notas desta versão", "v\(HelperConstants.releaseVersion) no GitHub",
                 UpdateFeed.releasePage(for: HelperConstants.releaseVersion))
            SettingsDivider()
            link("checkmark.seal", .green, "Licença", "MIT", URL(string: "https://github.com/\(UpdateFeed.repository)/blob/main/LICENSE"))
            SettingsDivider()
            link("list.bullet.rectangle", .orange, "Avisos de terceiros", "THIRD_PARTY_NOTICES.md",
                 URL(string: "https://github.com/\(UpdateFeed.repository)/blob/main/THIRD_PARTY_NOTICES.md"))
        }
        SettingsSection(title: "Dependências") {
            SettingsRow(symbol: "terminal", color: .gray, title: "openfortivpn",
                        subtitle: "Para Fortinet SSL VPN. Dependência externa, instalada pelo Homebrew e mantida pelo próprio projeto. Não é distribuída com o TunnelMac.")
            SettingsDivider()
            SettingsRow(symbol: "terminal", color: .gray, title: "OpenVPN 2.7+",
                        subtitle: "Para perfis OpenVPN (brew install openvpn). Dependência externa, não distribuída com o TunnelMac.")
            SettingsDivider()
            SettingsRow(symbol: "terminal", color: .gray, title: "wireguard-go",
                        subtitle: "Para perfis WireGuard (brew install wireguard-go). Dependência externa, não distribuída com o TunnelMac; o wg-quick não é usado.")
        }
    }

    private func link(_ symbol: String, _ color: Color, _ title: String, _ subtitle: String, _ url: URL?) -> some View {
        SettingsRow(symbol: symbol, color: color, title: title, subtitle: subtitle) {
            Button { if let url { NSWorkspace.shared.open(url) } } label: { Image(systemName: "arrow.up.right.square") }
                .buttonStyle(.borderless)
                .help("Abrir no navegador")
                .accessibilityLabel("Abrir \(title) no navegador")
                .disabled(url == nil)
        }
    }
}

// MARK: - Update card (main window)

/// Discreet notice above the detail area: never covers content, never modal.
struct UpdateCard: View {
    let offer: UpdateOffer
    let update: () -> Void
    let later: () -> Void
    @Environment(\.colorSchemeContrast) private var contrast

    /// The first bullets when the notes have them (headings carry little), else the first lines.
    private var summary: String {
        let lines = offer.notes.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        let bullets = lines.filter { $0.hasPrefix("• ") }.map { String($0.dropFirst(2)) }
        return (bullets.isEmpty ? lines : bullets).prefix(2).joined(separator: " · ")
    }

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: 12, style: .continuous)
        HStack(alignment: .center, spacing: 12) {
            Image(nsImage: NSApp.applicationIconImage).resizable().frame(width: 34, height: 34).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text("TunnelMac \(offer.version) disponível").font(.callout.weight(.semibold))
                Text(summary.isEmpty ? "Uma nova versão está disponível." : summary)
                    .font(.caption).foregroundStyle(.secondary).lineLimit(2)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .accessibilityElement(children: .combine)
            GlassGroup(spacing: 6) {
                HStack(spacing: 6) {
                    Button { if let url = offer.pageURL { NSWorkspace.shared.open(url) } } label: {
                        Label("Ver novidades", systemImage: "doc.text.magnifyingglass").labelStyle(.iconOnly)
                    }
                    .adaptiveButtonStyle()
                    .help("Ver novidades no GitHub")
                    Button("Depois", action: later).adaptiveButtonStyle()
                        .help("Esconder até a próxima abertura do app")
                    Button("Atualizar", action: update).adaptiveButtonStyle(prominent: true)
                        .help("Baixar, instalar e reiniciar o TunnelMac")
                }
                .controlSize(.small)
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 10)
        .background(shape.fill(Color.accentColor.opacity(0.08)))
        .overlay(shape.strokeBorder(Color.accentColor.opacity(contrast == .increased ? 0.7 : 0.28), lineWidth: contrast == .increased ? 1 : 0.75))
    }
}
