import SwiftUI
import AppKit
import UniformTypeIdentifiers
import VPNHelperShared

/// Open panel for OpenVPN profiles: a .ovpn/.conf file, a Viscosity .visc folder or its .zip.
enum OpenVPNImportPanel {
    @MainActor static func choose() -> [URL]? {
        let panel = NSOpenPanel()
        panel.title = String(localized: "Importar perfil OpenVPN")
        panel.message = String(localized: "Escolha o .ovpn, a pasta .visc (ou o .zip) ou o .ovpn com os certificados (⌘-clique).")
        panel.prompt = String(localized: "Importar")
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = true
        panel.treatsFilePackagesAsDirectories = false
        return panel.runModal() == .OK && !panel.urls.isEmpty ? panel.urls : nil
    }
}

/// Open panel for a WireGuard configuration (.conf exported by the server or wg-quick).
enum WireGuardImportPanel {
    @MainActor static func choose() -> [URL]? {
        let panel = NSOpenPanel()
        panel.title = String(localized: "Importar perfil WireGuard")
        panel.message = String(localized: "Escolha o arquivo .conf do WireGuard.")
        panel.prompt = String(localized: "Importar")
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        return panel.runModal() == .OK && !panel.urls.isEmpty ? panel.urls : nil
    }
}

/// Original files of a saved import that may go to the Trash (asked once, after saving).
struct ImportCleanup: Equatable {
    var files: [URL]
    /// A .visc folder whose every visible entry was used: trashed as a whole.
    var folder: URL?
    var holdsPrivateKey = false
    var names: [String] { folder.map { [$0.lastPathComponent + String(localized: " (pasta inteira)")] } ?? files.map(\.lastPathComponent) }
    func trash() -> [String] {
        var failed: [String] = []
        for url in folder.map({ [$0] }) ?? files {
            do { try FileManager.default.trashItem(at: url, resultingItemURL: nil) }
            catch { failed.append(url.lastPathComponent) }
        }
        return failed
    }
}

struct ConnectionEditor: View {
    @ObservedObject var model: AppModel
    @State private var importGeneration = 0
    @State var connection: Connection
    /// A profile just read from disk (new import or replacement); saved only on Adicionar/Salvar.
    @State var pendingImport: OpenVPNImport?
    @State var pendingWireGuard: WireGuardImport?
    var saved: () -> Void
    /// Opens Configurações › Serviço privilegiado (nil where there is no window to open it from).
    var openService: (() -> Void)?
    /// Type chosen while its client is not usable by the service: asked before the form.
    @State private var serviceBlock: VPNProtocol?
    @State private var password = ""
    /// Typed in this sheet (as opposed to read from the Keychain); never cleared behind the user's back.
    @State private var passwordTyped = false
    @State private var revealPassword = false
    /// Fortinet gateway as typed: host, host:port or host:port/realm.
    @State private var gatewayText = ""
    /// "Só redes internas" as typed; read into the connection when saving.
    @State private var networksText = ""
    /// Check Point: last "Consultar gateway" (certificate and the helper's snx-rs -m info).
    @State private var checkPointCertificate: CheckPointGateway.Certificate?
    @State private var checkPointInfo: CheckPointGatewayInfo?
    @State private var checkPointQueryError: String?
    @State private var checkPointQuerying = false
    @State private var checkPointQueryGeneration = 0
    /// Gateway text of the last query, so leaving the field does not ask again for the same one.
    @State private var checkPointQueriedText: String?
    /// Short wait after typing or pasting a complete address before querying it.
    @State private var checkPointDebounce: Task<Void, Never>?
    @State private var error: String?
    @State private var loaded = false
    @State private var applyDigestFix = false
    @State private var step: Step
    /// Saved profile of an existing OpenVPN connection, for the compatibility option.
    @State private var savedProfile: OpenVPNProfile?
    @State private var dropTargeted = false
    /// Saved import whose originals may now go to the Trash (asked once, after saving).
    @State private var cleanup: ImportCleanup?
    /// Keychain identities offered as client certificate (Fortinet).
    @State private var identities: [ClientIdentity] = []
    @FocusState private var focus: Field?
    @Environment(\.dismiss) private var dismiss
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    init(model: AppModel, connection: Connection, pendingImport: OpenVPNImport? = nil, pendingWireGuard: WireGuardImport? = nil,
         openService: (() -> Void)? = nil, saved: @escaping () -> Void) {
        self.openService = openService
        _model = ObservedObject(wrappedValue: model)
        _connection = State(initialValue: connection)
        _pendingImport = State(initialValue: pendingImport)
        _pendingWireGuard = State(initialValue: pendingWireGuard)
        // A blank new cadastro starts by choosing the VPN type.
        let blank = connection.name.isEmpty && pendingImport == nil && pendingWireGuard == nil
            && !model.data.connections.contains { $0.id == connection.id }
        _step = State(initialValue: blank ? .chooseKind : .form)
        self.saved = saved
    }

    private enum Field: Hashable { case name, server, username, password, certificate }
    private enum Step { case chooseKind, chooseFiles, form }

    private var isNew: Bool { !model.data.connections.contains { $0.id == connection.id } }

    var body: some View {
        switch step {
        case .chooseKind: kindChooser
        case .chooseFiles: fileChooser
        case .form: form
        }
    }

    // MARK: Step 1 — type

    private var kindChooser: some View {
        ProtocolChooser(catalog: .standard, state: clientState, openService: openService.map { open in { dismiss(); open() } },
                        cancelDisabled: model.writing, choose: choose, cancel: { dismiss() })
        .sheetFrame(width: 560, height: ProtocolChooser.sheetHeight(count: ProtocolCatalog.standard.entries.count))
        .alert("Serviço privilegiado necessário", isPresented: Binding(get: { serviceBlock != nil }, set: { if !$0 { serviceBlock = nil } }),
               presenting: serviceBlock) { kind in
            if let openService {
                Button("Abrir Serviço privilegiado") { serviceBlock = nil; dismiss(); openService() }
            }
            Button("Cadastrar mesmo assim") { serviceBlock = nil; proceed(kind) }
            Button("Cancelar", role: .cancel) { serviceBlock = nil }
        } message: { kind in
            Text(String(localized: "Conexões \(kind.title) só conectam com o \(kind.runtime.title) aprovado no serviço privilegiado.")
                 + "\n\n" + (serviceProblem(kind) ?? ""))
                .font(.callout)
        }
    }

    /// Client line of a type in the chooser, in the locale the chooser is shown in.
    private func clientState(_ kind: VPNProtocol, locale: Locale) -> ProtocolClientState {
        if let problem = serviceProblem(kind) { return ProtocolClientState(kind: .problem, text: problem) }
        guard model.service.health != .checking else {
            return ProtocolClientState(kind: .checking, text: LocalizedStringResource("Verificando o serviço…").string(in: locale))
        }
        let runtime = model.service.status?.runtime(kind.runtime)
        return ProtocolClientState(kind: .ready, text: LocalizedStringResource("\(kind.runtime.title) \(runtime?.version ?? "") aprovado").string(in: locale))
    }

    /// Why the service cannot run this type's client now; nil while the service is still being checked.
    private func serviceProblem(_ kind: VPNProtocol) -> String? {
        guard model.service.health != .checking else { return nil }
        return model.service.unavailableReason(for: kind.runtime)
    }

    /// A new connection of a type the service cannot run yet asks first, so the user learns it
    /// before filling the form instead of at Conectar.
    private func choose(_ kind: VPNProtocol) {
        switch ProtocolChoice.decide(isNew: isNew, problem: serviceProblem(kind)) {
        case .askService: serviceBlock = kind
        case .proceed: proceed(kind)
        }
    }

    private func proceed(_ kind: VPNProtocol) {
        connection.kind = kind
        error = nil
        if kind == .globalProtect && isNew { connection.authentication = .saml }
        if kind == .checkPoint { connection.authentication = .password; if connection.checkPoint == nil { connection.checkPoint = CheckPointSettings() } }
        if [.fortinet, .globalProtect, .checkPoint].contains(kind) { step = .form; loaded = true; focus = .name } else { step = .chooseFiles }
    }

    // MARK: Step 2 — profile files

    private var fileChooser: some View {
        let kind = connection.kind
        let wireGuard = kind == .wireguard
        return VStack(spacing: 0) {
            SheetHeader(symbol: "doc.badge.gearshape", tone: .neutral, title: String(localized: "Importar perfil \(kind.title)"), kind: kind)
                .padding(.horizontal, 22).padding(.top, 20).padding(.bottom, 4)
            VStack(alignment: .leading, spacing: 16) {
                VStack(spacing: 10) {
                    ProtocolIcon(kind: kind, size: 40)
                    Text(wireGuard ? "Arraste o arquivo .conf para cá" : "Arraste o perfil e os certificados para cá").font(.headline)
                    Button(wireGuard ? "Escolher arquivo…" : "Escolher arquivos…") { chooseFiles() }
                        .adaptiveButtonStyle(prominent: true)
                        .keyboardShortcut(.defaultAction)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 22)
                .background(RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(kind.brandColor.opacity(dropTargeted ? 0.14 : 0.05)))
                .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .strokeBorder(style: StrokeStyle(lineWidth: dropTargeted ? 2 : 1, dash: [6, 4]))
                    .foregroundStyle(dropTargeted ? kind.brandColor : Color.secondary.opacity(0.5)))
                .onDrop(of: [UTType.fileURL], isTargeted: $dropTargeted) { providers in
                    receive(providers); return true
                }
                VStack(alignment: .leading, spacing: 8) {
                    Text("Aceita").font(.callout.weight(.semibold))
                    if wireGuard {
                        Label("O .conf do servidor ou do app WireGuard", systemImage: "doc.text")
                    } else {
                        Label("Um .ovpn ou .conf", systemImage: "doc.text")
                        Label("Uma pasta .visc do Viscosity, ou o .zip dela", systemImage: "folder")
                        Label("O .ovpn com os certificados, selecionados juntos", systemImage: "doc.on.doc")
                    }
                }
                .font(.callout)
            }
            .padding(.horizontal, 22).padding(.vertical, 14)
            if let error {
                InlineNotice(tone: .danger, symbol: "exclamationmark.triangle.fill", title: error)
                    .padding(.horizontal, 20).padding(.bottom, 12)
            }
            Spacer(minLength: 0)
            SheetFooter {
                Button("Voltar") { error = nil; step = .chooseKind }
                Spacer()
                Button("Cancelar") { dismiss() }.keyboardShortcut(.cancelAction).disabled(model.writing)
            }
        }
        .sheetFrame(width: 560, height: 560)
    }

    private func receive(_ providers: [NSItemProvider]) {
        var urls: [URL] = []
        let group = DispatchGroup()
        let lock = NSLock()
        for provider in providers where provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) {
            group.enter()
            _ = provider.loadObject(ofClass: URL.self) { url, _ in
                if let url { lock.withLock { urls.append(url) } }
                group.leave()
            }
        }
        group.notify(queue: .main) { if !urls.isEmpty { importFiles(urls) } }
    }

    private func chooseFiles() {
        let urls = connection.isWireGuard ? WireGuardImportPanel.choose() : OpenVPNImportPanel.choose()
        if let urls { importFiles(urls) }
    }

    private func importFiles(_ urls: [URL]) {
        if connection.isWireGuard { importWireGuard(urls); return }
        importGeneration += 1
        let generation = importGeneration
        Task {
        do {
            let imported = try await Task.detached { try OpenVPNImporter.load(urls) }.value
            guard generation == importGeneration else { return }
            pendingImport = imported
            applyDigestFix = false
            connection.kind = .openvpn
            connection.openVPN = imported.summary
            connection.port = imported.profile.remotes.first?.port ?? 1194
            if connection.name.isEmpty { connection.name = imported.name }
            if connection.username.isEmpty { connection.username = imported.username }
            // After the username change has reset the field (see onChange below).
            if !imported.password.isEmpty { DispatchQueue.main.async { password = imported.password } }
            error = nil
            loaded = true
            step = .form
        } catch { if generation == importGeneration { self.error = error.localizedDescription } }
        }
    }

    private func importWireGuard(_ urls: [URL]) {
        importGeneration += 1
        let generation = importGeneration
        Task {
        do {
            let imported = try await Task.detached { try WireGuardImporter.load(urls) }.value
            guard generation == importGeneration else { return }
            pendingWireGuard = imported
            connection.kind = .wireguard
            connection.wireGuard = imported.summary
            if connection.name.isEmpty { connection.name = imported.name }
            error = nil
            loaded = true
            step = .form
        } catch { if generation == importGeneration { self.error = error.localizedDescription } }
        }
    }

    // MARK: Step 3 — details

    private var form: some View {
        formContent
            .alert("Apagar os arquivos originais?", isPresented: Binding(get: { cleanup != nil }, set: { if !$0 { finishCleanup(trash: false) } })) {
                Button("Mover para a Lixeira", role: .destructive) { finishCleanup(trash: true) }
                Button("Manter", role: .cancel) { finishCleanup(trash: false) }
            } message: {
                Text(cleanupMessage)
            }
    }

    private var cleanupMessage: String {
        guard let cleanup else { return "" }
        let intro = cleanup.holdsPrivateKey
            ? String(localized: "O app já guardou o perfil. O original não é mais necessário e ainda contém a chave privada:\n\n")
            : String(localized: "O app já guardou o perfil e as chaves. Os originais não são mais necessários:\n\n")
        return intro + cleanup.names.joined(separator: "\n") + String(localized: "\n\nEles vão para a Lixeira; esvazie-a para apagá-los de vez.")
    }

    private func finishCleanup(trash: Bool) {
        guard let pending = cleanup else { return }
        cleanup = nil
        if trash {
            let failed = pending.trash()
            if !failed.isEmpty {
                let names = failed.joined(separator: ", ")
                model.error = String(localized: "Não foi possível mover para a Lixeira: \(names). A conexão foi salva normalmente.")
            }
        }
        saved(); dismiss()
    }

    private var formContent: some View {
        VStack(spacing: 0) {
            SheetHeader(symbol: connection.usesProfile ? "doc.badge.gearshape" : "network.badge.shield.half.filled", tone: .neutral,
                        title: isNew ? (connection.usesProfile ? String(localized: "Importar perfil \(connection.kind.title)") : String(localized: "Nova conexão")) : String(localized: "Editar conexão"),
                        subtitle: isNew ? (connection.usesProfile ? nil : connection.kind.title) : "\(connection.name) · \(connection.kind.title)",
                        kind: connection.kind)
                .padding(.horizontal, 22).padding(.top, 20).padding(.bottom, 4)
            Form {
                switch connection.kind {
                case .fortinet: fortinetSections
                case .openvpn: openVPNSections
                case .wireguard: wireGuardSections
                case .globalProtect: globalProtectSections
                case .checkPoint: checkPointSections
                }
            }
            .formStyle(.grouped)
            .animation(Motion.state(reduceMotion), value: connection.authentication)
            if isNew, let problem = serviceProblem(connection.kind) {
                InlineNotice(tone: .warning, symbol: "exclamationmark.shield.fill",
                             title: String(localized: "Esta conexão ainda não conecta: o serviço privilegiado não está pronto para o \(connection.kind.runtime.title)."),
                             message: problem) {
                    if let openService {
                        Button("Abrir Serviço privilegiado") { dismiss(); openService() }
                    }
                }
                .padding(.horizontal, 20).padding(.bottom, 12)
            }
            if let error {
                InlineNotice(tone: .danger, symbol: "exclamationmark.triangle.fill", title: error)
                    .padding(.horizontal, 20).padding(.bottom, 12)
                    .transition(.opacity)
            }
            SheetFooter {
                Spacer()
                Button("Cancelar") { dismiss() }.keyboardShortcut(.cancelAction).disabled(model.writing)
                Button(saveTitle) {
                    if let authority = pendingAuthority { trust(authority) }
                    save()
                }
                    .keyboardShortcut(.defaultAction)
                    .adaptiveButtonStyle(prominent: true)
                    .disabled(!loaded || model.writing || !model.ready || checkPointQuerying)
            }
        }
        .sheetFrame(width: 560, height: connection.usesProfile ? 640 : 600)
        .animation(Motion.state(reduceMotion), value: error)
        .onAppear {
            gatewayText = GatewayAddress.display(host: connection.server, port: connection.port, realm: connection.realm)
            networksText = connection.routedNetworks.joined(separator: ", ")
            if model.manager.session(connection.id).authenticationRejected {
                password = ""
                error = String(localized: "A última autenticação foi recusada. Confira o usuário e digite a senha novamente para evitar um bloqueio.")
                loaded = true
            } else if let pendingImport, isNew {
                password = pendingImport.password
                loaded = true
            } else if connection.isWireGuard {
                loaded = true // No password: the key is in the saved profile.
            } else {
                let store = model.passwords, id = connection.id
                Task {
                    do { password = try await Task.detached { try store.read(id) ?? "" }.value; loaded = true }
                    catch { self.error = error.localizedDescription }
                }
            }
            if isNew { focus = .name }
            if !isNew, connection.isOpenVPN, pendingImport == nil {
                let profiles = model.profiles, id = connection.id
                Task {
                    if let profile = try? await Task.detached(operation: {
                        guard let profiles else { throw AppFailure(String(localized: "Perfis indisponíveis.")) }
                        return try OpenVPNProfile.validated(profiles.read(id))
                    }).value {
                        savedProfile = profile
                        if let fix = editFix { applyDigestFix = OpenVPNCompatibility.isApplied(fix, in: profile) }
                    }
                }
            }
        }
        .onDisappear { importGeneration += 1 }
        .onChange(of: connection.username) { _ in
            // A saved password belongs to its account: changing the user drops it. One typed in
            // this sheet stays, whatever order the fields were filled in.
            if loaded && !passwordTyped { password = "" }
        }
    }

    /// Password with the eye button to show it, as in the macOS password fields.
    private var passwordRow: some View {
        let typed = Binding(get: { password }, set: { password = $0; passwordTyped = true })
        return LabeledContent("Senha") {
            HStack(spacing: 6) {
                Group {
                    if revealPassword { TextField("Senha", text: typed) } else { SecureField("Senha", text: typed) }
                }
                .labelsHidden()
                .multilineTextAlignment(.trailing)
                .focused($focus, equals: .password)
                Button { revealPassword.toggle() } label: {
                    Image(systemName: revealPassword ? "eye.slash" : "eye").foregroundStyle(.secondary)
                }
                .buttonStyle(.borderless)
                .help(revealPassword ? "Ocultar senha" : "Mostrar senha")
                .accessibilityLabel(revealPassword ? "Ocultar senha" : "Mostrar senha")
            }
        }
    }

    // MARK: Check Point

    private var loginType: Binding<String> {
        Binding(get: { connection.checkPoint?.loginType ?? "" }, set: { value in
            var settings = connection.checkPoint ?? CheckPointSettings()
            settings.loginType = value
            connection.checkPoint = settings
        })
    }

    /// Login types of the last query, answered through the system validation or the gateway's own
    /// authority (trusted on save).
    private var checkPointOptions: [CheckPointLoginOption]? {
        guard let options = checkPointInfo?.loginOptions, !options.isEmpty else { return nil }
        switch checkPointCertificate {
        case .system, .authority: return options
        default: return nil
        }
    }

    /// The gateway's authority found by the last query and not trusted yet: saving trusts it.
    private var pendingAuthority: CheckPointAuthority? {
        guard connection.isCheckPoint, case .authority(let found) = checkPointCertificate,
              found.sha256 != connection.checkPoint?.authority?.sha256 else { return nil }
        return found
    }

    private var saveTitle: String {
        if pendingAuthority != nil {
            return isNew ? String(localized: "Confiar no certificado e adicionar") : String(localized: "Confiar no certificado e salvar")
        }
        return isNew ? String(localized: "Adicionar") : String(localized: "Salvar")
    }

    @ViewBuilder private var checkPointSections: some View {
        Section {
            TextField("Nome", text: $connection.name, prompt: Text("Escritório"))
                .focused($focus, equals: .name)
            TextField("Servidor", text: $gatewayText, prompt: Text("vpn.exemplo.com"))
                .focused($focus, equals: .server)
                .help("O endereço que o certificado do gateway cobre: vpn.exemplo.com ou 203.0.113.10:4443")
                .onChange(of: gatewayText) { _ in gatewayEdited() }
                .onSubmit { queryCheckPointIfNeeded() }
                .onChange(of: focus) { field in if field != .server { queryCheckPointIfNeeded() } }
            if checkPointQuerying {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Consultando o gateway…").foregroundStyle(.secondary)
                }
            }
        } header: {
            Text("Gateway")
        } footer: {
            if let checkPointQueryError {
                Text(checkPointQueryError).font(.footnote).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
            }
        }
        Section {
            TextField("Usuário", text: $connection.username, prompt: Text("usuário"))
                .focused($focus, equals: .username)
            passwordRow
            if let options = checkPointOptions, options.count == 1, let only = options.first, CheckPointRules.isSupported(only) {
                // The gateway offers a single type: nothing to choose.
                LabeledContent("Tipo de login") { Text("\(only.displayName) (\(only.id))") }
            } else if let options = checkPointOptions {
                Picker("Tipo de login", selection: loginType) {
                    if !options.contains(where: { $0.id == loginType.wrappedValue }) { Text("Escolha…").tag(loginType.wrappedValue) }
                    ForEach(options) { option in
                        let reason = CheckPointGateway.unsupportedReason(option)
                        Text(reason.map { "\(option.displayName) (\(option.id)) — \($0)" } ?? "\(option.displayName) (\(option.id))")
                            .tag(option.id)
                            .disabled(reason != nil)
                    }
                }
                .onChange(of: loginType.wrappedValue) { value in
                    // Unsupported types are shown, never kept.
                    if let option = options.first(where: { $0.id == value }), !CheckPointRules.isSupported(option) {
                        loginType.wrappedValue = options.first(where: CheckPointRules.isSupported)?.id ?? ""
                    }
                }
            } else {
                // The explanation stays in the tooltip: the field rarely needs it.
                TextField("Tipo de login", text: loginType, prompt: Text("vpn"))
                    .help("O identificador do tipo de login (vpn, vpn_Username_Password…). Ao informar o servidor, o app consulta o gateway e lista os disponíveis.")
            }
        } header: {
            Text("Autenticação")
        } footer: {
            if checkPointOptions != nil {
                Text("Só tipos de login com usuário e senha; MFA, navegador e certificado ainda não são suportados.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
        }
        Section {
            checkPointCertificateRows
        } header: {
            Text("Certificado do gateway")
        } footer: {
            if pendingAuthority != nil {
                Text("Compare o SHA-256 ou as palavras com o administrador da VPN antes de salvar: salvar confia nesta autoridade.")
                    .font(.footnote).foregroundStyle(.secondary)
            } else if checkPointCertificate == nil && connection.checkPoint?.authority == nil {
                Text("Informe o servidor para conferir o certificado.").font(.footnote).foregroundStyle(.secondary)
            }
        }
        Section {
            Toggle("Todo o tráfego pela VPN", isOn: $connection.allTraffic)
        } header: {
            Text("Rotas")
        } footer: {
            Text(connection.allTraffic
                 ? "Toda a internet passa pela VPN, onde a empresa pode inspecionar o tráfego."
                 : "Só as redes que o gateway envia passam pela VPN; o resto da internet sai pela sua rede.")
                .font(.footnote).foregroundStyle(.secondary)
        }
    }

    @ViewBuilder private var checkPointCertificateRows: some View {
        switch checkPointCertificate {
        case .system:
            Label("Validação padrão do sistema", systemImage: "checkmark.seal")
        case .authority(let found):
            authorityFacts(found, words: checkPointInfo?.fingerprintWords)
            HStack {
                Spacer()
                if found.sha256 == connection.checkPoint?.authority?.sha256 {
                    Label("Autoridade confiada", systemImage: "checkmark.seal.fill").foregroundStyle(.green)
                } else {
                    Label("Confiada ao salvar", systemImage: "seal").foregroundStyle(.secondary)
                }
            }
        case .mismatch(let names, _):
            Text(names.isEmpty ? String(localized: "O certificado deste gateway não vale para este endereço.")
                 : String(localized: "O certificado deste gateway vale para: \(names.joined(separator: ", ")).")).fixedSize(horizontal: false, vertical: true)
            HStack {
                Spacer()
                ForEach(names.prefix(3), id: \.self) { name in
                    Button("Usar \(name)") { useGatewayName(name) }
                }
            }
        case .untrusted(let reason):
            Text(reason).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        case nil:
            if let saved = connection.checkPoint?.authority {
                authorityFacts(saved, words: saved.fingerprintWords)
                HStack {
                    Spacer()
                    Button("Usar a validação do sistema") { connection.checkPoint?.authority = nil }
                }
            } else {
                Label("Validação padrão do sistema", systemImage: "checkmark.seal").foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder private func authorityFacts(_ authority: CheckPointAuthority, words: String?) -> some View {
        LabeledContent("Autoridade") { Text(authority.subject).textSelection(.enabled).multilineTextAlignment(.trailing) }
        if let notAfter = authority.notAfter {
            LabeledContent("Válida até") { Text(notAfter.formatted(date: .abbreviated, time: .omitted)) }
        }
        LabeledContent("SHA-256") {
            Text(NetworkCertificates.display(authority.sha256.uppercased()))
                .font(.system(.caption, design: .monospaced)).textSelection(.enabled).multilineTextAlignment(.trailing)
        }
        if let words {
            LabeledContent("Fingerprint do gateway") { Text(words).font(.system(.caption, design: .monospaced)).textSelection(.enabled) }
        }
    }

    /// Each edit drops the previous answer; a complete address is queried after a short pause
    /// (typing on or pasting replaces it), anything else when the field loses focus.
    private func gatewayEdited() {
        guard connection.isCheckPoint else { return }
        checkPointDebounce?.cancel()
        resetCheckPointQuery()
        checkPointQueriedText = nil
        guard CheckPointGateway.isCompleteAddress(gatewayText) else { return }
        let text = gatewayText
        checkPointDebounce = Task {
            try? await Task.sleep(nanoseconds: 700_000_000)
            guard !Task.isCancelled, text == gatewayText else { return }
            queryCheckPointIfNeeded()
        }
    }

    private func queryCheckPointIfNeeded() {
        guard connection.isCheckPoint, step == .form else { return }
        let text = gatewayText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, gatewayText != checkPointQueriedText else { return }
        queryCheckPoint()
    }

    private func resetCheckPointQuery() {
        checkPointQueryGeneration += 1
        checkPointCertificate = nil
        checkPointInfo = nil
        checkPointQueryError = nil
        checkPointQuerying = false
    }

    /// TLS check in the app, then `snx-rs -m info` in the helper: with the gateway's own
    /// authority when it has one (the query sends no credential), so its fingerprint words can
    /// be compared before trusting it.
    private func queryCheckPoint() {
        checkPointDebounce?.cancel()
        checkPointQueriedText = gatewayText
        let gateway: (host: String, port: Int, realm: String)
        do {
            gateway = try GatewayAddress.parse(gatewayText)
            guard gateway.realm.isEmpty else { throw AppFailure(String(localized: "Informe o servidor como vpn.exemplo.com ou vpn.exemplo.com:4443.")) }
            _ = try CheckPointRules.server(host: gateway.host, port: gateway.port)
        } catch let violation as RuleViolation { checkPointQueryError = violation.message; return }
        catch { checkPointQueryError = error.localizedDescription; return }
        resetCheckPointQuery()
        checkPointQuerying = true
        let generation = checkPointQueryGeneration
        Task {
            let certificate = await CheckPointGateway.inspect(host: gateway.host, port: gateway.port)
            guard generation == checkPointQueryGeneration else { return }
            checkPointCertificate = certificate
            let authority: Data?
            switch certificate {
            case .system: authority = nil
            case .authority(let found): authority = found.der
            case .mismatch, .untrusted: checkPointQuerying = false; return
            }
            do {
                let info = try await model.service.queryCheckPointGateway(CheckPointGatewayQuery(host: gateway.host, port: gateway.port, authorityDER: authority))
                guard generation == checkPointQueryGeneration else { return }
                checkPointInfo = info
                checkPointQueryError = info.failure
                if info.failure == nil && info.loginOptions.isEmpty {
                    checkPointQueryError = String(localized: "O gateway não listou tipos de login; informe o identificador à mão.")
                }
                if case .authority(let found) = certificate, found.sha256 == connection.checkPoint?.authority?.sha256 {
                    connection.checkPoint?.authority?.fingerprintWords = info.fingerprintWords
                }
                if case .system = certificate { connection.checkPoint?.authority = nil }
                selectDefaultLoginType()
            } catch {
                guard generation == checkPointQueryGeneration else { return }
                checkPointQueryError = error.localizedDescription
            }
            checkPointQuerying = false
        }
    }

    private func trust(_ authority: CheckPointAuthority) {
        var trusted = authority
        trusted.fingerprintWords = checkPointInfo?.fingerprintWords
        var settings = connection.checkPoint ?? CheckPointSettings()
        settings.authority = trusted
        connection.checkPoint = settings
        selectDefaultLoginType()
    }

    /// The first supported login type, unless the current one is still offered.
    private func selectDefaultLoginType() {
        guard let options = checkPointOptions else { return }
        if options.contains(where: { $0.id == loginType.wrappedValue && CheckPointRules.isSupported($0) }) { return }
        loginType.wrappedValue = options.first(where: CheckPointRules.isSupported)?.id ?? loginType.wrappedValue
    }

    private func useGatewayName(_ name: String) {
        let port = (try? GatewayAddress.parse(gatewayText).port) ?? GatewayAddress.defaultPort
        gatewayText = GatewayAddress.display(host: name, port: port, realm: "") // queried as a complete address
    }

    // MARK: GlobalProtect

    @ViewBuilder private var globalProtectSections: some View {
        Section("Gateway") {
            TextField("Nome", text: $connection.name, prompt: Text("Escritório"))
                .focused($focus, equals: .name)
            TextField("Servidor", text: $gatewayText, prompt: Text("vpn.exemplo.com"))
                .focused($focus, equals: .server)
                .help("O gateway GlobalProtect: vpn.exemplo.com ou vpn.exemplo.com:4443")
        }
        Section {
            Picker("Método", selection: $connection.authentication) {
                ForEach(Authentication.allCases) { Text($0.title).tag($0) }
            }
            .pickerStyle(.segmented)
            if connection.authentication == .password {
                TextField("Usuário", text: $connection.username, prompt: Text("usuário"))
                    .focused($focus, equals: .username)
                passwordRow
            }
        } header: {
            Text("Autenticação")
        } footer: {
            if connection.authentication == .saml {
                Text("O login abre no navegador padrão. Ao terminar, permita que o navegador abra o TunnelMac.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
        }
        Section {
            Toggle("Todo o tráfego pela VPN", isOn: $connection.allTraffic)
            if !connection.allTraffic {
                TextField("Redes internas", text: $networksText, prompt: Text("10.0.0.0/8, 172.16.0.0/12"))
            }
        } header: {
            Text("Rotas")
        } footer: {
            Text(connection.allTraffic
                 ? "Segue o gateway, que costuma mandar toda a internet pela VPN, onde a empresa pode inspecionar HTTPS."
                 : "Só estas redes e os domínios da empresa passam pela VPN; o resto da internet sai pela sua rede.")
                .font(.footnote).foregroundStyle(.secondary)
        }
        Section {
            TextField("SHA-256 confiável", text: $connection.trustedCertificate, prompt: Text("Opcional"))
                .focused($focus, equals: .certificate)
        } header: {
            Text("Certificado")
        } footer: {
            Text("Usado só quando o certificado do gateway não é validado pelo macOS.")
                .font(.footnote).foregroundStyle(.secondary)
        }
    }

    // MARK: Fortinet

    @ViewBuilder private var fortinetSections: some View {
        Section("Gateway") {
            TextField("Nome", text: $connection.name, prompt: Text("Escritório"))
                .focused($focus, equals: .name)
            TextField("Servidor", text: $gatewayText, prompt: Text("vpn.exemplo.com:10443"))
                .focused($focus, equals: .server)
                .help("vpn.exemplo.com, vpn.exemplo.com:10443 ou vpn.exemplo.com:443/realm")
        }
        Section {
            Picker("Método", selection: $connection.authentication) {
                ForEach(Authentication.allCases) { Text($0.title).tag($0) }
            }
            .pickerStyle(.segmented)
            TextField("Usuário", text: $connection.username,
                      prompt: Text(connection.authentication == .password ? "usuário" : "Opcional"))
                .focused($focus, equals: .username)
            if connection.authentication == .password { passwordRow }
        } header: {
            Text("Autenticação")
        }
        Section {
            TextField("SHA-256 confiável", text: $connection.trustedCertificate, prompt: Text("Opcional"))
                .focused($focus, equals: .certificate)
            Picker("Certificado do cliente", selection: certificateSelection) {
                Text("Nenhum").tag(String?.none)
                ForEach(identities) { identity in
                    Text(identityLabel(identity)).tag(Optional(identity.sha1))
                }
                if let reference = connection.clientCertificate, !identities.contains(where: { $0.sha1 == reference.sha1 }) {
                    Text("\(reference.name) (não encontrado no Keychain)").tag(Optional(reference.sha1))
                }
            }
            HStack {
                Spacer()
                Button("Importar .p12…") { importCertificate() }
            }
        } header: {
            Text("Certificado")
        }
        .task { identities = await Task.detached { ClientIdentities.list() }.value }
    }

    private var certificateSelection: Binding<String?> {
        Binding(get: { connection.clientCertificate?.sha1 }, set: { sha1 in
            guard let sha1 else { connection.clientCertificate = nil; return }
            if let identity = identities.first(where: { $0.sha1 == sha1 }) { connection.clientCertificate = identity.reference }
        })
    }

    private func identityLabel(_ identity: ClientIdentity) -> String {
        var label = identity.name
        if !identity.issuer.isEmpty && identity.issuer != identity.name { label += " — \(identity.issuer)" }
        if identity.expired { label += String(localized: " (expirado)") }
        return label
    }

    /// Imports a .p12/.pfx into the login keychain and selects it. The file password is used
    /// only for the import and never saved.
    private func importCertificate() {
        let panel = NSOpenPanel()
        panel.title = String(localized: "Importar certificado do cliente")
        panel.message = String(localized: "Escolha o arquivo .p12 ou .pfx.")
        panel.prompt = String(localized: "Continuar")
        panel.allowedContentTypes = [.pkcs12]
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let alert = NSAlert()
        alert.messageText = String(localized: "Senha do certificado")
        alert.informativeText = String(localized: "Digite a senha de \(url.lastPathComponent).")
        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 24))
        alert.accessoryView = field
        alert.addButton(withTitle: String(localized: "Importar"))
        alert.addButton(withTitle: String(localized: "Cancelar"))
        alert.window.initialFirstResponder = field
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        let passphrase = field.stringValue
        field.stringValue = ""
        importGeneration += 1
        let generation = importGeneration
        Task {
            do {
                let (identity, available) = try await Task.detached {
                    let data = try BoundedFile.read(url, limit: 1024 * 1024)
                    let identity = try ClientIdentities.importPKCS12(data, password: passphrase)
                    return (identity, ClientIdentities.list())
                }.value
                guard generation == importGeneration else { return }
                identities = available
                connection.clientCertificate = identity.reference
                error = nil
            } catch { if generation == importGeneration { self.error = error.localizedDescription } }
        }
    }

    // MARK: WireGuard

    private var wireGuardSummary: WireGuardSummary? { pendingWireGuard?.summary ?? connection.wireGuard }

    @ViewBuilder private var wireGuardSections: some View {
        Section("Perfil") {
            TextField("Nome", text: $connection.name, prompt: Text("Escritório"))
                .focused($focus, equals: .name)
            if let summary = wireGuardSummary {
                LabeledContent("Servidor") {
                    VStack(alignment: .trailing, spacing: 2) {
                        ForEach(summary.endpoints.isEmpty ? [String(localized: "Sem endpoint")] : summary.endpoints, id: \.self) { endpoint in
                            Text(endpoint).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                        }
                    }
                }
                LabeledContent("Endereço") {
                    Text(summary.addresses.joined(separator: ", ")).font(.system(.callout, design: .monospaced))
                        .lineLimit(2).truncationMode(.middle).textSelection(.enabled)
                }
                LabeledContent("Rotas") { Text(summary.routesDescription).lineLimit(2).truncationMode(.middle).help(summary.allowedIPs.joined(separator: ", ")) }
                LabeledContent("DNS") { Text(summary.dns.isEmpty ? "Não altera o DNS" : summary.dns.joined(separator: ", ")).lineLimit(1).truncationMode(.middle) }
                LabeledContent("Chave pública") {
                    Text(summary.publicKey).font(.system(.caption, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                        .textSelection(.enabled).help("Chave pública deste perfil, a que o administrador do servidor cadastra. A chave privada nunca é mostrada.")
                }
                if !summary.source.isEmpty {
                    LabeledContent("Origem") {
                        Text(summary.source).lineLimit(1).truncationMode(.middle).help(summary.source).textSelection(.enabled)
                    }
                }
            }
            HStack {
                if pendingWireGuard != nil && !isNew {
                    Text("O novo perfil substitui o atual ao salvar.").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button("Substituir perfil…") { replaceProfile() }.controlSize(.small)
            }
        }
        if let warnings = wireGuardSummary?.warnings, !warnings.isEmpty {
            Section("Avisos da importação") {
                ForEach(warnings, id: \.self) { warning in
                    Label { Text(warning).font(.callout).fixedSize(horizontal: false, vertical: true) }
                        icon: { Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange) }
                }
            }
        }
    }

    // MARK: OpenVPN

    private var summary: OpenVPNSummary? { pendingImport?.summary ?? connection.openVPN }

    @ViewBuilder private var openVPNSections: some View {
        Section("Perfil") {
            TextField("Nome", text: $connection.name, prompt: Text("Escritório"))
                .focused($focus, equals: .name)
            if let summary {
                LabeledContent("Servidores") {
                    VStack(alignment: .trailing, spacing: 2) {
                        ForEach(Array(summary.remotes.enumerated()), id: \.offset) { _, remote in
                            Text(remote.display).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                        }
                    }
                }
                if !summary.source.isEmpty {
                    LabeledContent("Origem") {
                        Text(summary.source).lineLimit(1).truncationMode(.middle).help(summary.source).textSelection(.enabled)
                    }
                }
            }
            HStack {
                if pendingImport != nil && !isNew {
                    Text("O novo perfil substitui o atual ao salvar.").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button("Substituir perfil…") { replaceProfile() }.controlSize(.small)
            }
        }
        if summary?.requiresCredentials == true {
            Section {
                TextField("Usuário", text: $connection.username, prompt: Text("usuário"))
                    .focused($focus, equals: .username)
                passwordRow
            } header: {
                Text("Autenticação")
            }
        }
        if let fix = currentFix {
            Section {
                Toggle(isOn: $applyDigestFix) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Usar auth \(fix.to) em vez de \(fix.from)")
                        Text("O OpenVPN 2.7 recusa auth \(fix.from); \(fix.to) é o equivalente e precisa ser igual ao do servidor.")
                            .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    }
                }
            } header: {
                Text("Compatibilidade")
            }
        }
        if let warnings = summary?.warnings, !warnings.isEmpty {
            Section("Avisos da importação") {
                ForEach(warnings, id: \.self) { warning in
                    Label { Text(warning).font(.callout).fixedSize(horizontal: false, vertical: true) }
                        icon: { Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange) }
                }
            }
        }
    }

    /// The compatibility option of the import being made, or of the saved profile.
    private var currentFix: OpenVPNCompatibility.DigestFix? { pendingImport != nil ? pendingImport?.digestFix : editFix }
    private var editFix: OpenVPNCompatibility.DigestFix? {
        connection.openVPN?.compatibility ?? savedProfile.flatMap { OpenVPNCompatibility.digestFix(for: $0) }
    }

    private func replaceProfile() {
        let urls = connection.isWireGuard ? WireGuardImportPanel.choose() : OpenVPNImportPanel.choose()
        if let urls { importFiles(urls) }
    }

    private func save() {
        Task { await saveInBackground() }
    }
    private func saveInBackground() async {
        do {
            if connection.isWireGuard {
                if let pendingWireGuard { connection.wireGuard = pendingWireGuard.summary }
                try await model.saveAsync(connection, password: "", wireGuardProfile: pendingWireGuard?.profile.text)
                if let pendingWireGuard, !pendingWireGuard.sourceFiles.isEmpty {
                    cleanup = ImportCleanup(files: pendingWireGuard.sourceFiles, holdsPrivateKey: true)
                    return
                }
            } else if connection.isOpenVPN {
                var profileText = pendingImport?.profileText(applyingFix: applyDigestFix)
                if let pendingImport { connection.openVPN = pendingImport.summary }
                if pendingImport == nil, let fix = editFix, let savedProfile,
                   applyDigestFix != OpenVPNCompatibility.isApplied(fix, in: savedProfile) {
                    let changed = applyDigestFix ? OpenVPNCompatibility.apply(fix, to: savedProfile)
                                                 : OpenVPNCompatibility.revert(fix, in: savedProfile)
                    profileText = changed.text
                }
                connection.openVPN?.compatibility = currentFix
                try await model.saveAsync(connection, password: summary?.requiresCredentials == true ? password : "",
                               openVPNProfile: profileText)
                if let pendingImport, !pendingImport.sourceFiles.isEmpty {
                    // The sheet closes after the answer.
                    cleanup = ImportCleanup(files: pendingImport.sourceFiles, folder: pendingImport.sourceFolder)
                    return
                }
            } else {
                let gateway = try GatewayAddress.parse(gatewayText)
                if (connection.isGlobalProtect || connection.isCheckPoint) && !gateway.realm.isEmpty {
                    throw AppFailure(String(localized: "Informe o servidor como vpn.exemplo.com ou vpn.exemplo.com:4443."))
                }
                if connection.isGlobalProtect && connection.authentication == .saml { connection.username = "" }
                if connection.isGlobalProtect && !connection.allTraffic {
                    connection.internalNetworks = networksText.components(separatedBy: CharacterSet(charactersIn: ", \n")).filter { !$0.isEmpty }
                }
                connection.server = gateway.host
                connection.port = gateway.port
                connection.realm = gateway.realm
                try await model.saveAsync(connection, password: password)
            }
            saved(); dismiss()
        } catch { self.error = error.localizedDescription }
    }
}

/// Nova conexão, step 1: the VPN types as a grid of tiles over a quick view of the tile under
/// the pointer (nothing until it passes over one). Nothing is preselected: Tab enters the grid,
/// arrows move the focus, Enter or Space chooses, Tab leaves the grid for Cancelar.
struct ProtocolChooser: View {
    let catalog: ProtocolCatalog
    let state: (VPNProtocol, Locale) -> ProtocolClientState
    /// Opens Serviço privilegiado from the quick view of a type whose client is missing.
    var openService: (() -> Void)?
    var cancelDisabled = false
    let choose: (VPNProtocol) -> Void
    let cancel: () -> Void
    @State private var hovered: String?
    @State private var selection: ProtocolCatalog.Selection
    @FocusState private var focused: String?
    /// The single tile Tab stops at; the arrows move it.
    @State private var current: String?
    @Environment(\.locale) private var locale

    /// The 560 pt sheet minus the grid's margins: five tiles in a row.
    static let gridWidth: CGFloat = 528
    /// Room kept for the quick view, so the sheet does not change size when it appears.
    static let quickViewHeight: CGFloat = 155

    /// Header, the grid's rows, the quick view's room and the footer.
    static func sheetHeight(count: Int) -> CGFloat {
        let columns = ProtocolCatalog.columns(width: gridWidth)
        let rows = CGFloat(max(1, (count + columns - 1) / columns))
        return 60 + rows * ProtocolTileButton.height + (rows - 1) * ProtocolTileButton.spacing + 16 + quickViewHeight + 54
    }

    /// `shown` puts a tile in the quick view from the start (renders only).
    init(catalog: ProtocolCatalog, state: @escaping (VPNProtocol, Locale) -> ProtocolClientState, openService: (() -> Void)? = nil,
         cancelDisabled: Bool = false, shown: String? = nil, choose: @escaping (VPNProtocol) -> Void, cancel: @escaping () -> Void) {
        self.catalog = catalog
        self.state = state
        self.openService = openService
        self.cancelDisabled = cancelDisabled
        self.choose = choose
        self.cancel = cancel
        _selection = State(initialValue: ProtocolCatalog.Selection(shown: shown))
    }

    var body: some View {
        VStack(spacing: 0) {
            SheetHeader(symbol: "plus.circle", tone: .neutral, title: LocalizedStringResource("Nova conexão").string(in: locale),
                        subtitle: LocalizedStringResource("Escolha o tipo de VPN").string(in: locale), brand: true)
                .padding(.horizontal, 22).padding(.top, 18).padding(.bottom, 2)
            // No GlassGroup: the container draws the tiles' glass above their state badges.
            LazyVGrid(columns: [GridItem(.adaptive(minimum: ProtocolTileButton.minimumWidth), spacing: ProtocolTileButton.spacing)],
                      spacing: ProtocolTileButton.spacing) {
                ForEach(catalog.entries) { tile($0) }
            }
            .padding(.horizontal, 16).padding(.vertical, 8)
            .onMoveCommand(perform: move)
            Group {
                if let entry = selection.shown(in: catalog.entries) {
                    ProtocolQuickView(entry: entry, state: state(entry.kind, locale), openService: openService)
                }
            }
            .padding(.horizontal, 16)
            .frame(height: Self.quickViewHeight, alignment: .top)
            Spacer(minLength: 0)
            SheetFooter {
                Spacer()
                Button(LocalizedStringResource("Cancelar").string(in: locale)) { cancel() }
                    .keyboardShortcut(.cancelAction).disabled(cancelDisabled)
            }
        }
        .background { keyButtons }
        // Nothing preselected, not even by the window's automatic first responder.
        .onAppear { DispatchQueue.main.async { focused = nil } }
        .onChange(of: focused) { id in if let id { current = id } }
    }

    private func tile(_ entry: ProtocolCatalog.Entry) -> some View {
        ProtocolTileButton(entry: entry, state: state(entry.kind, locale), hovering: hovered == entry.id) { choose(entry.kind) }
            .onHover { inside in
                if inside { hovered = entry.id; selection.hovered(entry.id) } else if hovered == entry.id { hovered = nil }
            }
            .focusable(entry.id == (current ?? catalog.entries.first?.id))
            .focused($focused, equals: entry.id)
    }

    private func move(_ direction: MoveCommandDirection) {
        let entries = catalog.entries
        guard let index = entries.firstIndex(where: { $0.id == (focused ?? current) }) else { return }
        let next = entries[ProtocolCatalog.move(from: index, direction, count: entries.count,
                                                columns: ProtocolCatalog.columns(width: Self.gridWidth))].id
        guard next != entries[index].id else { return }
        // The tile becomes focusable first, then takes the focus.
        current = next
        DispatchQueue.main.async { focused = next }
    }

    /// Enter and Space choose the focused tile; with the focus elsewhere they do nothing here.
    private var keyButtons: some View {
        ZStack {
            Button(action: chooseFocused) { EmptyView() }.keyboardShortcut(.defaultAction)
            Button(action: chooseFocused) { EmptyView() }.keyboardShortcut(.space, modifiers: [])
        }
        .disabled(focused == nil)
        .opacity(0)
        .frame(width: 0, height: 0)
        .accessibilityHidden(true)
    }

    private func chooseFocused() {
        guard let entry = catalog.entries.first(where: { $0.id == focused }) else { return }
        choose(entry.kind)
    }
}

/// One VPN type in the Nova conexão grid: mark, short name, one-line subtitle and a badge
/// with the client state (the quick view and VoiceOver say it in words).
struct ProtocolTileButton: View {
    static let minimumWidth: CGFloat = 96
    static let spacing: CGFloat = 12
    static let height: CGFloat = 100
    private static let iconTop: CGFloat = 12
    let entry: ProtocolCatalog.Entry
    let state: ProtocolClientState
    var hovering = false
    let action: () -> Void
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.locale) private var locale

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: 18, style: .continuous)
        VStack(spacing: 6) {
            ProtocolTile(kind: entry.kind, state: .disconnected, size: 44)
            VStack(spacing: 1) {
                Text(entry.shortName).font(.callout.weight(.semibold))
                Text(entry.tileSubtitle.string(in: locale)).font(.caption).foregroundStyle(.secondary)
            }
            .lineLimit(1)
            .minimumScaleFactor(0.85)
        }
        .padding(.horizontal, 6)
        .padding(.top, Self.iconTop)
        .frame(maxWidth: .infinity, minHeight: Self.height, maxHeight: Self.height, alignment: .top)
        .tileSurface(cornerRadius: 18)
        .overlay(shape.strokeBorder(entry.kind.brandColor.opacity(0.8), lineWidth: 1.5).opacity(hovering ? 1 : 0))
        // On the icon's corner, outside the glass (which would tint it).
        .overlay(alignment: .top) { badge.offset(x: 22, y: Self.iconTop - 6) }
        .contentShape(shape)
        .focusRingShape(shape)
        .scaleEffect(hovering && !reduceMotion ? 1.03 : 1)
        .animation(Motion.state(reduceMotion), value: hovering)
        .onTapGesture(perform: action)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(spoken.label)
        .accessibilityValue(spoken.value)
        .accessibilityHint(spoken.hint)
        .accessibilityAddTraits(.isButton)
        .accessibilityAction(.default, action)
    }

    /// What VoiceOver reads for the tile: name, client state and what the form asks for.
    struct Spoken: Equatable { var label, value, hint: String }
    static func spoken(_ entry: ProtocolCatalog.Entry, _ state: ProtocolClientState, locale: Locale) -> Spoken {
        Spoken(label: entry.title, value: state.text, hint: entry.hint.string(in: locale))
    }
    private var spoken: Spoken { Self.spoken(entry, state, locale: locale) }

    @ViewBuilder private var badge: some View {
        switch state.kind {
        case .ready:
            Image(systemName: "checkmark.circle.fill").symbolRenderingMode(.palette).foregroundStyle(.white, .green)
                .font(.system(size: 14, weight: .semibold)).background(Circle().fill(.background).padding(1))
        case .problem:
            Image(systemName: "exclamationmark.triangle.fill").symbolRenderingMode(.palette).foregroundStyle(.white, .orange)
                .font(.system(size: 13, weight: .semibold))
        case .checking:
            EmptyView()
        }
    }
}

/// Panel under the grid describing one type: what it is, its client, how it signs in
/// and what the form asks for. Hidden from VoiceOver, which hears the same on the tile.
struct ProtocolQuickView: View {
    let entry: ProtocolCatalog.Entry
    let state: ProtocolClientState
    var openService: (() -> Void)?
    @Environment(\.locale) private var locale

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            VStack(alignment: .leading, spacing: 1) {
                HStack(alignment: .firstTextBaseline) {
                    Text(entry.title).font(.headline).accessibilityHidden(true)
                    Spacer(minLength: 8)
                    if state.kind == .problem, let openService {
                        Button(LocalizedStringResource("Abrir Serviço privilegiado…").string(in: locale), action: openService)
                            .adaptiveButtonStyle()
                            .controlSize(.small)
                    }
                }
                Text(entry.about.string(in: locale)).font(.callout).foregroundStyle(.secondary)
                    .lineLimit(2).fixedSize(horizontal: false, vertical: true)
                    .accessibilityHidden(true)
            }
            VStack(alignment: .leading, spacing: 6) {
                Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 3) {
                    GridRow {
                        label("Cliente")
                        client.frame(maxWidth: .infinity, alignment: .leading)
                    }
                    GridRow {
                        label("Autenticação")
                        Text(entry.authentication.string(in: locale)).lineLimit(2).fixedSize(horizontal: false, vertical: true)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    GridRow {
                        label("O cadastro pede")
                        Text(entry.requires.string(in: locale)).lineLimit(2).fixedSize(horizontal: false, vertical: true)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                .font(.callout)
            }
            .accessibilityHidden(true)
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .padding(.horizontal, 14).padding(.vertical, 10)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Color.primary.opacity(0.045)))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Color(nsColor: .separatorColor), lineWidth: 0.5))
    }

    private func label(_ text: LocalizedStringResource) -> some View {
        Text(text.string(in: locale)).foregroundStyle(.secondary).gridColumnAlignment(.trailing)
    }

    @ViewBuilder private var client: some View {
        switch state.kind {
        case .ready:
            Label { Text(state.text) } icon: { Image(systemName: "checkmark.circle.fill").foregroundStyle(.green) }
        case .checking:
            Label { Text(state.text) } icon: { Image(systemName: "clock").foregroundStyle(.secondary) }
        case .problem:
            Label {
                (Text(entry.kind.runtime.title).fontWeight(.medium) + Text(verbatim: " · ") + Text(state.text))
                    .lineLimit(2).fixedSize(horizontal: false, vertical: true)
            } icon: { Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange) }
        }
    }
}
