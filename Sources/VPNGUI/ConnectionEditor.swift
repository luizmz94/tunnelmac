import SwiftUI
import AppKit
import UniformTypeIdentifiers
import VPNHelperShared

/// Open panel for OpenVPN profiles: a .ovpn/.conf file, a Viscosity .visc folder or its .zip.
enum OpenVPNImportPanel {
    @MainActor static func choose() -> [URL]? {
        let panel = NSOpenPanel()
        panel.title = "Importar perfil OpenVPN"
        panel.message = "Escolha o .ovpn, a pasta .visc (ou o .zip) ou o .ovpn com os certificados (⌘-clique)."
        panel.prompt = "Importar"
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
        panel.title = "Importar perfil WireGuard"
        panel.message = "Escolha o arquivo .conf do WireGuard."
        panel.prompt = "Importar"
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
    var names: [String] { folder.map { [$0.lastPathComponent + " (pasta inteira)"] } ?? files.map(\.lastPathComponent) }
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
    @State private var password = ""
    /// Typed in this sheet (as opposed to read from the Keychain); never cleared behind the user's back.
    @State private var passwordTyped = false
    @State private var revealPassword = false
    /// Fortinet gateway as typed: host, host:port or host:port/realm.
    @State private var gatewayText = ""
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
         saved: @escaping () -> Void) {
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
        VStack(spacing: 0) {
            SheetHeader(symbol: "plus.circle", tone: .neutral, title: "Nova conexão", subtitle: "Escolha o tipo de VPN", brand: true)
                .padding(.horizontal, 22).padding(.top, 20).padding(.bottom, 4)
            VStack(spacing: 12) {
                ProtocolCard(kind: .fortinet, title: "Fortinet SSL VPN",
                             subtitle: "Gateway FortiGate, o mesmo usado pelo FortiClient.",
                             status: clientStatus(.fortinet)) { choose(.fortinet) }
                ProtocolCard(kind: .openvpn, title: "OpenVPN",
                             subtitle: "Perfil .ovpn ou pasta .visc do Viscosity (também em .zip).",
                             status: clientStatus(.openvpn)) { choose(.openvpn) }
                ProtocolCard(kind: .wireguard, title: "WireGuard",
                             subtitle: "Arquivo .conf do servidor ou do app WireGuard.",
                             status: clientStatus(.wireguard)) { choose(.wireguard) }
            }
            .padding(.horizontal, 22).padding(.vertical, 16)
            Spacer(minLength: 0)
            SheetFooter {
                Spacer()
                Button("Cancelar") { dismiss() }.keyboardShortcut(.cancelAction).disabled(model.writing)
            }
        }
        .sheetFrame(width: 560, height: 520)
    }

    private func clientStatus(_ kind: VPNProtocol) -> String {
        guard let status = model.service.status else { return "Usa o \(kind.runtime.title)" }
        if let runtime = status.runtime(kind.runtime) { return "\(kind.runtime.title) \(runtime.version) aprovado" }
        return "\(kind.runtime.title) ainda não aprovado no serviço"
    }

    private func choose(_ kind: VPNProtocol) {
        connection.kind = kind
        error = nil
        if kind == .fortinet { step = .form; loaded = true; focus = .name } else { step = .chooseFiles }
    }

    // MARK: Step 2 — profile files

    private var fileChooser: some View {
        let kind = connection.kind
        let wireGuard = kind == .wireguard
        return VStack(spacing: 0) {
            SheetHeader(symbol: "doc.badge.gearshape", tone: .neutral, title: "Importar perfil \(kind.title)", kind: kind)
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
            ? "O app já guardou o perfil. O original não é mais necessário e ainda contém a chave privada:\n\n"
            : "O app já guardou o perfil e as chaves. Os originais não são mais necessários:\n\n"
        return intro + cleanup.names.joined(separator: "\n") + "\n\nEles vão para a Lixeira; esvazie-a para apagá-los de vez."
    }

    private func finishCleanup(trash: Bool) {
        guard let pending = cleanup else { return }
        cleanup = nil
        if trash {
            let failed = pending.trash()
            if !failed.isEmpty { model.error = "Não foi possível mover para a Lixeira: \(failed.joined(separator: ", ")). A conexão foi salva normalmente." }
        }
        saved(); dismiss()
    }

    private var formContent: some View {
        VStack(spacing: 0) {
            SheetHeader(symbol: connection.usesProfile ? "doc.badge.gearshape" : "network.badge.shield.half.filled", tone: .neutral,
                        title: isNew ? (connection.usesProfile ? "Importar perfil \(connection.kind.title)" : "Nova conexão") : "Editar conexão",
                        subtitle: isNew ? (connection.usesProfile ? nil : connection.kind.title) : "\(connection.name) · \(connection.kind.title)",
                        kind: connection.kind)
                .padding(.horizontal, 22).padding(.top, 20).padding(.bottom, 4)
            Form {
                switch connection.kind {
                case .fortinet: fortinetSections
                case .openvpn: openVPNSections
                case .wireguard: wireGuardSections
                }
            }
            .formStyle(.grouped)
            .animation(Motion.state(reduceMotion), value: connection.authentication)
            if let error {
                InlineNotice(tone: .danger, symbol: "exclamationmark.triangle.fill", title: error)
                    .padding(.horizontal, 20).padding(.bottom, 12)
                    .transition(.opacity)
            }
            SheetFooter {
                Spacer()
                Button("Cancelar") { dismiss() }.keyboardShortcut(.cancelAction).disabled(model.writing)
                Button(isNew ? "Adicionar" : "Salvar") { save() }
                    .keyboardShortcut(.defaultAction)
                    .adaptiveButtonStyle(prominent: true)
                    .disabled(!loaded || model.writing || !model.ready)
            }
        }
        .sheetFrame(width: 560, height: connection.usesProfile ? 640 : 600)
        .animation(Motion.state(reduceMotion), value: error)
        .onAppear {
            gatewayText = GatewayAddress.display(host: connection.server, port: connection.port, realm: connection.realm)
            if model.manager.session(connection.id).authenticationRejected {
                password = ""
                error = "A última autenticação foi recusada. Confira o usuário e digite a senha novamente para evitar um bloqueio."
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
                        guard let profiles else { throw AppFailure("Perfis indisponíveis.") }
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
        if identity.expired { label += " (expirado)" }
        return label
    }

    /// Imports a .p12/.pfx into the login keychain and selects it. The file password is used
    /// only for the import and never saved.
    private func importCertificate() {
        let panel = NSOpenPanel()
        panel.title = "Importar certificado do cliente"
        panel.message = "Escolha o arquivo .p12 ou .pfx."
        panel.prompt = "Continuar"
        panel.allowedContentTypes = [.pkcs12]
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let alert = NSAlert()
        alert.messageText = "Senha do certificado"
        alert.informativeText = "Digite a senha de \(url.lastPathComponent)."
        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 24))
        alert.accessoryView = field
        alert.addButton(withTitle: "Importar")
        alert.addButton(withTitle: "Cancelar")
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
                        ForEach(summary.endpoints.isEmpty ? ["Sem endpoint"] : summary.endpoints, id: \.self) { endpoint in
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
                connection.server = gateway.host
                connection.port = gateway.port
                connection.realm = gateway.realm
                try await model.saveAsync(connection, password: password)
            }
            saved(); dismiss()
        } catch { self.error = error.localizedDescription }
    }
}

/// One VPN type in the Nova conexão chooser.
struct ProtocolCard: View {
    let kind: VPNProtocol
    let title: String
    let subtitle: String
    let status: String
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 16) {
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(kind.brandColor.opacity(0.12))
                    .frame(width: 56, height: 56)
                    .overlay(ProtocolIcon(kind: kind, size: 30))
                VStack(alignment: .leading, spacing: 4) {
                    Text(title).font(.title3.weight(.semibold))
                    Text(subtitle).font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Text(status).font(.caption).foregroundStyle(.tertiary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                Image(systemName: "chevron.right").font(.body.weight(.semibold)).foregroundStyle(.tertiary)
            }
            .padding(16)
            .contentShape(Rectangle())
            .background(RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(Color.primary.opacity(hovering ? 0.07 : 0.035)))
            .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(hovering ? kind.brandColor.opacity(0.7) : Color(nsColor: .separatorColor), lineWidth: hovering ? 1.5 : 0.5))
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .accessibilityLabel("\(title). \(subtitle)")
    }
}
