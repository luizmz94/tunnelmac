import SwiftUI
import AppKit
import VPNHelperShared

/// First run: while the privileged service is not registered or still waits for the
/// user's approval in System Settings, the main window opens a short setup guide:
/// choose and install the VPN clients, activate, allow in System Settings, approve the
/// chosen clients, done.
enum ServiceOnboarding {
    /// "Agora não" holds until the app quits; the next launch asks again.
    @MainActor static var postponed = false

    static func needed(_ health: ServiceController.Health) -> Bool {
        health == .notRegistered || health == .requiresApproval
    }

    enum Step: Int, CaseIterable {
        case clients = 1, activate, allow, approve, done

        var title: String {
            switch self {
            case .clients: return "Escolher as VPNs"
            case .activate: return "Ativar o serviço"
            case .allow: return "Permitir em segundo plano"
            case .approve: return "Aprovar os clientes"
            case .done: return "Pronto"
            }
        }
        var subtitle: String {
            switch self {
            case .clients: return "E instalar pelo Homebrew"
            case .activate: return "O ajudante do sistema"
            case .allow: return "Nos Ajustes do Sistema"
            case .approve: return "Com a senha de administrador"
            case .done: return "Conectar sem senha"
            }
        }
    }

    /// The service step a state belongs to; nil while checking or for states the guide
    /// does not handle (those continue in Serviço privilegiado).
    static func step(_ health: ServiceController.Health) -> Step? {
        switch health {
        case .notRegistered, .notFound: return .activate
        case .requiresApproval: return .allow
        case .runtimeMissing, .userNotAuthorized, .ready: return .approve
        default: return nil
        }
    }

    /// Homebrew commands that install or update the chosen clients, one line per verb.
    static func commands(_ kinds: [RuntimeKind], states: (RuntimeKind) -> ClientState) -> [String] {
        var install: [String] = [], upgrade: [String] = []
        for kind in RuntimeKind.allCases where kinds.contains(kind) {
            switch states(kind) {
            case .notInstalled: install.append(kind.executableName)
            case .notApproved(_, let latest) where latest != nil: upgrade.append(kind.executableName)
            case .updateAvailable: upgrade.append(kind.executableName)
            default: break
            }
        }
        return [install.isEmpty ? nil : "brew install " + install.joined(separator: " "),
                upgrade.isEmpty ? nil : "brew upgrade " + upgrade.joined(separator: " ")].compactMap { $0 }
    }

    /// Installed and current enough to approve.
    static func installed(_ state: ClientState) -> Bool {
        switch state {
        case .notInstalled, .updateAvailable: return false
        case .notApproved(_, let latest): return latest == nil
        default: return true
        }
    }
}

struct ServiceOnboardingSheet: View {
    @ObservedObject var model: AppModel
    @ObservedObject private var service: ServiceController
    @StateObject private var versions: ClientVersionChecker
    private let forced: ServiceOnboarding.Step?
    /// true from Começar; false when postponed.
    let finish: (_ completed: Bool) -> Void
    @State private var shown: ServiceOnboarding.Step = .clients
    @State private var chosen: Set<RuntimeKind>
    @State private var copied = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    /// forcedStep, versions and chosen are for the UI previews.
    init(model: AppModel, versions: ClientVersionChecker? = nil, forcedStep: ServiceOnboarding.Step? = nil,
         chosen: Set<RuntimeKind>? = nil, finish: @escaping (_ completed: Bool) -> Void) {
        _model = ObservedObject(wrappedValue: model)
        _service = ObservedObject(wrappedValue: model.service)
        _versions = StateObject(wrappedValue: versions ?? model.clientVersions)
        // Clients with saved connections start checked; installed ones join on the first check.
        _chosen = State(initialValue: chosen ?? Set(model.data.connections.map(\.kind.runtime)))
        self.forced = forcedStep
        self.finish = finish
    }

    private var step: ServiceOnboarding.Step { forced ?? shown }
    private var kinds: [RuntimeKind] { RuntimeKind.allCases.filter(chosen.contains) }
    private func state(_ kind: RuntimeKind) -> ClientState { versions.state(kind, status: service.status) }

    var body: some View {
        HStack(spacing: 0) {
            rail
            Divider()
            VStack(spacing: 0) {
                ScrollView {
                    content
                        .id(step)
                        .transition(reduceMotion ? .opacity : .asymmetric(insertion: .move(edge: .trailing).combined(with: .opacity),
                                                                          removal: .opacity))
                        .padding(.horizontal, 32).padding(.top, 30).padding(.bottom, 20)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                SheetFooter { footer }
            }
        }
        .frame(width: 760, height: 540)
        .onAppear {
            versions.refresh(status: service.status)
            follow(service.health)
        }
        .onChange(of: service.health) { follow($0) }
        .onChange(of: service.status) { versions.refresh(status: $0) }
        .onChange(of: versions.local) { local in
            // First check: what is already installed starts checked too.
            if chosen.isEmpty, forced == nil { chosen = Set(local.filter(\.value.exists).map(\.key)) }
        }
        // Homebrew runs in the Terminal and the switch is flipped in System Settings while
        // this app is in the background. A task, unlike a Timer publisher stored in the
        // view, is not restarted each time the parent rebuilds the sheet.
        .task {
            guard forced == nil else { return }
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                if step == .clients { versions.refresh(status: service.status) }
                if step == .activate || step == .allow, !service.busy { service.refresh() }
            }
        }
    }

    /// Follows the service while the guide is on a service step; the client steps move
    /// only with the user's Continuar.
    private func follow(_ health: ServiceController.Health) {
        guard step == .activate || step == .allow, let next = ServiceOnboarding.step(health), next != shown else { return }
        go(next)
    }

    private func go(_ next: ServiceOnboarding.Step) {
        withAnimation(reduceMotion ? nil : .easeInOut(duration: 0.3)) { shown = next }
    }

    // MARK: Steps rail

    private var rail: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                Image(nsImage: NSApp.applicationIconImage).resizable().frame(width: 40, height: 40).accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 1) {
                    Text("TunnelMac").font(.headline)
                    Text("Configuração inicial").font(.caption).foregroundStyle(.secondary)
                }
            }
            .accessibilityElement(children: .combine)
            .padding(.bottom, 28)
            ForEach(ServiceOnboarding.Step.allCases, id: \.self) { item in
                railRow(item, last: item == .done)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 20).padding(.top, 26)
        .frame(width: 244, alignment: .leading)
        .frame(maxHeight: .infinity, alignment: .top)
        .background(Color.primary.opacity(0.035))
    }

    private func railRow(_ item: ServiceOnboarding.Step, last: Bool) -> some View {
        let done = step.rawValue > item.rawValue || step == .done
        let current = step == item && step != .done
        return HStack(alignment: .top, spacing: 12) {
            VStack(spacing: 0) {
                ZStack {
                    Circle().fill(done ? Color.green : current ? Color.accentColor : Color.clear)
                    if !done && !current { Circle().strokeBorder(Color.secondary.opacity(0.4), lineWidth: 1.5) }
                    if done {
                        Image(systemName: "checkmark").font(.system(size: 11, weight: .bold)).foregroundStyle(.white)
                    } else {
                        Text("\(item.rawValue)").font(.caption.weight(.semibold)).foregroundStyle(current ? .white : .secondary)
                    }
                }
                .frame(width: 24, height: 24)
                if !last {
                    Rectangle().fill(done ? Color.green.opacity(0.6) : Color.secondary.opacity(0.25))
                        .frame(width: 2, height: 26)
                }
            }
            .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text(item.title).font(.callout.weight(current ? .semibold : .regular))
                    .foregroundStyle(done || current ? .primary : .secondary)
                Text(item.subtitle).font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(.top, 3)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Passo \(item.rawValue), \(item.title)\(done ? ", concluído" : current ? ", atual" : "")")
    }

    // MARK: Content

    @ViewBuilder private var content: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 6) {
                if step != .done {
                    Text("PASSO \(step.rawValue) DE \(ServiceOnboarding.Step.allCases.count - 1)")
                        .font(.caption.weight(.semibold)).foregroundStyle(Color.accentColor)
                }
                Text(heading).font(.title2.weight(.bold)).fixedSize(horizontal: false, vertical: true)
                Text(lead).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            .accessibilityElement(children: .combine)
            .accessibilityAddTraits(.isHeader)
            switch step {
            case .clients: clientsBody
            case .activate: activateBody
            case .allow: allowBody
            case .approve: ServicePanel(model: model, versions: versions, clientsOnly: true, kinds: kinds)
            case .done: doneBody
            }
            if step == .activate, let message = service.message {
                InlineNotice(tone: .warning, symbol: "exclamationmark.triangle", title: message)
            }
        }
    }

    private var heading: String {
        switch step {
        case .clients: return "Quais VPNs você vai usar?"
        case .activate: return "Conectar sem digitar a senha toda vez"
        case .allow: return "Permita o TunnelMac em segundo plano"
        case .approve: return kinds.count > 1 ? "Aprove os clientes escolhidos" : "Aprove o cliente escolhido"
        case .done: return "Tudo pronto"
        }
    }

    private var lead: String {
        switch step {
        case .clients:
            return "O TunnelMac conecta usando os clientes abertos de cada tipo de VPN, instalados pelo Homebrew. Marque os que você precisa; dá para mudar depois."
        case .activate:
            return "Para criar a VPN e ajustar rotas e DNS, o TunnelMac usa um pequeno serviço do sistema. Você o ativa uma vez só."
        case .allow:
            return "O macOS pede que você ligue o TunnelMac em Permitir em segundo plano. Clique em Abrir Ajustes do Sistema, ligue a chave como abaixo e volte: esta janela continua sozinha."
        case .approve:
            return "O serviço só executa cópias dos clientes que você aprovou. O macOS pede a senha de administrador uma vez para cada um."
        case .done:
            return "O serviço está ativo e conectar não pede mais senha de administrador. Adicione sua primeira conexão ou importe um perfil."
        }
    }

    // MARK: Clients

    private var homebrewInstalled: Bool {
        FileManager.default.isExecutableFile(atPath: BinaryLocator.homebrewPrefix + "/bin/brew")
    }

    private var clientsBody: some View {
        let commands = ServiceOnboarding.commands(kinds, states: state)
        return VStack(alignment: .leading, spacing: 14) {
            VStack(spacing: 0) {
                ForEach(Array(RuntimeKind.allCases.enumerated()), id: \.element) { index, kind in
                    if index > 0 { Divider().padding(.leading, 52) }
                    choiceRow(kind)
                }
            }
            .contentPanel()
            if !homebrewInstalled {
                InlineNotice(tone: .warning, symbol: "shippingbox", title: "O Homebrew não está instalado",
                             message: "Instale-o pelas instruções de brew.sh e volte aqui.") {
                    Button("Abrir brew.sh") { if let url = URL(string: "https://brew.sh") { NSWorkspace.shared.open(url) } }
                        .adaptiveButtonStyle()
                }
            }
            if !commands.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Text("No Terminal, rode:").font(.callout.weight(.medium))
                    HStack(alignment: .center, spacing: 10) {
                        Text(commands.joined(separator: "\n"))
                            .font(.system(.callout, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        Button(copied ? "Copiado" : "Copiar") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(commands.joined(separator: "\n"), forType: .string)
                            copied = true
                        }
                        .fixedSize()
                        .adaptiveButtonStyle()
                    }
                    .padding(12)
                    .contentPanel()
                    Text("Esta tela percebe a instalação sozinha; se não, use Verificar.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                .onChange(of: commands) { _ in copied = false }
            }
        }
    }

    private func choiceRow(_ kind: RuntimeKind) -> some View {
        let selected = chosen.contains(kind)
        let protocolKind = VPNProtocol.allCases.first { $0.runtime == kind } ?? .fortinet
        return Button {
            if selected { chosen.remove(kind) } else { chosen.insert(kind) }
        } label: {
            HStack(spacing: 12) {
                Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                    .font(.system(size: 18))
                    .foregroundStyle(selected ? Color.accentColor : Color.secondary)
                ProtocolIcon(kind: protocolKind, size: 22)
                VStack(alignment: .leading, spacing: 1) {
                    Text(protocolKind.title).font(.body.weight(.medium))
                    Text(kind.executableName).font(.caption).foregroundStyle(.secondary)
                }
                Spacer(minLength: 8)
                installBadge(kind)
            }
            .padding(.horizontal, 12).padding(.vertical, 10)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }

    private func installBadge(_ kind: RuntimeKind) -> some View {
        let text: String, tone: StatusTone
        switch state(kind) {
        case .notInstalled: (text, tone) = ("Não instalado", .neutral)
        case .notApproved(let installed, let latest?): (text, tone) = ("\(installed ?? "Instalado") → \(latest) disponível", .warning)
        case .updateAvailable(let current, let latest): (text, tone) = ("\(current) → \(latest) disponível", .warning)
        case .notApproved(let installed, nil), .approvalOutdated(_, let installed):
            (text, tone) = ("Instalado\(installed.map { " · \($0)" } ?? "")", .success)
        case .upToDate(let version): (text, tone) = ("Aprovado · \(version)", .success)
        }
        let color = tone == .neutral ? Color.secondary : tone.color
        return Text(text)
            .font(.caption.weight(.medium))
            .foregroundStyle(color)
            .padding(.horizontal, 8).padding(.vertical, 3)
            .background(Capsule().fill(color.opacity(0.12)))
    }

    // MARK: Service

    private var activateBody: some View {
        VStack(alignment: .leading, spacing: 14) {
            feature("key.fill", .blue, "Sem senha de administrador a cada conexão",
                    "O macOS pede uma aprovação agora e pronto.")
            feature("checkmark.shield.fill", .green, "Só obedece a este app",
                    "Aceita pedidos apenas do TunnelMac assinado e executa só os clientes aprovados.")
            feature("lock.fill", .orange, "Senhas ficam no Keychain",
                    "O serviço não guarda senhas. Você pode removê-lo a qualquer momento em Ajustes.")
        }
        .padding(.top, 4)
    }

    private func feature(_ symbol: String, _ color: Color, _ title: String, _ detail: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            SettingsIcon(symbol: symbol, color: color, size: 30)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.body.weight(.medium))
                Text(detail).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
        .accessibilityElement(children: .combine)
    }

    private var allowBody: some View {
        VStack(alignment: .leading, spacing: 12) {
            LoginItemsMock(animated: forced == nil && !reduceMotion)
            Text("Ajustes do Sistema › Geral › Itens de Início › Permitir em segundo plano")
                .font(.caption).foregroundStyle(.secondary)
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text("Aguardando a permissão do macOS…").font(.callout).foregroundStyle(.secondary)
            }
            .accessibilityElement(children: .combine)
        }
    }

    private var doneBody: some View {
        HStack(spacing: 14) {
            StatusBadge(symbol: "checkmark.seal.fill", tone: .success, diameter: 56)
            VStack(alignment: .leading, spacing: 4) {
                Text("Serviço privilegiado ativo").font(.body.weight(.medium))
                Text("Estado, clientes aprovados e remoção ficam em Ajustes › Serviço privilegiado.")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
        .accessibilityElement(children: .combine)
        .padding(.top, 6)
    }

    // MARK: Footer

    private var clientsReady: Bool { !kinds.isEmpty && kinds.allSatisfy { ServiceOnboarding.installed(state($0)) } }
    private var allApproved: Bool {
        service.health == .ready && !kinds.isEmpty && kinds.allSatisfy { !state($0).needsAction }
    }

    @ViewBuilder private var footer: some View {
        if step != .done {
            Button(step == .approve ? "Fazer depois" : "Agora não") { finish(false) }
                .keyboardShortcut(.cancelAction)
                .adaptiveButtonStyle()
        }
        Spacer()
        if (service.busy && service.approvingKind == nil) || (step == .clients && versions.checking) {
            ProgressView().controlSize(.small).accessibilityLabel("Em andamento")
        }
        switch step {
        case .clients:
            Button("Verificar") { versions.refresh(status: service.status, force: true) }
                .adaptiveButtonStyle()
            Button("Continuar") { go(ServiceOnboarding.step(service.health) ?? .activate) }
                .keyboardShortcut(.defaultAction).adaptiveButtonStyle(prominent: true)
                .disabled(!clientsReady)
                .help(kinds.isEmpty ? "Marque pelo menos um tipo de VPN" : clientsReady ? "" : "Instale ou atualize os clientes marcados")
        case .activate:
            Button("Ativar serviço") { service.activate(openingSettings: false) }
                .keyboardShortcut(.defaultAction).adaptiveButtonStyle(prominent: true).disabled(service.busy)
        case .allow:
            Button("Abrir Ajustes do Sistema") { service.openSettings() }
                .keyboardShortcut(.defaultAction).adaptiveButtonStyle(prominent: true)
        case .approve:
            Button("Continuar") { go(.done) }
                .keyboardShortcut(.defaultAction).adaptiveButtonStyle(prominent: true)
                .disabled(!allApproved)
        case .done:
            Button("Começar") { finish(true) }
                .keyboardShortcut(.defaultAction).adaptiveButtonStyle(prominent: true)
        }
    }
}

/// A small picture of the System Settings row to turn on, with the switch flipping on.
private struct LoginItemsMock: View {
    let animated: Bool
    @Environment(\.colorSchemeContrast) private var contrast

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: 12, style: .continuous)
        VStack(alignment: .leading, spacing: 8) {
            Text("Permitir em segundo plano").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                .padding(.leading, 4)
            TimelineView(.periodic(from: .now, by: 1.6)) { context in
                let on = !animated || Int(context.date.timeIntervalSinceReferenceDate / 1.6) % 2 == 1
                HStack(spacing: 10) {
                    Image(nsImage: NSApp.applicationIconImage).resizable().frame(width: 28, height: 28)
                    VStack(alignment: .leading, spacing: 1) {
                        Text("TunnelMac").font(.callout.weight(.medium))
                        Text("1 item").font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    MockSwitch(on: on)
                        .animation(.easeInOut(duration: 0.25), value: on)
                        .padding(3)
                        .overlay(Capsule().strokeBorder(Color.accentColor.opacity(on ? 0 : 0.6), lineWidth: 2))
                        .animation(.easeInOut(duration: 0.25), value: on)
                }
                .padding(.horizontal, 12).padding(.vertical, 10)
                .background(shape.fill(Color(nsColor: .textBackgroundColor)))
                .overlay(shape.strokeBorder(Color(nsColor: .separatorColor), lineWidth: contrast == .increased ? 1 : 0.5))
            }
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(Color.primary.opacity(0.04)))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Ligue o TunnelMac em Permitir em segundo plano")
    }
}

private struct MockSwitch: View {
    let on: Bool
    var body: some View {
        ZStack(alignment: on ? .trailing : .leading) {
            Capsule().fill(on ? Color.accentColor : Color.secondary.opacity(0.3))
            Circle().fill(.white).shadow(color: .black.opacity(0.2), radius: 1, y: 0.5).padding(2)
        }
        .frame(width: 38, height: 22)
    }
}
