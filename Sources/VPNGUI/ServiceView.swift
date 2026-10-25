import SwiftUI
import AppKit
import VPNHelperShared

/// Compact service state at the bottom of the native material sidebar. The row
/// uses a quiet fill instead of a second material layer.
struct ServiceStatusRow: View {
    @ObservedObject var service: ServiceController
    let manage: () -> Void
    var body: some View {
        HStack(spacing: 9) {
            StatusSymbol(symbol: service.health.symbol, tone: service.health.tone,
                         pulsing: service.health == .checking || service.busy, size: 13)
            VStack(alignment: .leading, spacing: 1) {
                Text("Serviço privilegiado").font(.caption2).foregroundStyle(.secondary)
                Text(service.health.title).font(.caption.weight(.medium)).lineLimit(1).truncationMode(.tail)
            }
            .accessibilityElement(children: .combine)
            Spacer(minLength: 4)
            Button("Gerenciar…", action: manage)
                .controlSize(.small)
                .adaptiveButtonStyle()
                .help("Estado, aprovação e remoção do serviço privilegiado")
        }
        .padding(.leading, 10).padding(.trailing, 6).padding(.vertical, 7)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Color.primary.opacity(0.05)))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Color(nsColor: .separatorColor), lineWidth: 0.5))
    }
}

/// Service management (the Serviço privilegiado tab): status, the VPN clients in plain
/// language (approve, approve again, update) and the service actions. Logic stays in
/// ServiceController and ClientVersionChecker; runtime consent presents the source and inspection warnings.
struct ServicePanel: View {
    @ObservedObject var model: AppModel
    @ObservedObject private var service: ServiceController
    @StateObject private var versions: ClientVersionChecker
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var confirmingRemoval = false
    @State private var copied: RuntimeKind?
    /// Only the VPN clients, optionally a subset (first-run guide); the guide carries the service state.
    private let clientsOnly: Bool
    private let kinds: [RuntimeKind]
    init(model: AppModel, versions: ClientVersionChecker? = nil, clientsOnly: Bool = false, kinds: [RuntimeKind] = RuntimeKind.allCases) {
        self.clientsOnly = clientsOnly
        self.kinds = kinds
        _model = ObservedObject(wrappedValue: model)
        _service = ObservedObject(wrappedValue: model.service)
        _versions = StateObject(wrappedValue: versions ?? model.clientVersions)
    }

    private var showsClients: Bool {
        switch service.health {
        case .runtimeMissing, .userNotAuthorized, .ready: return true
        default: return false
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            if !clientsOnly {
                SheetHeader(symbol: service.health.symbol, tone: service.health.tone,
                            title: service.health.title, subtitle: "TunnelMac \(HelperConstants.releaseVersion) · build \(HelperConstants.build)")
                Text(showsClients ? clientsDetail : service.health.detail)
                    .fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
                if let warning = service.bundleLocationWarning {
                    InlineNotice(tone: .warning, symbol: "folder.badge.questionmark", title: warning)
                }
            }
            if let message = service.message {
                InlineNotice(tone: .neutral, symbol: "info.circle", title: message)
            }
            if showsClients || clientsOnly { clients }
            if !clientsOnly {
                ViewThatFits(in: .horizontal) {
                    HStack(spacing: 8) { serviceActions; Spacer(minLength: 0) }
                    VStack(alignment: .leading, spacing: 8) { serviceActions }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .onAppear { versions.refresh(status: service.status) }
        .onChange(of: service.status) { status in versions.refresh(status: status) }
        .confirmationDialog("Remover o serviço privilegiado?", isPresented: $confirmingRemoval) {
            Button("Remover serviço", role: .destructive) { service.remove(includeManagedFiles: false) }
            Button("Remover serviço e arquivos gerenciados", role: .destructive) { service.remove(includeManagedFiles: true) }
            Button("Cancelar", role: .cancel) {}
        } message: {
            Text("As conexões ativas serão desconectadas e o app aguardará a limpeza antes de remover o registro. Cadastros e senhas são preservados. Remover os arquivos gerenciados (\(HelperConstants.stateDirectory)) exige administrador.")
        }
    }

    private var clientsDetail: String {
        if service.health == .userNotAuthorized {
            return "Um administrador precisa aprovar um cliente VPN neste usuário do macOS antes da primeira conexão."
        }
        return service.health == .ready
            ? "Conectar não pede senha de administrador enquanto o serviço estiver habilitado e íntegro."
            : "Aprove o cliente VPN que você usa. É preciso fazer isso uma vez e depois de cada atualização dele."
    }

    // MARK: Clients

    private var clients: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                Text("Clientes VPN").font(.headline).accessibilityAddTraits(.isHeader)
                Spacer()
                if versions.checking { ProgressView().controlSize(.small).accessibilityLabel("Consultando versões") }
            }
            VStack(spacing: 0) {
                ForEach(Array(kinds.enumerated()), id: \.element) { index, kind in
                    if index > 0 { Divider().padding(.leading, 44) }
                    clientRow(kind)
                }
            }
            .contentPanel()
            Text("Aprovar faz uma cópia protegida do cliente encontrado no caminho informado e pede a senha de administrador uma vez. O serviço só executa essa cópia: atualizar o Homebrew não muda nada até você aprovar de novo.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }

    private func clientRow(_ kind: RuntimeKind) -> some View {
        let state = versions.state(kind, status: service.status)
        let presentation = Self.presentation(kind, state)
        return HStack(alignment: .center, spacing: 12) {
            Image(systemName: presentation.symbol)
                .symbolRenderingMode(.hierarchical)
                .font(.system(size: 18, weight: .semibold))
                .foregroundStyle(presentation.tone.color)
                .frame(width: 22)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(Self.clientTitle(kind)).font(.body.weight(.medium))
                Text(presentation.text).font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if let command = presentation.command {
                    Text(command).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .accessibilityElement(children: .combine)
            clientAction(kind, state, command: presentation.command)
        }
        .padding(.horizontal, 12).padding(.vertical, 10)
    }

    @ViewBuilder private func clientAction(_ kind: RuntimeKind, _ state: ClientState, command: String?) -> some View {
        if service.approvingKind == kind {
            ProgressView().controlSize(.small).accessibilityLabel("Aprovando")
        } else if let command {
            Button(copied == kind ? "Copiado" : "Copiar comando") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(command, forType: .string)
                copied = kind
            }
            .fixedSize()
            .adaptiveButtonStyle()
        } else if state.needsAction {
            Button(service.status?.runtime(kind) == nil ? "Aprovar…" : "Aprovar de novo…") { service.approveClient(kind) }
                .fixedSize()
                .adaptiveButtonStyle(prominent: true)
                .disabled(service.busy)
        }
    }

    static func clientTitle(_ kind: RuntimeKind) -> String {
        switch kind {
        case .openfortivpn: return "openfortivpn (Fortinet)"
        case .openvpn: return "OpenVPN"
        case .wireguard: return "WireGuard (wireguard-go)"
        }
    }

    struct Presentation: Equatable {
        var symbol: String
        var tone: StatusTone
        var text: String
        var command: String?
    }

    static func presentation(_ kind: RuntimeKind, _ state: ClientState) -> Presentation {
        let formula = kind.executableName
        switch state {
        case .notInstalled:
            return Presentation(symbol: "arrow.down.circle", tone: .neutral,
                                text: "Não instalado. Instale pelo Homebrew no Terminal e volte aqui para aprovar:",
                                command: "brew install \(formula)")
        case .notApproved(let installed, let latest):
            if let latest {
                return Presentation(symbol: "arrow.up.circle", tone: .warning,
                                    text: "Versão \(installed ?? "instalada") desatualizada (atual: \(latest)). Atualize antes de aprovar:",
                                    command: "brew upgrade \(formula)")
            }
            return Presentation(symbol: "exclamationmark.shield", tone: .warning,
                                text: "Instalado\(installed.map { " (\($0))" } ?? ""), ainda não aprovado. Aprove para conectar com ele.", command: nil)
        case .updateAvailable(let current, let latest):
            return Presentation(symbol: "arrow.up.circle", tone: .warning,
                                text: "Versão \(current) instalada; a \(latest) já está disponível. Atualize e depois aprove de novo:",
                                command: "brew upgrade \(formula)")
        case .approvalOutdated(let approved, let installed):
            return Presentation(symbol: "arrow.triangle.2.circlepath", tone: .warning,
                                text: "O app usa a cópia aprovada \(approved), mas a instalação local agora tem \(installed ?? "outra versão"). Aprove de novo para usar a nova.",
                                command: nil)
        case .upToDate(let version):
            return Presentation(symbol: "checkmark.seal", tone: .success, text: "Versão \(version), aprovada e atualizada.", command: nil)
        }
    }

    // MARK: Service actions

    @ViewBuilder private var serviceActions: some View {
        switch service.health {
        case .notRegistered, .notFound:
            Button("Ativar serviço") { service.activate() }.fixedSize().adaptiveButtonStyle(prominent: true).disabled(service.busy)
        case .requiresApproval:
            Button("Abrir Ajustes") { service.openSettings() }.fixedSize().adaptiveButtonStyle(prominent: true)
        case .outdated, .incompatible:
            Button("Atualizar serviço") { service.update() }.fixedSize().adaptiveButtonStyle(prominent: true).disabled(service.busy)
        default:
            EmptyView()
        }
        Button("Verificar novamente") {
            service.refresh()
            versions.refresh(status: service.status, force: true)
        }
        .fixedSize().adaptiveButtonStyle().disabled(service.busy)
        if service.isRegistered {
            Button("Remover serviço…", role: .destructive) { confirmingRemoval = true }
                .fixedSize().adaptiveButtonStyle().disabled(service.busy)
        }
        if service.busy && service.approvingKind == nil {
            ProgressView().controlSize(.small).accessibilityLabel("Em andamento")
        }
    }
}
