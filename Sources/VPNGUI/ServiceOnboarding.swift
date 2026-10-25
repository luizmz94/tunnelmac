import SwiftUI
import AppKit

/// First run: while the privileged service is not registered or still waits for the
/// user's approval in System Settings, the main window asks for it in plain language.
/// Once macOS allows it, the sheet closes and Serviço privilegiado opens for the clients.
enum ServiceOnboarding {
    /// "Agora não" holds until the app quits; the next launch asks again.
    @MainActor static var postponed = false

    static func needed(_ health: ServiceController.Health) -> Bool {
        health == .notRegistered || health == .requiresApproval
    }

    /// 1: activate, 2: allow in System Settings, 3: approve a VPN client.
    static func step(_ health: ServiceController.Health) -> Int {
        switch health {
        case .notRegistered, .notFound: return 1
        case .requiresApproval: return 2
        default: return 3
        }
    }
}

struct ServiceOnboardingSheet: View {
    @ObservedObject var service: ServiceController
    let later: () -> Void
    /// The switch is flipped in System Settings while this app is in the background.
    private let poll = Timer.publish(every: 2, on: .main, in: .common).autoconnect()

    private var step: Int { ServiceOnboarding.step(service.health) }

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 18) {
                SheetHeader(symbol: "lock.shield", tone: .warning, title: "Permitir o TunnelMac em segundo plano",
                            subtitle: "Uma vez só, para conectar sem digitar a senha a cada vez")
                Text("Para criar a VPN e ajustar rotas e DNS, o TunnelMac usa um pequeno serviço do sistema. O macOS pede que você o permita em Ajustes do Sistema.")
                    .fixedSize(horizontal: false, vertical: true)
                VStack(alignment: .leading, spacing: 12) {
                    row(1, "Ativar o serviço do TunnelMac")
                    row(2, "Ativar TunnelMac em Ajustes do Sistema › Geral › Itens de Início › Permitir em segundo plano")
                    row(3, "Aprovar o cliente VPN que você usa, na tela seguinte")
                }
                if step == 1, let message = service.message {
                    InlineNotice(tone: .warning, symbol: "exclamationmark.triangle", title: message)
                }
            }
            .padding(24)
            SheetFooter {
                Button("Agora não", action: later)
                    .keyboardShortcut(.cancelAction)
                    .adaptiveButtonStyle()
                Spacer()
                if service.busy { ProgressView().controlSize(.small).accessibilityLabel("Em andamento") }
                Button(step == 1 ? "Permitir em segundo plano" : "Abrir Ajustes do Sistema") {
                    step == 1 ? service.activate() : service.openSettings()
                }
                .keyboardShortcut(.defaultAction)
                .adaptiveButtonStyle(prominent: true)
                .disabled(service.busy)
            }
        }
        .frame(width: 500)
        .onReceive(poll) { _ in if !service.busy { service.refresh() } }
    }

    private func row(_ number: Int, _ text: String) -> some View {
        let done = step > number, current = step == number
        return HStack(alignment: .firstTextBaseline, spacing: 10) {
            ZStack {
                Circle().fill(done ? Color.green : current ? Color.accentColor : Color.secondary.opacity(0.25))
                if done {
                    Image(systemName: "checkmark").font(.system(size: 10, weight: .bold)).foregroundStyle(.white)
                } else {
                    Text("\(number)").font(.caption.weight(.semibold)).foregroundStyle(current ? .white : .secondary)
                }
            }
            .frame(width: 20, height: 20)
            .alignmentGuide(.firstTextBaseline) { $0[VerticalAlignment.center] + 4 }
            .accessibilityHidden(true)
            Text(text)
                .foregroundStyle(done ? .secondary : .primary)
                .fontWeight(current ? .semibold : .regular)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Passo \(number)\(done ? ", concluído" : ""): \(text)")
    }
}
