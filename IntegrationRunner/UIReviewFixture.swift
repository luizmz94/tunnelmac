@testable import VPNApp
import SwiftUI
import VPNHelperShared

/// Only a separately identified review bundle can show synthetic states. The
/// production bundle can never opt in, including via command-line arguments.
@MainActor
enum UIReviewFixture {
    static var enabled: Bool { Bundle.main.bundleIdentifier == "com.luiz.vpngui.ui-review.checked" }

    static func makeModel() -> AppModel {
        precondition(enabled)
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("VPNGUI-review-\(UUID())")
        let service = ServiceController(policy: .unavailable(reason: "Revisão visual isolada; nenhuma VPN será acessada"), registrar: nil, client: nil)
        let store = try! JSONStore(directory: root)
        let profiles = [
            Connection(name: "Escritório", server: "vpn.exemplo.invalid", port: 443, authentication: .saml),
            Connection(name: "Cliente com um nome de conexão muito longo para conferir a interface", server: "gateway.exemplo.invalid", port: 10443, authentication: .saml),
            Connection(name: "Laboratório", server: "lab-a.invalid", port: 443, authentication: .saml),
            Connection(name: "Laboratório", server: "lab-b.invalid", port: 8443, authentication: .saml),
            Connection(name: "Certificado pendente", server: "certificado.invalid", port: 443, authentication: .saml),
            Connection(name: "Autenticação recusada", server: "conta.invalid", port: 443, authentication: .saml),
            Connection(name: "Reconectando", server: "rede.invalid", port: 443, authentication: .saml)
        ] + ["Filial Curitiba", "Filial Recife", "Fornecedor Alfa", "Fornecedor Beta", "Homologação",
             "Produção", "Suporte remoto", "Backup noturno"].enumerated().map { index, name in
            Connection(name: name, server: "vpn\(index).exemplo.invalid", port: 443, authentication: .saml)
        }
        try! store.save(SavedData(connections: profiles))
        let model = AppModel(store: store,
                             passwords: PasswordStore(service: "com.luiz.vpngui.ui-review.passwords"),
                             cookies: SAMLCookieStore(service: "com.luiz.vpngui.ui-review.cookies"), service: service)
        // There is no XPC client, registrar or process transport in this model.
        let states: [ConnectionState] = [.connected, .waitingForSAML, .disconnected, .disconnecting, .failed, .failed, .reconnecting]
        for (profile, state) in zip(profiles, states) {
            let session = model.manager.session(profile.id)
            session.state = state
            session.logs = ["Revisão visual: dados fictícios, sem acesso à rede.", "Este ambiente não executa openfortivpn."]
        }
        model.manager.session(profiles[0].id).connectedAt = Date().addingTimeInterval(-3725)
        let certificate = model.manager.session(profiles[4].id)
        certificate.suggestedCertificate = String(repeating: "0f", count: 32)
        certificate.certificateValidationFailed = true
        model.manager.session(profiles[5].id).authenticationRejected = true
        return model
    }
}

/// Review-only controls affect this window, never the user's system appearance.
struct UIReviewContent: View {
    @ObservedObject var model: AppModel
    let menuBar: MenuBarCoordinator
    @State private var dark = false
    var body: some View {
        if UIReviewFixture.enabled {
            MainView(model: model, menuBar: menuBar)
                .preferredColorScheme(dark ? .dark : .light)
                .toolbar {
                    ToolbarItem {
                        Menu("Revisão visual") {
                            Toggle("Modo escuro", isOn: $dark)
                            Button("Encerrar revisão") {
                                for session in model.manager.sessions.values { session.state = .disconnected }
                                NSApp.terminate(nil)
                            }
                        }
                    }
                }
        } else {
            MainView(model: model, menuBar: menuBar)
        }
    }
}
