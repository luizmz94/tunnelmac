import SwiftUI
import AppKit
import CryptoKit
import Security

/// Networks that inspect HTTPS (a firewall that re-signs sites with its own authority, as
/// GlobalProtect gateways often do) make every site look untrusted until the organization's
/// root is trusted on the Mac. This finds those authorities from real connections through the
/// tunnel and offers each one to install, one at a time, with its fingerprint to compare.
/// Nothing is trusted without the user confirming it, and macOS asks for the password itself.
enum NetworkCertificates {
    struct Authority: Identifiable, Equatable {
        enum Role: Equatable { case root, intermediate }
        enum Status: Equatable { case trusted, inKeychain, missing }
        var id: String { sha256 }
        let sha256: String
        let name: String
        let issuer: String
        let role: Role
        let notAfter: Date?
        var status: Status
        let data: Data
        /// Sites whose certificate this authority signed (directly or through the chain).
        var hosts: [String]
    }

    struct HostResult: Identifiable, Equatable {
        var id: String { host }
        let host: String
        /// nil: could not connect.
        let trusted: Bool?
        let issuer: String
        let detail: String?
    }

    struct Report: Equatable {
        var hosts: [HostResult]
        var authorities: [Authority]
        /// The chain stopped at an issuer the network did not send (root missing).
        var missingRoots: [String]
    }

    static let defaultHosts = "github.com, www.microsoft.com, www.google.com, www.apple.com"

    static func hosts(_ text: String) -> [String] {
        var seen = Set<String>()
        return text.components(separatedBy: CharacterSet(charactersIn: ", \n\t")).compactMap { raw in
            var value = raw.trimmingCharacters(in: .whitespaces).lowercased()
            if value.hasPrefix("https://") { value = String(value.dropFirst(8)) }
            if let slash = value.firstIndex(of: "/") { value = String(value[..<slash]) }
            guard !value.isEmpty, value.count <= 253,
                  value.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || ".-:".contains($0)) }),
                  seen.insert(value).inserted else { return nil }
            return value
        }.prefix(12).map { $0 }
    }

    // MARK: Probe

    private final class Capture: NSObject, URLSessionDelegate {
        var chain: [SecCertificate] = []
        var trusted = false
        func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
            guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
                  let trust = challenge.protectionSpace.serverTrust else { completionHandler(.performDefaultHandling, nil); return }
            trusted = SecTrustEvaluateWithError(trust, nil)
            chain = (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? []
            // Only the handshake matters: never send a request to an untrusted server.
            completionHandler(trusted ? .performDefaultHandling : .cancelAuthenticationChallenge, nil)
        }
    }

    /// One TLS handshake per site (HEAD, no cookies or cache); the request is sent only to
    /// sites macOS already trusts.
    static func probe(_ host: String) async -> (trusted: Bool?, chain: [SecCertificate], error: String?) {
        guard let url = URL(string: "https://\(host)/") else { return (nil, [], nil) }
        let capture = Capture()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 10
        configuration.timeoutIntervalForResource = 15
        let session = URLSession(configuration: configuration, delegate: capture, delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        var request = URLRequest(url: url)
        request.httpMethod = "HEAD"
        do { _ = try await session.data(for: request) } catch {
            if capture.chain.isEmpty { return (nil, [], error.localizedDescription) }
        }
        return (capture.trusted, capture.chain, nil)
    }

    static func discover(_ hosts: [String]) async -> Report {
        var results: [HostResult] = []
        var authorities: [String: Authority] = [:]
        var order: [String] = []
        var missing = Set<String>()
        for host in hosts {
            let (trusted, chain, error) = await probe(host)
            let issuer = chain.first.map(issuerName) ?? ""
            results.append(HostResult(host: host, trusted: trusted, issuer: issuer, detail: error))
            guard trusted == false, chain.count > 0 else { continue }
            // Every certificate above the site's own is an authority the network presented.
            for certificate in chain.dropFirst() {
                let digest = sha256(certificate)
                if var known = authorities[digest] {
                    if !known.hosts.contains(host) { known.hosts.append(host) }
                    authorities[digest] = known
                    continue
                }
                let data = SecCertificateCopyData(certificate) as Data
                authorities[digest] = Authority(sha256: digest, name: SecCertificateCopySubjectSummary(certificate) as String? ?? "?",
                                                issuer: issuerName(certificate), role: selfSigned(certificate) ? .root : .intermediate,
                                                notAfter: notAfter(certificate), status: status(certificate), data: data, hosts: [host])
                order.append(digest)
            }
            if let top = chain.last, !selfSigned(top) { missing.insert(issuerName(top)) }
        }
        // Root first: trusting it is what fixes the sites; intermediates come after.
        let list = order.compactMap { authorities[$0] }.sorted { ($0.role == .root ? 0 : 1) < ($1.role == .root ? 0 : 1) }
        return Report(hosts: results, authorities: list, missingRoots: missing.sorted())
    }

    // MARK: Certificate facts

    static func sha256(_ certificate: SecCertificate) -> String {
        SHA256.hash(data: SecCertificateCopyData(certificate) as Data).map { String(format: "%02X", $0) }.joined()
    }

    static func display(_ sha256: String) -> String {
        stride(from: 0, to: sha256.count, by: 2).map {
            let start = sha256.index(sha256.startIndex, offsetBy: $0)
            return String(sha256[start..<sha256.index(start, offsetBy: 2)])
        }.joined(separator: ":")
    }

    static func selfSigned(_ certificate: SecCertificate) -> Bool {
        guard let subject = SecCertificateCopyNormalizedSubjectSequence(certificate) as Data?,
              let issuer = SecCertificateCopyNormalizedIssuerSequence(certificate) as Data? else { return false }
        return subject == issuer
    }

    static func issuerName(_ certificate: SecCertificate) -> String {
        let keys = [kSecOIDX509V1IssuerName] as CFArray
        guard let values = SecCertificateCopyValues(certificate, keys, nil) as? [String: Any],
              let issuer = values[kSecOIDX509V1IssuerName as String] as? [String: Any],
              let entries = issuer[kSecPropertyKeyValue as String] as? [[String: Any]] else { return "" }
        let common = entries.first { ($0[kSecPropertyKeyLabel as String] as? String) == (kSecOIDCommonName as String) }
        let organization = entries.first { ($0[kSecPropertyKeyLabel as String] as? String) == (kSecOIDOrganizationName as String) }
        return (common?[kSecPropertyKeyValue as String] as? String) ?? (organization?[kSecPropertyKeyValue as String] as? String) ?? ""
    }

    static func notAfter(_ certificate: SecCertificate) -> Date? {
        let keys = [kSecOIDX509V1ValidityNotAfter] as CFArray
        guard let values = SecCertificateCopyValues(certificate, keys, nil) as? [String: Any],
              let entry = values[kSecOIDX509V1ValidityNotAfter as String] as? [String: Any],
              let seconds = entry[kSecPropertyKeyValue as String] as? NSNumber else { return nil }
        return Date(timeIntervalSinceReferenceDate: seconds.doubleValue)
    }

    static func status(_ certificate: SecCertificate) -> Authority.Status {
        var trust: SecTrust?
        if SecTrustCreateWithCertificates(certificate, SecPolicyCreateBasicX509(), &trust) == errSecSuccess,
           let trust, SecTrustEvaluateWithError(trust, nil) { return .trusted }
        let query: [String: Any] = [kSecClass as String: kSecClassCertificate, kSecValueRef as String: certificate,
                                    kSecMatchLimit as String: kSecMatchLimitOne]
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess ? .inKeychain : .missing
    }

    // MARK: Install

    /// Adds the certificate to the login keychain; a root also gets trust for SSL only (user
    /// domain). macOS shows its own password prompt for the trust change.
    static func install(_ authority: Authority) throws {
        guard let certificate = SecCertificateCreateWithData(nil, authority.data as CFData), sha256(certificate) == authority.sha256 else {
            throw AppFailure(String(localized: "Certificado inválido."))
        }
        let add: [String: Any] = [kSecClass as String: kSecClassCertificate, kSecValueRef as String: certificate]
        let added = SecItemAdd(add as CFDictionary, nil)
        guard added == errSecSuccess || added == errSecDuplicateItem else {
            throw AppFailure(String(localized: "Não foi possível adicionar o certificado ao Keychain (\(added))."))
        }
        guard authority.role == .root else { return }
        let settings: [[String: Any]] = [[kSecTrustSettingsPolicy as String: SecPolicyCreateSSL(true, nil),
                                          kSecTrustSettingsResult as String: NSNumber(value: SecTrustSettingsResult.trustRoot.rawValue)]]
        let trusted = SecTrustSettingsSetTrustSettings(certificate, .user, settings as CFArray)
        guard trusted == errSecSuccess else {
            if trusted == errAuthorizationCanceled || trusted == errSecUserCanceled {
                throw AppFailure(String(localized: "Confiança cancelada. O certificado ficou no Keychain sem confiança."))
            }
            throw AppFailure(String(localized: "Não foi possível configurar a confiança do certificado (\(trusted))."))
        }
    }
}

/// Card in the GlobalProtect details: opens the discovery sheet.
struct NetworkCertificatesCard: View {
    let connected: Bool
    @State private var showing = false
    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "checkmark.seal").foregroundStyle(.secondary).font(.system(size: 15, weight: .semibold))
            VStack(alignment: .leading, spacing: 3) {
                Text("Certificados da rede").font(.callout.weight(.semibold))
                Text(connected ? "Se sites mostrarem que a conexão não é privada, a rede pode inspecionar HTTPS com uma autoridade própria."
                               : "Conecte para verificar se a rede inspeciona HTTPS com uma autoridade própria.")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            Button("Verificar…") { showing = true }.disabled(!connected)
        }
        .cardSurface()
        .sheet(isPresented: $showing) { NetworkCertificatesSheet() }
    }
}

struct NetworkCertificatesSheet: View {
    @Environment(\.dismiss) private var dismiss
    @AppStorage("networkCertificateHosts") private var hostText = NetworkCertificates.defaultHosts
    @State private var report: NetworkCertificates.Report?
    @State private var checking = false
    @State private var installing: String?
    @State private var error: String?

    var body: some View {
        VStack(spacing: 0) {
            SheetHeader(symbol: "checkmark.seal", tone: .neutral, title: String(localized: "Certificados da rede"),
                        subtitle: String(localized: "Autoridades que a rede usa para inspecionar HTTPS"))
                .padding(.horizontal, 22).padding(.top, 20).padding(.bottom, 4)
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Sites para testar").font(.callout.weight(.semibold))
                        HStack {
                            TextField("Sites", text: $hostText, prompt: Text(NetworkCertificates.defaultHosts)).labelsHidden()
                            Button(checking ? "Verificando…" : "Verificar") { check() }
                                .adaptiveButtonStyle(prominent: true)
                                .disabled(checking || NetworkCertificates.hosts(hostText).isEmpty)
                        }
                        Text("Inclua um site que mostrou o alerta no navegador. Só o certificado de cada site é lido.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                    if let error {
                        InlineNotice(tone: .danger, symbol: "exclamationmark.triangle.fill", title: error) { EmptyView() }
                    }
                    if let report { results(report) }
                }
                .padding(.horizontal, 22).padding(.vertical, 14)
            }
            SheetFooter {
                Spacer()
                Button("Fechar") { dismiss() }.keyboardShortcut(.cancelAction)
            }
        }
        .sheetFrame(width: 600, height: 620)
        .onAppear { if report == nil { check() } }
    }

    @ViewBuilder private func results(_ report: NetworkCertificates.Report) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Sites").font(.callout.weight(.semibold))
            ForEach(report.hosts) { host in
                HStack(spacing: 8) {
                    Image(systemName: host.trusted == true ? "checkmark.circle.fill" : host.trusted == false ? "exclamationmark.triangle.fill" : "questionmark.circle")
                        .foregroundStyle(host.trusted == true ? Color.green : host.trusted == false ? Color.orange : Color.secondary)
                    Text(host.host).font(.callout)
                    Spacer()
                    Text(host.trusted == true ? String(localized: "Confiável")
                         : host.trusted == false ? String(localized: "Não confiável · emitido por \(host.issuer)")
                         : String(localized: "Sem conexão"))
                        .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
            }
        }
        .cardSurface()
        if report.authorities.isEmpty {
            if report.hosts.contains(where: { $0.trusted == false }) {
                InlineNotice(tone: .warning, symbol: "questionmark.diamond",
                             title: String(localized: "A rede não enviou a autoridade que assinou os sites"),
                             message: String(localized: "Peça o certificado raiz ao administrador da rede.")) { EmptyView() }
            } else if report.hosts.contains(where: { $0.trusted == true }) {
                InlineNotice(tone: .success, symbol: "checkmark.seal.fill",
                             title: String(localized: "Nenhuma inspeção de HTTPS encontrada nestes sites")) { EmptyView() }
            }
        } else {
            InlineNotice(tone: .warning, symbol: "lock.trianglebadge.exclamationmark",
                         title: String(localized: "A rede apresenta certificados próprios"),
                         message: String(localized: "Instale um por vez, só se a organização confirmar a impressão digital. Confiar na raiz vale também fora da VPN.")) { EmptyView() }
            ForEach(report.authorities) { authority in row(authority) }
        }
        ForEach(report.missingRoots, id: \.self) { name in
            InlineNotice(tone: .warning, symbol: "questionmark.diamond",
                         title: String(localized: "Raiz \"\(name)\" não enviada pela rede"),
                         message: String(localized: "Peça esse certificado ao administrador da rede.")) { EmptyView() }
        }
    }

    private func row(_ authority: NetworkCertificates.Authority) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline) {
                Text(authority.name).font(.callout.weight(.semibold))
                Text(authority.role == .root ? "Raiz" : "Intermediária")
                    .font(.caption).padding(.horizontal, 6).padding(.vertical, 1)
                    .background(Capsule().fill(Color.primary.opacity(0.08)))
                Spacer()
                switch authority.status {
                case .trusted: Label("Confiável", systemImage: "checkmark.seal.fill").foregroundStyle(.green).font(.caption)
                case .inKeychain:
                    if authority.role == .root { installButton(authority, title: String(localized: "Confiar…")) }
                    else { Label("No Keychain", systemImage: "checkmark").foregroundStyle(.secondary).font(.caption) }
                case .missing: installButton(authority, title: authority.role == .root ? String(localized: "Instalar e confiar…") : String(localized: "Instalar…"))
                }
            }
            if authority.role == .intermediate { Text("Emitida por \(authority.issuer)").font(.caption).foregroundStyle(.secondary) }
            Text(NetworkCertificates.display(authority.sha256))
                .font(.system(.caption, design: .monospaced)).textSelection(.enabled).foregroundStyle(.secondary)
            HStack {
                if let notAfter = authority.notAfter { Text("Válido até \(notAfter.formatted(date: .abbreviated, time: .omitted))") }
                Text("· Vista em \(authority.hosts.joined(separator: ", "))").lineLimit(1).truncationMode(.tail)
            }
            .font(.caption).foregroundStyle(.secondary)
        }
        .cardSurface()
    }

    private func installButton(_ authority: NetworkCertificates.Authority, title: String) -> some View {
        Button(installing == authority.sha256 ? String(localized: "Instalando…") : title) { confirm(authority) }
            .disabled(installing != nil || checking)
    }

    private func confirm(_ authority: NetworkCertificates.Authority) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        if authority.role == .root {
            alert.messageText = String(localized: "Confiar em \"\(authority.name)\" para sites (SSL)?")
            alert.informativeText = String(localized: "Compare a impressão digital SHA-256 com uma fonte da organização antes de continuar:\n\n\(NetworkCertificates.display(authority.sha256))\n\nO certificado vai para o Keychain de início de sessão e passa a validar sites que ele assinar, também fora da VPN. O macOS pedirá sua senha. Para desfazer, apague-o no Acesso às Chaves.")
        } else {
            alert.messageText = String(localized: "Adicionar \"\(authority.name)\" ao Keychain?")
            alert.informativeText = String(localized: "Autoridade intermediária, emitida por \(authority.issuer). Ela não recebe confiança própria: herda a da raiz.\n\n\(NetworkCertificates.display(authority.sha256))")
        }
        alert.addButton(withTitle: authority.role == .root ? String(localized: "Confiar") : String(localized: "Adicionar"))
        alert.addButton(withTitle: String(localized: "Cancelar"))
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        installing = authority.sha256
        error = nil
        Task {
            do { try await Task.detached { try NetworkCertificates.install(authority) }.value }
            catch { self.error = error.localizedDescription }
            installing = nil
            check()
        }
    }

    private func check() {
        let hosts = NetworkCertificates.hosts(hostText)
        guard !hosts.isEmpty, !checking else { return }
        checking = true
        Task {
            report = await NetworkCertificates.discover(hosts)
            checking = false
        }
    }
}
