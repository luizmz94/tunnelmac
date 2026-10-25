import Foundation
import Security
import VPNHelperShared

/// Authenticated XPC client of the privileged helper.
///
/// The connection carries a code-signing requirement for the helper (same Team ID as this
/// app, identifier com.luiz.vpngui.helper); the system invalidates it if the peer does not
/// match, so the app never talks to a fake helper. A handshake (protocol version) precedes
/// every other request on each new connection.
@MainActor
final class HelperClient {
    typealias Factory = () -> NSXPCConnection?
    private let factory: Factory
    private let requirement: String
    private var connection: NSXPCConnection?
    private var handshaken = false
    private var waitingForHello: [(Result<HelperStatus, HelperFailure>) -> Void] = []
    private var helloInFlight = false
    /// Events of this app's own sessions, delivered in order on the main thread.
    var onEvents: ((EventBatch) -> Void)?
    var onStatus: ((HelperStatus) -> Void)?
    /// The connection was interrupted or invalidated (helper exit/crash, rejected peer).
    var onLost: (() -> Void)?

    init(requirement: String, factory: @escaping Factory) {
        self.requirement = requirement
        self.factory = factory
    }

    static func production(team: String) -> HelperClient {
        HelperClient(requirement: CodeTrust.requirement(identifier: HelperConstants.helperIdentifier, team: team)) {
            NSXPCConnection(machServiceName: HelperConstants.machServiceName, options: .privileged)
        }
    }

    var isConnected: Bool { connection != nil }

    func invalidate() {
        connection?.invalidate()
        connection = nil
        handshaken = false
    }

    private func ensureConnection() -> NSXPCConnection? {
        if let connection { return connection }
        guard let created = factory() else { return nil }
        created.setCodeSigningRequirement(requirement)
        created.remoteObjectInterface = HelperInterfaces.helper()
        created.exportedInterface = HelperInterfaces.client()
        created.exportedObject = EventReceiver { [weak self] batch in self?.onEvents?(batch) }
        let lost: () -> Void = { [weak self, weak created] in
            DispatchQueue.main.async {
                guard let self, let created, self.connection === created else { return }
                self.connection = nil
                self.handshaken = false
                let waiting = self.waitingForHello
                self.waitingForHello = []
                self.helloInFlight = false
                waiting.forEach { $0(.failure(HelperFailure(.transport, "Conexão com o serviço perdida."))) }
                self.onLost?()
            }
        }
        created.interruptionHandler = lost
        created.invalidationHandler = lost
        created.resume()
        connection = created
        return created
    }

    /// Sends one request, performing the handshake first when needed.
    func request(_ request: HelperRequest, timeout: TimeInterval = 20,
                 completion: @escaping (Result<HelperResponse, HelperFailure>) -> Void) {
        if case .hello = request {
            send(request, timeout: timeout, completion: completion)
            return
        }
        if handshaken, connection != nil {
            send(request, timeout: timeout, completion: completion)
            return
        }
        hello { [weak self] result in
            switch result {
            case .success: self?.send(request, timeout: timeout, completion: completion)
            case .failure(let failure): completion(.failure(failure))
            }
        }
    }

    func hello(_ completion: @escaping (Result<HelperStatus, HelperFailure>) -> Void) {
        waitingForHello.append(completion)
        guard !helloInFlight else { return }
        helloInFlight = true
        send(.hello(HelloRequest(appVersion: HelperConstants.fullVersion)), timeout: 15) { [weak self] result in
            guard let self else { return }
            self.helloInFlight = false
            let outcome: Result<HelperStatus, HelperFailure>
            switch result {
            case .success(.status(let status)):
                self.handshaken = true
                self.onStatus?(status)
                outcome = .success(status)
            case .success(.failure(let failure)): outcome = .failure(failure)
            case .success: outcome = .failure(HelperFailure(.invalidRequest, "Resposta inesperada do serviço."))
            case .failure(let failure): outcome = .failure(failure)
            }
            let waiting = self.waitingForHello
            self.waitingForHello = []
            waiting.forEach { $0(outcome) }
        }
    }

    private func send(_ request: HelperRequest, timeout: TimeInterval,
                      completion: @escaping (Result<HelperResponse, HelperFailure>) -> Void) {
        guard let connection = ensureConnection() else {
            completion(.failure(HelperFailure(.unavailable, "Serviço privilegiado indisponível neste ambiente.")))
            return
        }
        let once = Once(completion)
        let proxy = connection.remoteObjectProxyWithErrorHandler { error in
            DispatchQueue.main.async { once.call(.failure(HelperFailure(.transport, "Sem resposta do serviço: \(error.localizedDescription)"))) }
        } as? VPNHelperXPC
        guard let proxy else { once.call(.failure(HelperFailure(.transport, "Interface do serviço indisponível."))); return }
        DispatchQueue.main.asyncAfter(deadline: .now() + timeout) { [weak self] in
            guard once.pending else { return }
            // Invalidating ownership makes the helper abandon even a queued/late start.
            // Keep late tokens below as a second barrier if a reply won the XPC race.
            switch request {
            case .start, .startOpenVPN, .startWireGuard, .stop, .stopAll:
                connection.invalidate()
                if self?.connection === connection {
                    self?.connection = nil
                    self?.handshaken = false
                    self?.onLost?()
                }
            default: break // A read-only timeout must not disconnect healthy sessions.
            }
            once.call(.failure(HelperFailure(.timeout, "O serviço não respondeu a tempo.")))
        }
        proxy.perform(MessageCodec.encode(request)) { data in
            let decoded: Result<HelperResponse, HelperFailure>
            do {
                let response = try MessageCodec.decode(HelperResponse.self, from: data, limit: HelperConstants.maximumBatchSize)
                decoded = .success(response)
            } catch { decoded = .failure(HelperFailure(.invalidRequest, "Resposta malformada do serviço.")) }
            DispatchQueue.main.async {
                if !once.pending, case .success(.started(let token, _)) = decoded {
                    proxy.perform(MessageCodec.encode(HelperRequest.stop(token: token))) { _ in }
                }
                once.call(decoded)
            }
        }
    }

    private final class Once {
        private var completion: ((Result<HelperResponse, HelperFailure>) -> Void)?
        var pending: Bool { completion != nil }
        init(_ completion: @escaping (Result<HelperResponse, HelperFailure>) -> Void) { self.completion = completion }
        func call(_ result: Result<HelperResponse, HelperFailure>) {
            guard let completion else { return }
            self.completion = nil
            completion(result)
        }
    }
}

/// Exported to the helper. Replies only after the main thread processed the batch, so a
/// busy UI slows the helper's sender instead of growing memory here.
final class EventReceiver: NSObject, VPNHelperClientXPC {
    let handler: @MainActor (EventBatch) -> Void
    init(handler: @escaping @MainActor (EventBatch) -> Void) { self.handler = handler }
    func deliver(_ batch: Data, reply: @escaping () -> Void) {
        guard let decoded = try? MessageCodec.decode(EventBatch.self, from: batch, limit: HelperConstants.maximumBatchSize) else {
            reply(); return
        }
        DispatchQueue.main.async {
            MainActor.assumeIsolated { self.handler(decoded) }
            reply()
        }
    }
}

/// External form of an empty AuthorizationRef created here; the helper asks for the
/// administrator right with it, so the prompt appears in this user's session.
final class AdminAuthorizationHandle {
    private var reference: AuthorizationRef?
    let externalForm: Data
    init?() {
        var reference: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &reference) == errAuthorizationSuccess, let reference else { return nil }
        var form = AuthorizationExternalForm()
        guard AuthorizationMakeExternalForm(reference, &form) == errAuthorizationSuccess else {
            AuthorizationFree(reference, [])
            return nil
        }
        self.reference = reference
        externalForm = withUnsafeBytes(of: &form) { Data($0) }
    }
    deinit { if let reference { AuthorizationFree(reference, [.destroyRights]) } }
}
