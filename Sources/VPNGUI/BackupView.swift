import SwiftUI
import AppKit
import UniformTypeIdentifiers

// Configurações › Backup: export every connection (with passwords and profiles) to one
// password-protected file, and import such a file on this or another Mac.

enum BackupPanels {
    static var contentType: UTType { UTType(filenameExtension: ConfigBackup.fileExtension) ?? .data }

    @MainActor static func chooseDestination(now: Date = Date()) -> URL? {
        let panel = NSSavePanel()
        panel.title = "Exportar backup do TunnelMac"
        panel.message = "O arquivo contém senhas e chaves das VPNs, criptografadas com a senha escolhida."
        panel.prompt = "Exportar"
        panel.allowedContentTypes = [contentType]
        panel.canCreateDirectories = true
        let day = ISO8601DateFormatter.string(from: now, timeZone: .current, formatOptions: [.withFullDate, .withDashSeparatorInDate])
        panel.nameFieldStringValue = "TunnelMac-\(day).\(ConfigBackup.fileExtension)"
        return panel.runModal() == .OK ? panel.url : nil
    }

    @MainActor static func chooseBackup() -> URL? {
        let panel = NSOpenPanel()
        panel.title = "Importar backup do TunnelMac"
        panel.message = "Escolha um arquivo .\(ConfigBackup.fileExtension) exportado pelo TunnelMac."
        panel.prompt = "Abrir"
        panel.allowedContentTypes = [contentType]
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        return panel.runModal() == .OK ? panel.url : nil
    }
}

struct BackupSettings: View {
    @ObservedObject var model: AppModel
    let preferences: AppPreferences
    @State private var exporting = false
    @State private var importing: BackupFile?
    @State private var notice: BackupNotice?

    static let footer = "Criptografado com AES-256-GCM e uma chave derivada da senha (PBKDF2-SHA256, 600 mil iterações). Sem a senha não há como abrir o arquivo. Sessões SAML não são incluídas; certificados do cliente precisam estar no Keychain do outro Mac."

    var body: some View {
        SettingsSection(title: "Backup", footer: Self.footer) {
            SettingsRow(symbol: "square.and.arrow.up", color: .blue, title: "Exportar configurações",
                        subtitle: "Conexões, senhas, perfis OpenVPN e WireGuard e as preferências do app, num arquivo protegido por senha.") {
                Button("Exportar…") { notice = nil; exporting = true }
                    .controlSize(.small).adaptiveButtonStyle()
                    .disabled(!model.ready || model.writing)
            }
            SettingsDivider()
            SettingsRow(symbol: "square.and.arrow.down", color: .green, title: "Importar backup",
                        subtitle: "Adiciona as conexões do arquivo; as que já existem neste Mac são substituídas pela versão do backup.") {
                Button("Importar…") { chooseImport() }
                    .controlSize(.small).adaptiveButtonStyle()
                    .disabled(!model.ready || model.writing)
            }
        }
        .sheet(isPresented: $exporting) {
            ExportBackupSheet(model: model, preferences: preferences) { notice = $0 }
        }
        .sheet(item: $importing) { file in
            ImportBackupSheet(model: model, preferences: preferences, file: file) { notice = $0 }
        }
        if let notice {
            InlineNotice(tone: notice.tone, symbol: notice.symbol, title: notice.title, message: notice.message)
        }
    }

    private func chooseImport() {
        notice = nil
        guard let url = BackupPanels.chooseBackup() else { return }
        do { importing = BackupFile(name: url.lastPathComponent, data: try BoundedFile.read(url, limit: BackupCipher.maximumSize)) }
        catch { notice = .failure("Não foi possível ler o backup", error.localizedDescription) }
    }
}

struct BackupFile: Identifiable {
    let id = UUID()
    let name: String
    let data: Data
}

struct BackupNotice: Equatable {
    var tone: StatusTone
    var symbol: String
    var title: String
    var message: String?
    static func failure(_ title: String, _ message: String) -> BackupNotice {
        BackupNotice(tone: .danger, symbol: "exclamationmark.triangle.fill", title: title, message: message)
    }
}

struct ExportBackupSheet: View {
    let model: AppModel
    let preferences: AppPreferences
    let finished: (BackupNotice) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var password = ""
    @State private var confirmation = ""
    @State private var includePreferences = true
    @State private var working = false
    @State private var error: String?

    private var problem: String? {
        if password.count < BackupCipher.minimumPassword { return "Pelo menos \(BackupCipher.minimumPassword) caracteres." }
        if password != confirmation { return confirmation.isEmpty ? nil : "As senhas não coincidem." }
        return nil
    }
    private var canExport: Bool { problem == nil && password == confirmation && !working }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Exportar configurações").font(.headline)
            Text("\(model.data.connections.count) \(model.data.connections.count == 1 ? "conexão" : "conexões") com senhas e perfis. Guarde a senha: ela será pedida ao importar e não pode ser recuperada.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Form {
                SecureField("Senha do backup", text: $password)
                SecureField("Confirmar senha", text: $confirmation)
                Toggle("Incluir as preferências do app", isOn: $includePreferences)
            }
            .formStyle(.grouped)
            if let message = error ?? (password.isEmpty ? nil : problem) {
                Text(message).font(.caption).foregroundStyle(error == nil ? Color.secondary : Color.red)
            }
            HStack {
                if working { ProgressView().controlSize(.small) }
                Spacer()
                Button("Cancelar") { dismiss() }.keyboardShortcut(.cancelAction).disabled(working)
                Button("Exportar…") { export() }
                    .keyboardShortcut(.defaultAction).adaptiveButtonStyle(prominent: true)
                    .disabled(!canExport)
            }
        }
        .padding(20)
        .frame(width: 420)
    }

    private func export() {
        guard canExport, let url = BackupPanels.chooseDestination() else { return }
        working = true; error = nil
        let password = password, settings = includePreferences ? preferences.backup : nil
        let count = model.data.connections.count
        Task {
            do {
                let sealed = try await model.exportBackupAsync(password: password, preferences: settings)
                try await Task.detached { try BoundedFile.replace(url, data: sealed) }.value
                finished(BackupNotice(tone: .success, symbol: "checkmark.circle.fill",
                                      title: "Backup exportado: \(count) \(count == 1 ? "conexão" : "conexões")",
                                      message: "\(url.path)\nO arquivo contém senhas das VPNs; guarde-o em local seguro."))
                dismiss()
            } catch {
                working = false
                self.error = error.localizedDescription
            }
        }
    }
}

struct ImportBackupSheet: View {
    let model: AppModel
    let preferences: AppPreferences
    let file: BackupFile
    let finished: (BackupNotice) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var password = ""
    @State private var plan: BackupImportPlan?
    @State private var applyPreferences = true
    @State private var working = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Importar backup").font(.headline)
            if let plan { summary(plan) } else { passwordForm }
            if let error { Text(error).font(.caption).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true) }
            HStack {
                if working { ProgressView().controlSize(.small) }
                Spacer()
                Button("Cancelar") { dismiss() }.keyboardShortcut(.cancelAction).disabled(working)
                if let plan {
                    Button("Importar") { run(plan) }
                        .keyboardShortcut(.defaultAction).adaptiveButtonStyle(prominent: true)
                        .disabled(working || plan.payload.connections.isEmpty && !(plan.hasPreferences && applyPreferences))
                } else {
                    Button("Abrir") { open(password) }
                        .keyboardShortcut(.defaultAction).adaptiveButtonStyle(prominent: true)
                        .disabled(working || password.isEmpty)
                }
            }
        }
        .padding(20)
        .frame(width: 460)
    }

    private var passwordForm: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Digite a senha usada ao exportar \u{201C}\(file.name)\u{201D}.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Form { SecureField("Senha do backup", text: $password).onSubmit { open(password) } }
                .formStyle(.grouped)
        }
    }

    @ViewBuilder private func summary(_ plan: BackupImportPlan) -> some View {
        let created = plan.payload.createdAt.formatted(date: .abbreviated, time: .shortened)
        Text("Criado em \(created) pelo TunnelMac \(plan.payload.appVersion).")
            .font(.callout).foregroundStyle(.secondary)
        VStack(alignment: .leading, spacing: 8) {
            if !plan.adding.isEmpty { line("plus.circle.fill", .green, "Novas: " + plan.adding.joined(separator: ", ")) }
            if !plan.replacing.isEmpty { line("arrow.triangle.2.circlepath.circle.fill", .orange, "Substituídas: " + plan.replacing.joined(separator: ", ")) }
            if plan.payload.connections.isEmpty { line("info.circle.fill", .secondary, "O backup não tem conexões.") }
            if !plan.missingPasswords.isEmpty {
                line("key.fill", .orange, "Sem senha no backup (edite e salve a senha depois): " + plan.missingPasswords.joined(separator: ", "))
            }
            if !plan.missingCertificates.isEmpty {
                line("person.badge.key.fill", .orange, "Certificado do cliente ausente neste Mac (importe-o no Acesso às Chaves): " + plan.missingCertificates.joined(separator: ", "))
            }
        }
        if plan.hasPreferences {
            Toggle("Aplicar também as preferências do app (barra de menus, Dock, atualizações e DNS da internet)", isOn: $applyPreferences)
                .toggleStyle(.checkbox).fixedSize(horizontal: false, vertical: true)
        }
    }

    private func line(_ symbol: String, _ color: Color, _ text: String) -> some View {
        Label { Text(text).fixedSize(horizontal: false, vertical: true) } icon: { Image(systemName: symbol).foregroundStyle(color) }
            .font(.callout)
    }

    private func open(_ password: String) {
        guard !working, !password.isEmpty else { return }
        working = true; error = nil
        Task {
            do { plan = try await model.openBackupAsync(file.data, password: password) }
            catch { self.error = error.localizedDescription }
            working = false
        }
    }

    private func run(_ plan: BackupImportPlan) {
        working = true; error = nil
        let count = plan.payload.connections.count
        Task {
            do {
                try await model.importBackupAsync(plan)
                if applyPreferences, let saved = plan.payload.preferences { preferences.restore(saved) }
                var details: [String] = []
                if !plan.missingPasswords.isEmpty { details.append("Sem senha: " + plan.missingPasswords.joined(separator: ", ") + ".") }
                if !plan.missingCertificates.isEmpty { details.append("Certificado ausente: " + plan.missingCertificates.joined(separator: ", ") + ".") }
                finished(BackupNotice(tone: details.isEmpty ? .success : .warning,
                                      symbol: details.isEmpty ? "checkmark.circle.fill" : "exclamationmark.circle.fill",
                                      title: "Backup importado: \(count) \(count == 1 ? "conexão" : "conexões")",
                                      message: details.isEmpty ? nil : details.joined(separator: "\n")))
                dismiss()
            } catch {
                working = false
                if error is BackupImportFailure {
                    finished(.failure("Importação incompleta", error.localizedDescription))
                    dismiss()
                } else { self.error = error.localizedDescription }
            }
        }
    }
}
