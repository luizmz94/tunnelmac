import SwiftUI
import AppKit
import UniformTypeIdentifiers

// Configurações › Backup: export every connection (with passwords and profiles) to one
// password-protected file, and import such a file on this or another Mac.

enum BackupPanels {
    static var contentType: UTType { UTType(filenameExtension: ConfigBackup.fileExtension) ?? .data }

    @MainActor static func chooseDestination(now: Date = Date()) -> URL? {
        let panel = NSSavePanel()
        panel.title = String(localized: "Exportar backup do TunnelMac")
        panel.message = String(localized: "Protegido pela senha que você escolher.")
        panel.prompt = String(localized: "Exportar")
        panel.allowedContentTypes = [contentType]
        panel.canCreateDirectories = true
        let day = ISO8601DateFormatter.string(from: now, timeZone: .current, formatOptions: [.withFullDate, .withDashSeparatorInDate])
        panel.nameFieldStringValue = "TunnelMac-\(day).\(ConfigBackup.fileExtension)"
        return panel.runModal() == .OK ? panel.url : nil
    }

    @MainActor static func chooseBackup() -> URL? {
        let panel = NSOpenPanel()
        panel.title = String(localized: "Importar backup do TunnelMac")
        panel.message = String(localized: "Escolha um arquivo .\(ConfigBackup.fileExtension) exportado pelo TunnelMac.")
        panel.prompt = String(localized: "Abrir")
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

    var body: some View {
        SettingsSection {
            SettingsRow(symbol: "square.and.arrow.up", color: .blue, title: String(localized: "Exportar configurações"),
                        subtitle: String(localized: "Conexões, senhas e preferências, num arquivo com senha.")) {
                Button("Exportar…") { notice = nil; exporting = true }
                    .controlSize(.small).adaptiveButtonStyle()
                    .disabled(!model.ready || model.writing)
            }
            SettingsDivider()
            SettingsRow(symbol: "square.and.arrow.down", color: .green, title: String(localized: "Importar backup"),
                        subtitle: String(localized: "Conexões que já existem aqui são substituídas.")) {
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
        catch { notice = .failure(String(localized: "Não foi possível ler o backup"), error.localizedDescription) }
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
    @State private var reveal = false
    @State private var generated = false
    @State private var copied = false
    @State private var includePreferences = true
    @State private var working = false
    @State private var error: String?

    private var evaluation: BackupPassword.Evaluation { BackupPassword.evaluate(password) }
    private var matches: Bool { password == confirmation }
    private var canExport: Bool { evaluation.acceptable && matches && !working }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Exportar configurações").font(.headline)
            Text("\(model.data.connections.count) conexões com senhas e perfis. Guarde a senha: sem ela o backup não abre.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Form {
                Section {
                    passwordField(String(localized: "Senha do backup"), text: $password)
                    if !generated { passwordField(String(localized: "Confirmar senha"), text: $confirmation) }
                } footer: {
                    VStack(alignment: .leading, spacing: 8) {
                        if !password.isEmpty { PasswordStrengthMeter(evaluation: evaluation) }
                        if generated { generatedNote }
                        else if !confirmation.isEmpty && !matches {
                            Text("As senhas não coincidem.").font(.caption).foregroundStyle(.red)
                        }
                    }
                }
                Toggle("Incluir as preferências do app", isOn: $includePreferences)
            }
            .formStyle(.grouped)
            if let error { Text(error).font(.caption).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true) }
            HStack {
                Button { suggest() } label: { Label("Gerar senha forte", systemImage: "key.fill") }
                    .disabled(working)
                    .help("Cria uma senha aleatória no formato das senhas sugeridas pelo macOS")
                if working { ProgressView().controlSize(.small) }
                Spacer()
                Button("Cancelar") { dismiss() }.keyboardShortcut(.cancelAction).disabled(working)
                Button("Exportar…") { export() }
                    .keyboardShortcut(.defaultAction).adaptiveButtonStyle(prominent: true)
                    .disabled(!canExport)
            }
        }
        .padding(20)
        .frame(width: 460)
    }

    @ViewBuilder private func passwordField(_ title: String, text: Binding<String>) -> some View {
        let edited = Binding(get: { text.wrappedValue }, set: { value in
            text.wrappedValue = value
            // Typing over a suggestion turns the confirmation back on.
            if generated { generated = false; copied = false; confirmation = "" }
        })
        HStack(spacing: 6) {
            Group {
                if reveal { TextField(title, text: edited).font(.body.monospaced()) }
                else { SecureField(title, text: edited) }
            }
            Button { reveal.toggle() } label: { Image(systemName: reveal ? "eye.slash" : "eye") }
                .buttonStyle(.borderless)
                .help(reveal ? "Ocultar senha" : "Mostrar senha")
                .accessibilityLabel(reveal ? "Ocultar senha" : "Mostrar senha")
        }
    }

    private var generatedNote: some View {
        HStack(alignment: .top, spacing: 8) {
            Text("Senha gerada. Copie e guarde antes de exportar.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 4)
            Button(copied ? "Copiada" : "Copiar") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(password, forType: .string)
                copied = true
            }
            .controlSize(.small)
        }
    }

    private func suggest() {
        let value = BackupPassword.generate()
        password = value
        confirmation = value
        generated = true
        copied = false
        reveal = true
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
                                      title: String(localized: "Backup exportado: \(count) conexões"),
                                      message: String(localized: "\(url.path)\nGuarde o arquivo em local seguro.")))
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
            if !plan.adding.isEmpty { line("plus.circle.fill", .green, String(localized: "Novas: ") + plan.adding.joined(separator: ", ")) }
            if !plan.replacing.isEmpty { line("arrow.triangle.2.circlepath.circle.fill", .orange, String(localized: "Substituídas: ") + plan.replacing.joined(separator: ", ")) }
            if plan.payload.connections.isEmpty { line("info.circle.fill", .secondary, String(localized: "O backup não tem conexões.")) }
            if !plan.missingPasswords.isEmpty {
                line("key.fill", .orange, String(localized: "Sem senha (informe ao conectar): ") + plan.missingPasswords.joined(separator: ", "))
            }
            if !plan.missingCertificates.isEmpty {
                line("person.badge.key.fill", .orange, String(localized: "Certificado do cliente ausente neste Mac: ") + plan.missingCertificates.joined(separator: ", "))
            }
        }
        if plan.hasPreferences {
            Toggle("Aplicar também as preferências do app", isOn: $applyPreferences)
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
                if !plan.missingPasswords.isEmpty { details.append(String(localized: "Sem senha: ") + plan.missingPasswords.joined(separator: ", ") + ".") }
                if !plan.missingCertificates.isEmpty { details.append(String(localized: "Certificado ausente: ") + plan.missingCertificates.joined(separator: ", ") + ".") }
                finished(BackupNotice(tone: details.isEmpty ? .success : .warning,
                                      symbol: details.isEmpty ? "checkmark.circle.fill" : "exclamationmark.circle.fill",
                                      title: String(localized: "Backup importado: \(count) conexões"),
                                      message: details.isEmpty ? nil : details.joined(separator: "\n")))
                dismiss()
            } catch {
                working = false
                if error is BackupImportFailure {
                    finished(.failure(String(localized: "Importação incompleta"), error.localizedDescription))
                    dismiss()
                } else { self.error = error.localizedDescription }
            }
        }
    }
}

/// Five segments colored by strength, the level name and the most useful hint.
struct PasswordStrengthMeter: View {
    let evaluation: BackupPassword.Evaluation

    private var color: Color {
        switch evaluation.strength {
        case .veryWeak: return .red
        case .weak: return .orange
        case .fair: return .yellow
        case .strong, .veryStrong: return .green
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                HStack(spacing: 3) {
                    ForEach(0..<5, id: \.self) { index in
                        Capsule().fill(index <= evaluation.strength.rawValue ? color : Color.primary.opacity(0.12))
                            .frame(height: 4)
                    }
                }
                .frame(maxWidth: 180)
                Text("Força: \(evaluation.strength.title)").font(.caption.weight(.semibold)).foregroundStyle(color)
            }
            if !evaluation.acceptable {
                Text(evaluation.hints.first.map { "Exige uma senha forte. \($0)" } ?? "Exige uma senha forte; use uma senha mais longa.")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            } else if let hint = evaluation.hints.first, evaluation.strength == .strong {
                Text(hint).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Força da senha: \(evaluation.strength.title)")
    }
}
