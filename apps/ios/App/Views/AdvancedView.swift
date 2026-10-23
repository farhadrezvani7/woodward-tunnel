import SwiftUI
import UIKit

/// Everything technical lives here, away from the main screen.
struct AdvancedView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var dnsText = ""
    @State private var dnsInvalid = false
    @State private var confirmReset = false
    @State private var report: String?
    @State private var building = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField(L("advanced.dns.placeholder"), text: $dnsText, axis: .vertical)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.numbersAndPunctuation)
                        .environment(\.layoutDirection, .leftToRight)
                    if dnsInvalid {
                        Text(L("advanced.dns.invalid")).font(.footnote).foregroundStyle(.red)
                    }
                    Button(L("common.save")) { dnsInvalid = !model.saveDNS(dnsText) }
                    Button(L("advanced.dns.reset")) {
                        model.resetDNS()
                        dnsText = model.dnsServers.joined(separator: ", ")
                        dnsInvalid = false
                    }
                } header: {
                    Text(L("advanced.dns.title"))
                } footer: {
                    Text(L("advanced.dns.footer"))
                }

                if let p = model.selectedProfile {
                    Section(L("advanced.profile.title")) {
                        row(L("advanced.profile.protocol"), p.protocolName)
                        row(L("advanced.profile.server"), p.endpointText)
                    }
                }

                Section {
                    Button {
                        building = true
                        Task {
                            report = await model.buildDiagnosticReport()
                            building = false
                        }
                    } label: {
                        HStack {
                            Text(L("advanced.report.button"))
                            if building { Spacer(); ProgressView() }
                        }
                    }
                    .disabled(building)
                    Button(L("advanced.diagnostics.copy")) {
                        UIPasteboard.general.string = model.diagnosticsText
                        model.show(.success, L("advanced.diagnostics.copied"))
                    }
                    Button(L("advanced.reset.button"), role: .destructive) { confirmReset = true }
                } header: {
                    Text(L("advanced.support.title"))
                } footer: {
                    Text(L("advanced.support.footer"))
                }

                Section(L("advanced.about")) {
                    row(L("advanced.version"), versionText)
                    Text(L("advanced.about.text")).font(.footnote).foregroundStyle(.secondary)
                }
            }
            .navigationTitle(L("advanced.title"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button(L("common.done")) { dismiss() } }
            }
            .sheet(isPresented: Binding(get: { report != nil }, set: { if !$0 { report = nil } })) {
                DiagnosticReportSheet(text: report ?? "")
            }
            .onAppear { dnsText = model.dnsServers.joined(separator: ", ") }
            .confirmationDialog(L("advanced.reset.title"), isPresented: $confirmReset, titleVisibility: .visible) {
                Button(L("advanced.reset.button"), role: .destructive) { model.resetVPNConfiguration() }
                Button(L("common.cancel"), role: .cancel) {}
            } message: {
                Text(L("advanced.reset.message"))
            }
        }
    }

    private func row(_ title: String, _ value: String) -> some View {
        HStack {
            Text(title)
            Spacer()
            Text(verbatim: value).foregroundStyle(.secondary)
                .environment(\.layoutDirection, .leftToRight)
        }
        .accessibilityElement(children: .combine)
    }

    private var versionText: String {
        let info = Bundle.main.infoDictionary
        let v = info?["CFBundleShortVersionString"] as? String ?? "?"
        let b = info?["CFBundleVersion"] as? String ?? "?"
        return "\(v) (\(b))"
    }
}

/// Shows the report so the user can read exactly what would be shared. Nothing is sent by the app.
struct DiagnosticReportSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let text: String

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    Text(L("advanced.report.note")).font(.footnote).foregroundStyle(.secondary)
                    Text(verbatim: text)
                        .font(.system(.footnote, design: .monospaced))
                        .textSelection(.enabled)
                        .environment(\.layoutDirection, .leftToRight)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding()
            }
            .navigationTitle(L("advanced.report.title"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button(L("common.done")) { dismiss() } }
                ToolbarItem(placement: .primaryAction) {
                    Button(L("advanced.report.copy")) {
                        UIPasteboard.general.string = text
                        model.show(.success, L("advanced.diagnostics.copied"))
                    }
                }
            }
        }
    }
}
