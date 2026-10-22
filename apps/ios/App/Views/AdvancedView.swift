import SwiftUI
import UIKit

/// Everything technical lives here, away from the main screen.
struct AdvancedView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var dnsText = ""
    @State private var dnsInvalid = false
    @State private var confirmReset = false

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
