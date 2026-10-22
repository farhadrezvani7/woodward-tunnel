import SwiftUI

/// Main screen: one big button and a plain statement of what is going on.
struct ConnectView: View {
    @EnvironmentObject private var model: AppModel
    @ScaledMetric(relativeTo: .largeTitle) private var buttonSize: CGFloat = 176
    let onShowProfiles: () -> Void

    var body: some View {
        VStack(spacing: 20) {
            Spacer(minLength: 0)
            profileHeader
            connectButton
            statusBlock
            Spacer(minLength: 0)
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle(L("app.title"))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarLeading) {
                Button(action: model.showAdvancedTapped) {
                    Image(systemName: "gearshape")
                }
                .accessibilityLabel(L("advanced.title"))
            }
        }
    }

    // MARK: pieces

    private var profileHeader: some View {
        Group {
            if let p = model.selectedProfile {
                Button(action: onShowProfiles) {
                    VStack(spacing: 6) {
                        Text(verbatim: p.name)
                            .font(.title3.weight(.semibold))
                            .multilineTextAlignment(.center)
                        HStack(spacing: 8) {
                            ProtocolBadge(text: p.badge)
                            if !p.runsOnThisPlatform {
                                Text(L("profile.unsupported")).font(.caption).foregroundStyle(.orange)
                            }
                        }
                    }
                }
                .buttonStyle(.plain)
                .accessibilityHint(L("connect.profile.hint"))
            } else {
                Text(L("connect.noprofile")).font(.title3).foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
        }
    }

    private var connectButton: some View {
        Button(action: model.connectButtonTapped) {
            ZStack {
                Circle().fill(buttonColor.gradient)
                Circle().stroke(.primary.opacity(0.12), lineWidth: 2)
                if model.connection == .connecting || model.connection == .disconnecting {
                    ProgressView().controlSize(.large).tint(.white)
                } else {
                    Image(systemName: "power")
                        .font(.system(size: buttonSize * 0.38, weight: .semibold))
                        .foregroundStyle(.white)
                }
            }
            .frame(width: buttonSize, height: buttonSize)
            .shadow(color: buttonColor.opacity(0.35), radius: 16, y: 6)
        }
        .buttonStyle(.plain)
        .disabled(model.connection == .disconnecting || model.selectedProfile == nil && !model.connection.isActive)
        .accessibilityLabel(model.connection.isActive ? L("connect.button.disconnect") : L("connect.button.connect"))
        .accessibilityValue(L(model.connection.statusKey))
    }

    private var buttonColor: Color {
        switch model.connection {
        case .disconnected: return .gray
        case .connecting, .disconnecting: return .orange
        case .connected: return .green
        case .failed: return .red
        }
    }

    @ViewBuilder
    private var statusBlock: some View {
        VStack(spacing: 10) {
            Text(L(model.connection.statusKey))
                .font(.title2.weight(.semibold))
                .foregroundStyle(model.connection == .disconnected ? .secondary : .primary)
            switch model.connection {
            case .connected(let since):
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    Text(verbatim: ElapsedFormatter.string(from: since, to: context.date, persianDigits: uiIsPersian))
                        .font(.system(.title3, design: .monospaced))
                        .monospacedDigit()
                        .accessibilityLabel(L("connect.timer.label"))
                }
                if model.connectedWithInsecureTLS {
                    Label(L("connect.insecuretls"), systemImage: "exclamationmark.shield")
                        .font(.footnote)
                        .foregroundStyle(.orange)
                        .multilineTextAlignment(.center)
                }
            case .failed(let kind):
                failureBlock(kind)
            default:
                EmptyView()
            }
        }
        .accessibilityElement(children: .contain)
    }

    private func failureBlock(_ kind: FailureKind) -> some View {
        VStack(spacing: 10) {
            Text(L(kind.titleKey)).font(.headline).multilineTextAlignment(.center)
            Text(L(kind.messageKey)).font(.callout).foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            if kind.retryMakesSense {
                Button(L("common.retry"), action: model.connect)
                    .buttonStyle(.borderedProminent)
            } else if kind == .noProfile {
                Button(L("profiles.add"), action: { model.showFileImporter = true })
                    .buttonStyle(.borderedProminent)
            } else {
                Button(L("connect.choose.other"), action: onShowProfiles)
                    .buttonStyle(.bordered)
            }
        }
        .padding(.horizontal)
    }
}

struct ProtocolBadge: View {
    let text: String

    var body: some View {
        Text(verbatim: text)
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(Color.accentColor.opacity(0.15), in: Capsule())
            .foregroundStyle(Color.accentColor)
            .accessibilityLabel(L("profile.protocol.label", text))
    }
}

extension AppModel {
    func showAdvancedTapped() { showAdvanced = true }
}
