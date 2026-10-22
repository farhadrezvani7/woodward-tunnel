import PhotosUI
import SwiftUI
import UniformTypeIdentifiers

struct RootView: View {
    @EnvironmentObject private var model: AppModel
    @State private var preferredColumn: NavigationSplitViewColumn = .detail
    @State private var photoItem: PhotosPickerItem?

    var body: some View {
        Group {
            if let error = model.coreError {
                CoreFailureView(message: error)
            } else {
                NavigationSplitView(preferredCompactColumn: $preferredColumn) {
                    ProfileListView(onPick: { preferredColumn = .detail })
                } detail: {
                    ConnectView(onShowProfiles: { preferredColumn = .sidebar })
                }
            }
        }
        .overlay(alignment: .top) { BannerView() }
        .animation(.default, value: model.banner)
        .fileImporter(isPresented: $model.showFileImporter, allowedContentTypes: [.item], allowsMultipleSelection: false) { result in
            handleFile(result)
        }
        .photosPicker(isPresented: $model.showPhotoPicker, selection: $photoItem, matching: .images)
        .onChange(of: photoItem) { _, item in
            guard let item else { return }
            photoItem = nil
            Task { await handlePhoto(item) }
        }
        .fullScreenCover(isPresented: $model.showScanner) {
            QRScannerScreen { text in
                model.showScanner = false
                model.importText(text)
            }
        }
        .sheet(isPresented: $model.showAdvanced) {
            AdvancedView()
        }
        .confirmationDialog(
            L("sub.ask.title"),
            isPresented: Binding(get: { !model.pendingSubscriptions.isEmpty }, set: { if !$0 { model.declineNextSubscription() } }),
            titleVisibility: .visible
        ) {
            Button(L("sub.ask.download")) { model.confirmNextSubscription() }
            Button(L("common.cancel"), role: .cancel) { model.declineNextSubscription() }
        } message: {
            let host = model.pendingSubscriptions.first.map(SubscriptionDisplay.hostOnly) ?? ""
            Text(verbatim: L("sub.ask.message", host))
        }
    }

    private func handleFile(_ result: Result<[URL], Error>) {
        switch result {
        case .failure(let error):
            model.show(.error, error.localizedDescription)
        case .success(let urls):
            guard let url = urls.first else { return }
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            let size = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
            guard size <= 5 * 1024 * 1024 else {
                model.show(.error, L("import.file.toolarge"))
                return
            }
            do {
                model.importData(try Data(contentsOf: url))
            } catch {
                model.show(.error, L("import.file.unreadable"))
            }
        }
    }

    private func handlePhoto(_ item: PhotosPickerItem) async {
        guard let data = try? await item.loadTransferable(type: Data.self) else {
            model.show(.error, L("import.photo.unreadable"))
            return
        }
        guard let normalized = ImageNormalizer.pngOrJPEG(data) else {
            model.show(.error, L("import.photo.unreadable"))
            return
        }
        model.importData(normalized)
    }
}

/// Shown when the local storage cannot be opened at all.
struct CoreFailureView: View {
    let message: String

    var body: some View {
        ContentUnavailableView {
            Label(L("core.failed.title"), systemImage: "exclamationmark.triangle")
        } description: {
            Text(verbatim: message)
        }
    }
}

struct BannerView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        if let banner = model.banner {
            HStack(spacing: 8) {
                Image(systemName: icon(banner.kind)).accessibilityHidden(true)
                Text(verbatim: banner.text).font(.callout)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
            .background(.regularMaterial, in: Capsule())
            .overlay(Capsule().stroke(color(banner.kind), lineWidth: 1))
            .padding(.top, 8)
            .padding(.horizontal, 16)
            .transition(.move(edge: .top).combined(with: .opacity))
            .onTapGesture { model.banner = nil }
            .accessibilityElement(children: .combine)
        }
    }

    private func icon(_ kind: Banner.Kind) -> String {
        switch kind {
        case .success: return "checkmark.circle.fill"
        case .warning: return "exclamationmark.circle.fill"
        case .error: return "xmark.octagon.fill"
        }
    }

    private func color(_ kind: Banner.Kind) -> Color {
        switch kind {
        case .success: return .green
        case .warning: return .orange
        case .error: return .red
        }
    }
}
