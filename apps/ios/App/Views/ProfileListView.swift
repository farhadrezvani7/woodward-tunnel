import SwiftUI

struct ProfileListView: View {
    @EnvironmentObject private var model: AppModel
    let onPick: () -> Void

    @State private var renaming: ProfileItem?
    @State private var renameDraft = ""
    @State private var grouping: ProfileItem?
    @State private var deleting: ProfileItem?

    var body: some View {
        Group {
            if model.profiles.isEmpty {
                EmptyProfilesView()
            } else {
                list
            }
        }
        .navigationTitle(L("profiles.title"))
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) { AddProfileMenu() }
        }
        .overlay { if model.isWorking { ProgressView().controlSize(.large) } }
        .alert(L("rename.title"), isPresented: Binding(get: { renaming != nil }, set: { if !$0 { renaming = nil } })) {
            TextField(L("rename.placeholder"), text: $renameDraft)
            Button(L("common.save")) {
                if let p = renaming { model.rename(p, to: renameDraft) }
                renaming = nil
            }
            Button(L("common.cancel"), role: .cancel) { renaming = nil }
        }
        .sheet(item: $grouping) { p in
            GroupSheet(profile: p)
        }
        .confirmationDialog(
            L("delete.title"),
            isPresented: Binding(get: { deleting != nil }, set: { if !$0 { deleting = nil } }),
            titleVisibility: .visible
        ) {
            Button(L("common.delete"), role: .destructive) {
                if let p = deleting { model.delete(p) }
                deleting = nil
            }
            Button(L("common.cancel"), role: .cancel) { deleting = nil }
        } message: {
            Text(verbatim: L("delete.message", deleting?.name ?? ""))
        }
    }

    private var list: some View {
        List(selection: Binding(get: { model.selectedID }, set: { id in
            model.selectedID = id
            if id != nil { onPick() }
        })) {
            ForEach(ProfileGrouping.sections(model.profiles)) { section in
                Section(section.title.isEmpty ? L("profiles.ungrouped") : section.title) {
                    ForEach(section.items) { profile in
                        ProfileRow(profile: profile)
                            .tag(profile.id)
                            .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                                Button(role: .destructive) { deleting = profile } label: {
                                    Label(L("common.delete"), systemImage: "trash")
                                }
                            }
                            .swipeActions(edge: .leading) {
                                Button { beginRename(profile) } label: {
                                    Label(L("rename.action"), systemImage: "pencil")
                                }
                                .tint(.blue)
                            }
                            .contextMenu {
                                Button { beginRename(profile) } label: {
                                    Label(L("rename.action"), systemImage: "pencil")
                                }
                                Button { grouping = profile } label: {
                                    Label(L("group.action"), systemImage: "folder")
                                }
                                Button(role: .destructive) { deleting = profile } label: {
                                    Label(L("common.delete"), systemImage: "trash")
                                }
                            }
                            .accessibilityAction(named: L("rename.action")) { beginRename(profile) }
                            .accessibilityAction(named: L("group.action")) { grouping = profile }
                            .accessibilityAction(named: L("common.delete")) { deleting = profile }
                    }
                }
            }
        }
    }

    private func beginRename(_ p: ProfileItem) {
        renameDraft = p.name
        renaming = p
    }
}

struct ProfileRow: View {
    let profile: ProfileItem

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 3) {
                Text(verbatim: profile.name).font(.body)
                if !profile.endpointText.isEmpty {
                    Text(verbatim: profile.endpointText)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .environment(\.layoutDirection, .leftToRight)
                }
                if !profile.runsOnThisPlatform {
                    Text(L("profile.unsupported")).font(.caption).foregroundStyle(.orange)
                }
            }
            Spacer()
            ProtocolBadge(text: profile.badge)
        }
        .accessibilityElement(children: .combine)
    }
}

struct EmptyProfilesView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ContentUnavailableView {
            Label(L("profiles.empty.title"), systemImage: "tray")
        } description: {
            Text(L("profiles.empty.message"))
        } actions: {
            Button(L("add.file")) { model.showFileImporter = true }
                .buttonStyle(.borderedProminent)
            Button(L("add.paste")) { model.importFromClipboard() }
                .buttonStyle(.bordered)
            Button(L("add.qr")) { model.showScanner = true }
                .buttonStyle(.bordered)
        }
    }
}

struct AddProfileMenu: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Menu {
            Button { model.showFileImporter = true } label: { Label(L("add.file"), systemImage: "doc") }
            Button { model.showScanner = true } label: { Label(L("add.qr"), systemImage: "qrcode.viewfinder") }
            Button { model.showPhotoPicker = true } label: { Label(L("add.photo"), systemImage: "photo") }
            Button { model.importFromClipboard() } label: { Label(L("add.paste"), systemImage: "doc.on.clipboard") }
        } label: {
            Image(systemName: "plus")
        }
        .accessibilityLabel(L("profiles.add"))
    }
}

struct GroupSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let profile: ProfileItem
    @State private var newGroup = ""

    var body: some View {
        NavigationStack {
            Form {
                Section(L("group.existing")) {
                    Button(L("profiles.ungrouped")) { choose("") }
                    ForEach(ProfileGrouping.groupNames(model.profiles), id: \.self) { name in
                        Button(name) { choose(name) }
                    }
                }
                Section(L("group.new")) {
                    TextField(L("group.new.placeholder"), text: $newGroup)
                    Button(L("common.save")) { choose(newGroup) }
                        .disabled(newGroup.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
            .navigationTitle(L("group.title"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(L("common.cancel")) { dismiss() } }
            }
        }
        .presentationDetents([.medium, .large])
    }

    private func choose(_ name: String) {
        model.setGroup(profile, to: name)
        dismiss()
    }
}
