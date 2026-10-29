import SwiftUI

struct ContentView: View {
    @EnvironmentObject var store: Store
    @State private var showSettings = false
    @State private var showLogs = false
    @State private var showAdd = false
    @State private var newName = ""
    @State private var openDevice: Device?

    var body: some View {
        NavigationStack {
            List {
                serverSection
                if store.running { statsSection }
                devicesSection
                helpSection
            }
            .navigationTitle("Hotspot WG")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button { showLogs = true } label: { Image(systemName: "doc.text.magnifyingglass") }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button { showSettings = true } label: { Image(systemName: "gearshape") }
                }
            }
            .sheet(isPresented: $showSettings) { SettingsView(settings: store.state.settings) }
            .sheet(isPresented: $showLogs) { LogView() }
            .sheet(item: $openDevice) { d in DeviceView(device: d) }
            .alert("Add device", isPresented: $showAdd) {
                TextField("Name (e.g. laptop)", text: $newName)
                Button("Add") {
                    if let d = store.addDevice(name: newName) { openDevice = d }
                    newName = ""
                }
                Button("Cancel", role: .cancel) { newName = "" }
            } message: {
                Text("Each device gets its own WireGuard config.")
            }
        }
    }

    private var serverSection: some View {
        Section {
            HStack {
                Circle()
                    .fill(store.running ? Color.green : Color.secondary)
                    .frame(width: 12, height: 12)
                Text(store.running ? "Running" : "Stopped").font(.headline)
                Spacer()
                if store.busy {
                    ProgressView()
                } else {
                    Button(store.running ? "Stop" : "Start") {
                        if store.running { store.stop() } else { store.start() }
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(store.running ? .red : .green)
                }
            }
            let net = store.status.net
            LabeledContent("Hotspot", value: net.hotspotIp.isEmpty ? "Not on (turn on Personal Hotspot)" : net.hotspotIp)
            LabeledContent("Cellular", value: net.cellularIf.isEmpty ? "Not found" : "\(net.cellularIf)  \(net.cellularIp)")
            if net.vpnActive {
                LabeledContent("Phone VPN", value: "\(net.vpnIf) — traffic goes through it")
            }
            if store.running {
                LabeledContent("Listening", value: "\(store.endpointHost):\(store.state.settings.listenPort) UDP")
                LabeledContent("Traffic exits via", value: store.status.egressIf)
            }
            if let err = store.lastError {
                Text(err).foregroundStyle(.red).font(.footnote)
            }
        }
    }

    private var statsSection: some View {
        Section("Traffic") {
            LabeledContent("Down / Up", value: "\(formatBytes(store.status.bytesDown)) / \(formatBytes(store.status.bytesUp))")
            LabeledContent("TCP connections", value: "\(store.status.tcpActive) open, \(store.status.tcpTotal) total")
            LabeledContent("UDP flows", value: "\(store.status.udpFlows)")
        }
    }

    private var devicesSection: some View {
        Section {
            ForEach(store.state.devices) { d in
                Button { openDevice = d } label: { DeviceRow(device: d) }
                    .foregroundStyle(.primary)
            }
            .onDelete { store.removeDevices(at: $0) }
            Button { showAdd = true } label: { Label("Add device", systemImage: "plus.circle") }
        } header: {
            Text("Devices")
        } footer: {
            Text("Swipe left to remove a device.")
        }
    }

    private var helpSection: some View {
        Section("How to connect") {
            Text("1. Turn on Personal Hotspot and Start here.")
            Text("2. iPhone/iPad: install WireGuard, tap + → Create from QR code, scan the device's QR.")
            if store.state.settings.webPageEnabled {
                Text("3. Laptop: install WireGuard, join the hotspot, open http://\(store.endpointHost):\(store.state.settings.webPort) and download its .conf, then Import tunnel from file.")
            } else {
                Text("3. Laptop: install WireGuard and import the .conf shared from the device screen.")
            }
            Text("4. Activate the tunnel. Everything — games included — now leaves through the phone's cellular IP.")
        }
        .font(.footnote)
    }
}

struct DeviceRow: View {
    @EnvironmentObject var store: Store
    let device: Device

    var body: some View {
        let ps = store.peerStatus(for: device)
        let online = (ps?.lastHandshake ?? 0) > Int64(Date().timeIntervalSince1970) - 180
        HStack {
            Image(systemName: online ? "checkmark.circle.fill" : "circle")
                .foregroundStyle(online ? .green : .secondary)
            VStack(alignment: .leading) {
                Text(device.name).font(.body)
                Text(device.address).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if let ps = ps, ps.lastHandshake > 0 {
                VStack(alignment: .trailing) {
                    Text("↓\(formatBytes(ps.txBytes)) ↑\(formatBytes(ps.rxBytes))").font(.caption)
                    Text(formatAgo(ps.lastHandshake)).font(.caption2).foregroundStyle(.secondary)
                }
            }
            Image(systemName: "qrcode").foregroundStyle(.secondary)
        }
    }
}

struct LogView: View {
    @EnvironmentObject var store: Store
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                Text(store.logs.isEmpty ? "No log yet." : store.logs)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
            }
            .navigationTitle("Log")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button { UIPasteboard.general.string = store.logs } label: { Image(systemName: "doc.on.doc") }
                }
                ToolbarItem(placement: .topBarTrailing) { Button("Done") { dismiss() } }
            }
        }
    }
}
