import Foundation
import SwiftUI
import WGCore

// MARK: - Persisted model

struct Device: Codable, Identifiable, Hashable {
    var id = UUID()
    var name: String
    var privateKey: String
    var publicKey: String
    var address: String
}

struct AppSettings: Codable, Equatable {
    var listenPort: Int = 51820
    var bindCellular: Bool = true
    var dns: String = "1.1.1.1, 8.8.8.8"
    var webPageEnabled: Bool = true
    var webPort: Int = 8080
    var locationKeepAlive: Bool = false
    var autoStart: Bool = false
}

struct PersistedState: Codable {
    var serverPrivateKey: String
    var devices: [Device] = []
    var settings = AppSettings()
}

// MARK: - Status decoded from the Go core

struct NetInfo: Codable {
    var hotspotIp: String = ""
    var cellularIf: String = ""
    var cellularIp: String = ""
    var wifiIp: String = ""
    var vpnActive: Bool = false
    var vpnIf: String = ""
    var defaultIf: String = ""
}

struct PeerStatus: Codable {
    var name: String = ""
    var publicKey: String = ""
    var address: String = ""
    var endpoint: String = ""
    var lastHandshake: Int64 = 0
    var rxBytes: Int64 = 0
    var txBytes: Int64 = 0
}

struct CoreStatus: Codable {
    var running: Bool = false
    var listenPort: Int = 0
    var net: NetInfo = NetInfo()
    var egressIf: String = ""
    var tcpActive: Int64 = 0
    var tcpTotal: Int64 = 0
    var udpFlows: Int = 0
    var bytesUp: Int64 = 0
    var bytesDown: Int64 = 0
    var uptime: Int64 = 0
    var webError: String = ""
    var peers: [PeerStatus]? = nil
}

// MARK: - Store

@MainActor
final class Store: ObservableObject {
    @Published var state: PersistedState
    @Published var status = CoreStatus()
    @Published var running = false
    @Published var busy = false
    @Published var lastError: String?
    @Published var logs = ""
    @Published var rateDown: Int64 = 0 // bytes/s through the tunnel
    @Published var rateUp: Int64 = 0
    private var lastSample: (date: Date, down: Int64, up: Int64)?

    let keepAlive = KeepAlive()
    private var timer: Timer?
    private var bonjour: NetService?

    private static var fileURL: URL {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("hotspotwg.json")
    }

    init() {
        if let data = try? Data(contentsOf: Store.fileURL),
           let s = try? JSONDecoder().decode(PersistedState.self, from: data),
           !WgcorePublicKey(s.serverPrivateKey).isEmpty {
            state = s
        } else {
            state = PersistedState(serverPrivateKey: WgcoreGeneratePrivateKey())
        }
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
        if state.settings.autoStart {
            start()
        }
    }

    var serverPublicKey: String { WgcorePublicKey(state.serverPrivateKey) }

    /// The address clients reach the phone on (Personal Hotspot bridge).
    var endpointHost: String {
        status.net.hotspotIp.isEmpty ? "172.20.10.1" : status.net.hotspotIp
    }

    func save() {
        if let data = try? JSONEncoder().encode(state) {
            try? data.write(to: Store.fileURL, options: .atomic)
        }
    }

    // MARK: Server control

    private func coreConfigJSON() -> String {
        let s = state.settings
        let peers: [[String: Any]] = state.devices.map {
            ["name": $0.name, "public_key": $0.publicKey, "private_key": $0.privateKey, "address": $0.address]
        }
        let dns = s.dns.split(whereSeparator: { $0 == "," || $0 == " " }).map(String.init).filter { !$0.isEmpty }
        let cfg: [String: Any] = [
            "private_key": state.serverPrivateKey,
            "listen_port": s.listenPort,
            "bind_cellular": s.bindCellular,
            "dns": dns,
            "web_port": s.webPageEnabled ? s.webPort : 0,
            "peers": peers,
        ]
        let data = (try? JSONSerialization.data(withJSONObject: cfg)) ?? Data()
        return String(data: data, encoding: .utf8) ?? "{}"
    }

    func start() {
        guard !busy else { return }
        busy = true
        lastError = nil
        let json = coreConfigJSON()
        let useLocation = state.settings.locationKeepAlive
        DispatchQueue.global(qos: .userInitiated).async {
            var err: NSError?
            let ok = WgcoreStart(json, &err)
            DispatchQueue.main.async {
                self.busy = false
                if ok {
                    self.keepAlive.start(useLocation: useLocation)
                    self.advertise()
                } else {
                    self.lastError = err?.localizedDescription ?? "Failed to start"
                }
                self.refresh()
            }
        }
    }

    func stop() {
        WgcoreStop()
        keepAlive.stop()
        bonjour?.stop()
        bonjour = nil
        refresh()
    }

    func restartIfRunning() {
        if WgcoreRunning() {
            WgcoreStop()
            start()
        }
    }

    /// Publishing a Bonjour service makes iOS show the Local Network
    /// permission prompt, which is needed for hotspot clients to reach us.
    private func advertise() {
        guard bonjour == nil else { return }
        let svc = NetService(domain: "local.", type: "_hotspotwg._udp.", name: "HotspotWG", port: Int32(state.settings.listenPort))
        svc.publish()
        bonjour = svc
    }

    func refresh() {
        running = WgcoreRunning()
        let json = WgcoreStatusJSON()
        let dec = JSONDecoder()
        dec.keyDecodingStrategy = .convertFromSnakeCase
        if let data = json.data(using: .utf8), let st = try? dec.decode(CoreStatus.self, from: data) {
            status = st
            let now = Date()
            if st.running, let last = lastSample, now.timeIntervalSince(last.date) > 0.5 {
                let dt = now.timeIntervalSince(last.date)
                rateDown = max(0, Int64(Double(st.bytesDown - last.down) / dt))
                rateUp = max(0, Int64(Double(st.bytesUp - last.up) / dt))
            } else if !st.running {
                rateDown = 0
                rateUp = 0
            }
            lastSample = (now, st.bytesDown, st.bytesUp)
        }
        logs = WgcoreLogs()
    }

    // MARK: Devices

    private func pushPeers() {
        save()
        guard WgcoreRunning() else { return }
        let peers: [[String: Any]] = state.devices.map {
            ["name": $0.name, "public_key": $0.publicKey, "private_key": $0.privateKey, "address": $0.address]
        }
        if let data = try? JSONSerialization.data(withJSONObject: peers),
           let json = String(data: data, encoding: .utf8) {
            var err: NSError?
            if !WgcoreSetPeers(json, &err) {
                lastError = err?.localizedDescription
            }
        }
    }

    @discardableResult
    func addDevice(name: String) -> Device? {
        let used = Set(state.devices.map(\.address))
        guard let host = (2...254).first(where: { !used.contains("10.66.66.\($0)") }) else {
            lastError = "Device limit reached"
            return nil
        }
        let priv = WgcoreGeneratePrivateKey()
        let trimmed = name.trimmingCharacters(in: .whitespaces)
        let d = Device(name: trimmed.isEmpty ? "device\(host)" : trimmed,
                       privateKey: priv, publicKey: WgcorePublicKey(priv),
                       address: "10.66.66.\(host)")
        state.devices.append(d)
        pushPeers()
        return d
    }

    func removeDevices(at offsets: IndexSet) {
        state.devices.remove(atOffsets: offsets)
        pushPeers()
    }

    func rename(_ device: Device, to name: String) {
        guard let i = state.devices.firstIndex(where: { $0.id == device.id }) else { return }
        state.devices[i].name = name
        pushPeers()
    }

    func clientConfig(for d: Device) -> String {
        WgcoreClientConfig(d.privateKey, d.address, serverPublicKey, endpointHost,
                           state.settings.listenPort, "10.66.66.1", 1420)
    }

    func peerStatus(for d: Device) -> PeerStatus? {
        status.peers?.first(where: { $0.publicKey == d.publicKey })
    }

    func updateSettings(_ new: AppSettings) {
        let old = state.settings
        state.settings = new
        save()
        if old != new {
            restartIfRunning()
        }
    }
}

// MARK: - Formatting helpers

func formatBytes(_ b: Int64) -> String {
    ByteCountFormatter.string(fromByteCount: b, countStyle: .binary)
}

func formatAgo(_ unix: Int64) -> String {
    guard unix > 0 else { return "never" }
    let s = Int(Date().timeIntervalSince1970) - Int(unix)
    if s < 5 { return "just now" }
    if s < 60 { return "\(s)s ago" }
    if s < 3600 { return "\(s / 60)m ago" }
    return "\(s / 3600)h ago"
}
