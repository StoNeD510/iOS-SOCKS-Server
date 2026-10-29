import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var store: Store
    @Environment(\.dismiss) private var dismiss
    @State var settings: AppSettings

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Toggle("Send traffic out cellular only", isOn: $settings.bindCellular)
                } footer: {
                    Text("Pins outgoing connections to the cellular interface (pdp_ip). If a VPN is running on the phone, traffic follows the VPN instead.")
                }
                Section("WireGuard") {
                    Stepper("UDP port \(settings.listenPort)", value: $settings.listenPort, in: 1024...65535)
                    TextField("Upstream DNS", text: $settings.dns)
                        .keyboardType(.numbersAndPunctuation)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                }
                Section {
                    Toggle("Config download page", isOn: $settings.webPageEnabled)
                    if settings.webPageEnabled {
                        Stepper("Port \(settings.webPort)", value: $settings.webPort, in: 1024...65535)
                    }
                } footer: {
                    Text("Lets a laptop on the hotspot download its .conf from a browser. Anyone on your hotspot can open it.")
                }
                Section {
                    Toggle("Extra keep-alive (location)", isOn: $settings.locationKeepAlive)
                    Toggle("Start when app opens", isOn: $settings.autoStart)
                } header: {
                    Text("Background")
                } footer: {
                    Text("Silent audio keeps the server alive in the background. Location adds a second signal at a small battery cost.")
                }
                Section {
                    Text(store.serverPublicKey)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                } header: {
                    Text("Server public key")
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Save") {
                        store.updateSettings(settings)
                        dismiss()
                    }
                }
            }
        }
    }
}
