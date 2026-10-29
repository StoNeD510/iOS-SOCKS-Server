import CoreImage
import CoreImage.CIFilterBuiltins
import SwiftUI
import UIKit

struct DeviceView: View {
    @EnvironmentObject var store: Store
    @Environment(\.dismiss) private var dismiss
    let device: Device
    @State private var name = ""
    @State private var copied = false

    var body: some View {
        let conf = store.clientConfig(for: device)
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    if let img = qrImage(conf) {
                        Image(uiImage: img)
                            .interpolation(.none)
                            .resizable()
                            .scaledToFit()
                            .frame(maxWidth: 320)
                            .padding(12)
                            .background(Color.white)
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                    }
                    Text("Scan with the WireGuard app: + → Create from QR code")
                        .font(.footnote).foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)

                    if let url = confFileURL(conf) {
                        ShareLink(item: url) {
                            Label("Share .conf file", systemImage: "square.and.arrow.up")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                    }
                    Button {
                        UIPasteboard.general.string = conf
                        copied = true
                    } label: {
                        Label(copied ? "Copied" : "Copy config text", systemImage: "doc.on.doc")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)

                    if store.state.settings.webPageEnabled {
                        Text("Laptop: open http://\(store.endpointHost):\(store.state.settings.webPort) while on the hotspot and download “\(device.name).conf”.")
                            .font(.footnote)
                            .multilineTextAlignment(.center)
                    }

                    TextField("Name", text: $name)
                        .textFieldStyle(.roundedBorder)
                        .onSubmit { if !name.isEmpty { store.rename(device, to: name) } }

                    Text(conf)
                        .font(.system(.caption2, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(8)
                        .background(Color(.secondarySystemBackground))
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                }
                .padding()
            }
            .navigationTitle(device.name)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") {
                        if !name.isEmpty && name != device.name { store.rename(device, to: name) }
                        dismiss()
                    }
                }
            }
            .onAppear { name = device.name }
        }
    }

    private func qrImage(_ text: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let out = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 8, y: 8)) else { return nil }
        guard let cg = CIContext().createCGImage(out, from: out.extent) else { return nil }
        return UIImage(cgImage: cg)
    }

    private func confFileURL(_ conf: String) -> URL? {
        let safe = device.name.filter { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" }
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent((safe.isEmpty ? "device" : String(safe.prefix(32))) + ".conf")
        do {
            try conf.write(to: url, atomically: true, encoding: .utf8)
            return url
        } catch {
            return nil
        }
    }
}
