import SwiftUI
import PQMailCore
import YubiKit

@main struct PQMailApp: App {
    var body: some Scene { WindowGroup { TabView { LocalMailView().tabItem { Label("Mail", systemImage: "envelope") }; ContentView().tabItem { Label("YubiKey", systemImage: "key") } } } }
}
struct ContentView: View {
    @State private var profile = Profile.level3
    @State private var hybrid = true
    @State private var result = "No YubiKey checked."
    @State private var busy = false
    var body: some View {
        NavigationStack {
            Form {
                Section("iOS development preview") {
                    Text("Read-only YubiKey diagnostics. Select saved software or YubiKey credentials in the Mail tab for S/MIME and supported OpenPGP signing/decryption. Physical YubiKey testing is still required.")
                }
                Section("Pure and hybrid profiles") {
                    Picker("Level", selection: $profile) { ForEach(Profile.allCases) { Text("Level \($0.rawValue)").tag($0) } }
                    Toggle("Hybrid", isOn: $hybrid)
                    LabeledContent("Signing", value: hybrid ? profile.hybridSigningName : profile.mlDSA)
                    LabeledContent("Encryption", value: hybrid ? profile.hybridEncryptionName : profile.mlKEM)
                    Text("Each YubiKey profile uses four keys: ML-DSA, ECDSA, ML-KEM and ECDH. Software .p12 identities are managed separately in the Mail tab.").font(.footnote)
                }
                Section("Check existing YubiKey") {
                    Button("Read over NFC") { probe(nfc: true) }.disabled(busy)
                    Button("Read over USB-C") { probe(nfc: false) }.disabled(busy)
                    Text("No PIN required. No key generation or certificate changes. Keep the key connected until the check finishes.").font(.footnote)
                    Text(result).textSelection(.enabled)
                }
            }.navigationTitle("PQ Mail")
        }
    }
    @MainActor private func probe(nfc: Bool) {
        busy = true
        result = nfc ? "Hold your YubiKey near the iPhone and keep it there." : "Connect your YubiKey over USB-C."
        Task {
            do {
                let connection: any SmartCardConnection
                if nfc { connection = try await NFCSmartCardConnection() }
                else { connection = try await USBSmartCardConnection() }
                let report = try await YubiKeyProbe.inspect(connection)
                result = "YubiKey \(report.serial) · firmware \(report.firmware)\n" + report.metadataBytes.sorted { $0.key < $1.key }.map { String(format: "Slot %02X: %d metadata bytes", $0.key, $0.value) }.joined(separator: "\n") + "\nRead complete. You can remove your YubiKey.\nThis checks connectivity, not signing or decryption."
            } catch { result = "Read ended: \(error.localizedDescription)\nYou can remove your YubiKey." }
            busy = false
        }
    }
}
