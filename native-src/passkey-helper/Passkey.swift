import AppKit
import AuthenticationServices
import CryptoKit
import Foundation

// One assertion per process. Public request metadata enters on stdin; the PRF
// result goes only to the parent through stdout. No files or browser callback.
private let relyingParty = "ve7jtb.github.io"
private func b64(_ value: Data) -> String {
    value.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
}
private func decode(_ value: Any?) throws -> Data {
    guard let text = value as? String, text.count <= 8192,
          text.range(of: "^[A-Za-z0-9_-]*$", options: .regularExpression) != nil,
          let data = Data(base64Encoded: text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/") + String(repeating: "=", count: (4 - text.count % 4) % 4)),
          b64(data) == text else { throw Failure.invalidRequest }
    return data
}
private enum Failure: Error { case invalidRequest }
private struct Request {
    let challenge: Data
    let salt: Data
    let credential: Data?
    let name: String
    let platform: Bool
    init(_ input: Data) throws {
        guard input.count <= 32768,
              let object = try JSONSerialization.jsonObject(with: input) as? [String: Any],
              object["rp"] as? String == relyingParty,
              object["operation"] as? String == "assert",
              let name = object["name"] as? String, name.count <= 80,
              !name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              let provider = object["provider"] as? String,
              ["security-key", "platform"].contains(provider) else { throw Failure.invalidRequest }
        challenge = try decode(object["challenge"])
        salt = try decode(object["salt"])
        credential = object["credential"] == nil ? nil : try decode(object["credential"])
        guard challenge.count == 32, salt.count == 32,
              credential == nil || (1...2048).contains(credential!.count) else { throw Failure.invalidRequest }
        self.name = name
        platform = provider == "platform"
    }
}

@available(macOS 26.4, *)
private final class PasskeyApp: NSObject, NSApplicationDelegate, ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {
    private let request: Request
    private var window: NSWindow!
    private var controller: ASAuthorizationController?
    init(_ request: Request) { self.request = request }
    func applicationDidFinishLaunching(_ notification: Notification) {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 450, height: 130), styleMask: [.titled], backing: .buffered, defer: false)
        window.title = "PQ Mail — unlock with passkey"
        let label = NSTextField(wrappingLabelWithString: "Use your existing PQ Mail passkey: \(request.name)\nApprove the macOS passkey prompt. No new credential will be created.")
        label.frame = NSRect(x: 24, y: 25, width: 402, height: 80)
        window.contentView?.addSubview(label)
        window.center(); window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        // AuthenticationServices performs WebAuthn's PRF input processing.
        // Supply the same raw input as navigator.credentials.get, not a hash.
        let input = ASAuthorizationPublicKeyCredentialPRFAssertionInput.inputValues(.init(saltInput1: request.salt))
        let authorization: ASAuthorizationRequest
        if request.platform {
            let r = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: relyingParty).createCredentialAssertionRequest(challenge: request.challenge)
            r.userVerificationPreference = .required
            r.prf = input
            if let id = request.credential { r.allowedCredentials = [.init(credentialID: id)] }
            authorization = r
        } else {
            let r = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: relyingParty).createCredentialAssertionRequest(challenge: request.challenge)
            r.userVerificationPreference = .required
            r.prf = input
            if let id = request.credential { r.allowedCredentials = [.init(credentialID: id, transports: [.usb])] }
            authorization = r
        }
        controller = ASAuthorizationController(authorizationRequests: [authorization])
        controller?.delegate = self
        controller?.presentationContextProvider = self
        controller?.performRequests()
        DispatchQueue.main.asyncAfter(deadline: .now() + 290) { self.fail("Native passkey operation timed out", code: 2) }
    }
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor { window }
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        let assertion: any ASAuthorizationPublicKeyCredentialAssertion
        let output: ASAuthorizationPublicKeyCredentialPRFAssertionOutput?
        if let result = authorization.credential as? ASAuthorizationSecurityKeyPublicKeyCredentialAssertion {
            assertion = result; output = result.prf
        } else if let result = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion {
            assertion = result; output = result.prf
        } else { fail("Expected a passkey assertion", code: 3); return }
        guard let output else { fail("Selected passkey did not return PRF output; vault remains locked", code: 4); return }
        var secret = output.first.withUnsafeBytes { Data($0) }
        guard secret.count == 32, request.credential == nil || assertion.credentialID == request.credential else { fail("Unexpected passkey result", code: 5); return }
        let response: [String: Any] = ["type": "public-key", "rawId": b64(assertion.credentialID), "response": ["authenticatorData": b64(assertion.rawAuthenticatorData), "clientDataJSON": b64(assertion.rawClientDataJSON), "signature": b64(assertion.signature), "userHandle": b64(assertion.userID)], "clientExtensionResults": ["prf": ["results": ["first": b64(secret)]]]]
        guard let bytes = try? JSONSerialization.data(withJSONObject: response) else { fail("Cannot encode passkey result", code: 6); return }
        FileHandle.standardOutput.write(bytes)
        secret.resetBytes(in: 0..<secret.count)
        exit(0)
    }
    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        let e = error as NSError
        // Only a bounded code/domain, never credential material or a full response.
        fail("AuthenticationServices failed (\(e.domain.prefix(100)), code \(e.code)); no browser fallback was started", code: 7)
    }
    private func fail(_ message: String, code: Int32) {
        if let data = try? JSONSerialization.data(withJSONObject: ["error": message]) { FileHandle.standardOutput.write(data) }
        exit(code)
    }
}

@main
private enum Main {
static func main() {
do {
    if CommandLine.arguments.contains("--self-test") {
        let valid: [String: Any] = ["operation": "assert", "rp": relyingParty, "name": "Synthetic test", "provider": "security-key", "challenge": b64(Data(repeating: 1, count: 32)), "salt": b64(Data(repeating: 2, count: 32)), "credential": b64(Data([1, 2, 3]))]
        _ = try Request(JSONSerialization.data(withJSONObject: valid))
        for key in ["rp", "operation", "salt", "challenge", "provider", "credential"] {
            var invalid = valid; invalid[key] = "invalid!"
            do { _ = try Request(JSONSerialization.data(withJSONObject: invalid)); exit(10) } catch {}
        }
        print("PASS native assertion request validation; no authenticator accessed")
        exit(0)
    }
    guard #available(macOS 26.4, *) else { throw Failure.invalidRequest }
    var data = Data()
    while let chunk = try FileHandle.standardInput.read(upToCount: 32769 - data.count), !chunk.isEmpty {
        data.append(chunk)
        guard data.count <= 32768 else { throw Failure.invalidRequest }
    }
    let app = NSApplication.shared
    let delegate = try PasskeyApp(Request(data))
    app.setActivationPolicy(.accessory)
    app.delegate = delegate
    app.run()
} catch {
    FileHandle.standardOutput.write(Data("{\"error\":\"Invalid native passkey request or unsupported macOS; no credential operation performed\"}".utf8))
    exit(1)
}

}
}
