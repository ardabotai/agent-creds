import AppKit
import AuthenticationServices
import CryptoKit
import AgentCredsCore

/// WebAuthn passkey ceremony used to derive the vault's KEK.
///
/// The passkey's PRF extension turns "the user approved" into key material:
/// the authenticator derives a stable 32-byte output from its own secret plus
/// our salt, and only after Touch ID. Nothing else can produce it, so an
/// unapproved release is not blocked by policy — the key simply does not exist
/// in the process.
///
/// Requires a real relying-party domain with an apple-app-site-association file
/// and the associated-domains entitlement, which is why this needs the signed
/// .app bundle produced by scripts/package.sh.
enum PasskeyError: Error, CustomStringConvertible {
    case unsupported(String)
    case failed(String)
    case cancelled
    case noPRF

    var description: String {
        switch self {
        case .unsupported(let detail): return detail
        case .failed(let detail): return "passkey ceremony failed: \(detail)"
        case .cancelled: return "the user cancelled the passkey prompt"
        case .noPRF:
            return "this authenticator did not return a PRF value — it cannot be used to protect the vault"
        }
    }
}

final class PasskeyCeremony: NSObject {
    private var anchorWindow: NSWindow?
    private var continuationHandler: ((Result<ASAuthorization, Error>) -> Void)?
    private var controller: ASAuthorizationController?

    private static func randomChallenge() -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes)
    }

    /// Creates a passkey and confirms the authenticator supports PRF. Blocking.
    func enroll(relyingParty: String, userName: String) throws -> (credentialID: Data, prfSupported: Bool) {
        guard #available(macOS 15.0, *) else {
            throw PasskeyError.unsupported("passkey PRF requires macOS 15 or later")
        }
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
            relyingPartyIdentifier: relyingParty)
        var userID = Data(count: 16)
        userID.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
        let request = provider.createCredentialRegistrationRequest(
            challenge: Self.randomChallenge(), name: userName, userID: userID)
        request.prf = .checkForSupport

        let authorization = try perform([request])
        guard let registration = authorization.credential
                as? ASAuthorizationPlatformPublicKeyCredentialRegistration else {
            throw PasskeyError.failed("unexpected credential type")
        }
        let supported = registration.prf?.isSupported ?? false
        return (registration.credentialID, supported)
    }

    /// Performs an assertion and returns the PRF output. Blocking; prompts.
    func assertPRF(relyingParty: String, credentialID: Data, salt: Data) throws -> SymmetricKey {
        guard #available(macOS 15.0, *) else {
            throw PasskeyError.unsupported("passkey PRF requires macOS 15 or later")
        }
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
            relyingPartyIdentifier: relyingParty)
        let request = provider.createCredentialAssertionRequest(challenge: Self.randomChallenge())
        request.allowedCredentials = [
            ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: credentialID)
        ]
        request.prf = .inputValues(.saltInput1(salt))

        let authorization = try perform([request])
        guard let assertion = authorization.credential
                as? ASAuthorizationPlatformPublicKeyCredentialAssertion else {
            throw PasskeyError.failed("unexpected credential type")
        }
        guard let output = assertion.prf?.first else { throw PasskeyError.noPRF }
        return output
    }

    // MARK: - Blocking bridge

    private func perform(_ requests: [ASAuthorizationRequest]) throws -> ASAuthorization {
        let semaphore = DispatchSemaphore(value: 0)
        var result: Result<ASAuthorization, Error>!
        DispatchQueue.main.async {
            self.continuationHandler = { outcome in
                result = outcome
                semaphore.signal()
            }
            let controller = ASAuthorizationController(authorizationRequests: requests)
            controller.delegate = self
            controller.presentationContextProvider = self
            self.controller = controller
            NSApp.activate(ignoringOtherApps: true)
            controller.performRequests()
        }
        semaphore.wait()
        return try result.get()
    }
}

extension PasskeyCeremony: ASAuthorizationControllerDelegate {
    func authorizationController(controller: ASAuthorizationController,
                                 didCompleteWithAuthorization authorization: ASAuthorization) {
        continuationHandler?(.success(authorization))
        continuationHandler = nil
    }

    func authorizationController(controller: ASAuthorizationController,
                                 didCompleteWithError error: Error) {
        let mapped: Error
        if let asError = error as? ASAuthorizationError, asError.code == .canceled {
            mapped = PasskeyError.cancelled
        } else {
            mapped = PasskeyError.failed(error.localizedDescription)
        }
        continuationHandler?(.failure(mapped))
        continuationHandler = nil
    }
}

extension PasskeyCeremony: ASAuthorizationControllerPresentationContextProviding {
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        // A menubar daemon has no window, but the system sheet needs an anchor.
        if let existing = anchorWindow { return existing }
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1, height: 1),
                              styleMask: [.borderless], backing: .buffered, defer: false)
        window.level = .floating
        window.alphaValue = 0
        window.center()
        window.orderFrontRegardless()
        anchorWindow = window
        return window
    }
}
