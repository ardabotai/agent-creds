import SwiftUI
import AVFoundation

struct PairingScanner: View {
    let received: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var authorized: Bool?
    var body: some View {
        NavigationStack {
            VStack(spacing: 24) {
                Text("Scan your Mac’s code").font(.title2.bold())
                Text("On your Mac: agent-creds menu → Pair iPhone. Only scan a code shown on your own Mac.").multilineTextAlignment(.center).foregroundStyle(.secondary)
                if authorized == true { CameraPreview(received: received).clipShape(RoundedRectangle(cornerRadius: 24)).frame(maxHeight: 440) }
                else if authorized == false { ContentUnavailableView("Camera access needed", systemImage: "camera", description: Text("Allow Camera in Settings, or enter a pairing code instead.")) }
                else { ProgressView() }
                Spacer()
            }.padding(24).toolbar { Button("Cancel") { dismiss() } }
                .task { authorized = await AVCaptureDevice.requestAccess(for: .video) }
        }
    }
}

private struct CameraPreview: UIViewControllerRepresentable {
    var received: (String) -> Void
    func makeUIViewController(context: Context) -> ScannerController { ScannerController(received: received) }
    func updateUIViewController(_ controller: ScannerController, context: Context) {}
    static func dismantleUIViewController(_ controller: ScannerController, coordinator: ()) { controller.stop() }
}

private final class ScannerController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    private let session = AVCaptureSession()
    private let cameraQueue = DispatchQueue(label: "agentcreds.camera")
    private var preview: AVCaptureVideoPreviewLayer?
    private let received: (String) -> Void
    private var delivered = false
    init(received: @escaping (String) -> Void) { self.received = received; super.init(nibName: nil, bundle: nil) }
    required init?(coder: NSCoder) { fatalError() }
    override func viewDidLoad() {
        super.viewDidLoad()
        guard let camera = AVCaptureDevice.default(for: .video), let input = try? AVCaptureDeviceInput(device: camera), session.canAddInput(input) else { return }
        session.addInput(input)
        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { return }
        session.addOutput(output); output.setMetadataObjectsDelegate(self, queue: .main); output.metadataObjectTypes = [.qr]
        let preview = AVCaptureVideoPreviewLayer(session: session); preview.videoGravity = .resizeAspectFill
        view.layer.addSublayer(preview); self.preview = preview
        cameraQueue.async { self.session.startRunning() }
    }
    override func viewDidLayoutSubviews() { super.viewDidLayoutSubviews(); preview?.frame = view.bounds }
    func stop() { cameraQueue.async { self.session.stopRunning() } }
    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
        guard !delivered, let code = (metadataObjects.first as? AVMetadataMachineReadableCodeObject)?.stringValue else { return }
        delivered = true; stop(); received(code)
    }
}
