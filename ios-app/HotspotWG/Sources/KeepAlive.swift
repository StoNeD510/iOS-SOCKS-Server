import AVFoundation
import CoreLocation
import Foundation

/// Keeps the app running in the background (same trick as socks5.py):
/// loop a silent audio clip, mixed with other audio, plus optional
/// low-accuracy location updates as a second signal, and a watchdog that
/// restarts playback if anything stops it.
final class KeepAlive: NSObject, CLLocationManagerDelegate {
    private var player: AVAudioPlayer?
    private var watchdog: Timer?
    private var location: CLLocationManager?
    private(set) var active = false

    func start(useLocation: Bool) {
        active = true
        startAudio()
        let nc = NotificationCenter.default
        nc.removeObserver(self)
        nc.addObserver(self, selector: #selector(interrupted(_:)),
                       name: AVAudioSession.interruptionNotification, object: nil)
        nc.addObserver(self, selector: #selector(mediaReset(_:)),
                       name: AVAudioSession.mediaServicesWereResetNotification, object: nil)
        watchdog?.invalidate()
        watchdog = Timer.scheduledTimer(withTimeInterval: 10, repeats: true) { [weak self] _ in
            guard let self = self, self.active else { return }
            if self.player?.isPlaying != true { self.startAudio() }
        }
        if useLocation { startLocation() } else { stopLocation() }
    }

    func stop() {
        active = false
        watchdog?.invalidate()
        watchdog = nil
        player?.stop()
        player = nil
        stopLocation()
        NotificationCenter.default.removeObserver(self)
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
    }

    private func startAudio() {
        let session = AVAudioSession.sharedInstance()
        do {
            try session.setCategory(.playback, mode: .default, options: [.mixWithOthers])
            try session.setActive(true)
            if player == nil {
                player = try AVAudioPlayer(data: KeepAlive.silentWAV())
                player?.numberOfLoops = -1
                player?.volume = 1.0 // the samples are silence
                player?.prepareToPlay()
            }
            player?.play()
        } catch {
            NSLog("KeepAlive audio error: \(error)")
        }
    }

    @objc private func interrupted(_ note: Notification) {
        guard let raw = note.userInfo?[AVAudioSessionInterruptionTypeKey] as? UInt,
              let type = AVAudioSession.InterruptionType(rawValue: raw) else { return }
        if type == .ended && active {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { self.startAudio() }
        }
    }

    @objc private func mediaReset(_ note: Notification) {
        player = nil
        if active { startAudio() }
    }

    private func startLocation() {
        if location == nil {
            let m = CLLocationManager()
            m.delegate = self
            m.desiredAccuracy = kCLLocationAccuracyThreeKilometers
            m.distanceFilter = CLLocationDistanceMax
            m.pausesLocationUpdatesAutomatically = false
            location = m
        }
        location?.requestWhenInUseAuthorization()
        location?.allowsBackgroundLocationUpdates = true
        location?.showsBackgroundLocationIndicator = false
        location?.startUpdatingLocation()
    }

    private func stopLocation() {
        location?.stopUpdatingLocation()
        location = nil
    }

    func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {}
    func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {}

    /// One second of 8 kHz 16-bit mono silence as a WAV file.
    static func silentWAV() -> Data {
        let sampleRate: UInt32 = 8000
        let samples = Int(sampleRate)
        let dataSize = UInt32(samples * 2)
        var d = Data()
        func u32(_ v: UInt32) { var x = v.littleEndian; d.append(Data(bytes: &x, count: 4)) }
        func u16(_ v: UInt16) { var x = v.littleEndian; d.append(Data(bytes: &x, count: 2)) }
        d.append("RIFF".data(using: .ascii)!); u32(36 + dataSize)
        d.append("WAVE".data(using: .ascii)!)
        d.append("fmt ".data(using: .ascii)!); u32(16); u16(1); u16(1)
        u32(sampleRate); u32(sampleRate * 2); u16(2); u16(16)
        d.append("data".data(using: .ascii)!); u32(dataSize)
        d.append(Data(count: Int(dataSize)))
        return d
    }
}
