import Foundation
import CoreLocation
import UIKit

/// 手机侧定位。只负责「我现在在哪、这个点准不准、值不值得信」，
/// 距离与门限判定全在 `Geo` 里做。
///
/// 两档模式，由界面上的开关切换（存在 `StoreKey.locBg`）：
/// - **仅前台**（默认）：App 在屏幕上时才更新，切后台就停，几乎不耗电；
/// - **前台 + 后台**：`allowsBackgroundLocationUpdates` 打开，锁屏也会继续收点，
///   代价是系统状态栏会出现定位箭头、耗电明显上升。
///
/// 后台模式必须在 Info.plist 里声明 `UIBackgroundModes: location`，否则设置
/// `allowsBackgroundLocationUpdates = true` 会**直接崩溃**。工程里已经加上了。
final class Loc: NSObject, CLLocationManagerDelegate {

    /// 精度档位。
    ///
    /// - `fine`：`NearestTenMeters` + 5~10 米位移。判 10 米门限必须用这一档。
    /// - `coarse`：`HundredMeters` + 100 米位移。人在几公里外时，判 10 米毫无意义，
    ///   但「有没有回到车附近」必须有数 —— 这一档耗电只有细档的十分之一。
    enum Mode {
        case fine
        case coarse
    }

    private let m = CLLocationManager()

    private(set) var lat = 0.0
    private(set) var lng = 0.0
    /// 水平精度半径（米）。没拿到点时是 9999
    private(set) var acc = 9999.0
    private(set) var fixAt: Int64 = 0
    private(set) var auth: CLAuthorizationStatus = .notDetermined
    /// 是否申请了后台持续定位
    private(set) var background = false
    private(set) var running = false
    /// 当前精度档位
    private(set) var mode: Mode = .fine

    /// 当前正在监听的围栏（以车为圆心）。nil = 没在监听
    private var fence: CLCircularRegion?

    /// 每次拿到新点、以及授权状态变化时回调
    var onChange: (() -> Void)?
    /// 进出围栏时的回调（进 = true 说明人回到车附近了）
    var onFence: ((Bool) -> Void)?

    override init() {
        super.init()
        m.delegate = self
        m.desiredAccuracy = kCLLocationAccuracyNearestTenMeters
        m.distanceFilter = 5
        // 后台模式必须关掉「自动暂停」，否则系统会在人站着不动时把定位停掉，
        // 再想判「离开」就没数据了
        m.pausesLocationUpdatesAutomatically = false
        m.activityType = .other
        auth = m.authorizationStatus
        applyMode()
    }

    var authorized: Bool {
        return auth == .authorizedWhenInUse || auth == .authorizedAlways
    }

    /// 后台定位真正生效，除了打开开关，还得拿到「始终允许」
    var backgroundActive: Bool {
        return background && auth == .authorizedAlways
    }

    var statusText: String {
        switch auth {
        case .notDetermined:
            return "未授权 · 点一下开启定位"
        case .denied, .restricted:
            return "定位被拒绝 · 请到系统设置里打开"
        case .authorizedAlways:
            return (background ? "前台 + 后台" : "已授权（当前只用前台）") + modeSuffix
        case .authorizedWhenInUse:
            return (background ? "仅前台 · 后台需要「始终允许」" : "仅前台") + modeSuffix
        @unknown default:
            return "未知状态"
        }
    }

    private var modeSuffix: String {
        return mode == .coarse ? " · 围栏外低精度" : ""
    }

    // MARK: 权限

    func askPermission() {
        if auth == .notDetermined {
            m.requestWhenInUseAuthorization()
            return
        }
        if background && auth == .authorizedWhenInUse {
            // iOS 要求先有「使用期间」再升级到「始终」，系统会弹第二次
            m.requestAlwaysAuthorization()
        }
    }

    /// 切换前台 / 前后台模式。会立刻重启定位，让新参数生效。
    func setBackground(_ on: Bool) {
        if background == on && running { return }
        background = on
        m.allowsBackgroundLocationUpdates = on
        m.showsBackgroundLocationIndicator = on
        applyMode()
        if on && auth == .authorizedWhenInUse {
            m.requestAlwaysAuthorization()
        }
        if running {
            m.stopUpdatingLocation()
            m.startUpdatingLocation()
        }
    }

    /// 切精度档位。只有真的变了才动硬件参数。
    func setMode(_ target: Mode) {
        if mode == target { return }
        mode = target
        applyMode()
        // 档位变化要重启一次，否则 accuracy 要等下一个点才生效
        if running {
            m.stopUpdatingLocation()
            m.startUpdatingLocation()
        }
    }

    /// 把当前档位对应的参数写进 manager。
    ///
    /// 两档都不牺牲「够不够判」：细档 10 米精度 + 5/10 米位移；
    /// 粗档 100 米精度 + 100 米位移 —— 后者只看「还在不在围栏外」，不需要更细。
    private func applyMode() {
        switch mode {
        case .fine:
            m.desiredAccuracy = kCLLocationAccuracyNearestTenMeters
            m.distanceFilter = background ? 10 : 5
        case .coarse:
            m.desiredAccuracy = kCLLocationAccuracyHundredMeters
            m.distanceFilter = 100
        }
    }

    // MARK: 地理围栏

    /// 以车为圆心挂一个围栏。
    ///
    /// 为什么用它替代「常开 GPS」：iOS 的 region monitoring 是**系统级**的，
    /// 由基站 / WiFi 变化驱动，App 被挂起也能唤醒，几乎不耗电。
    /// 进围栏时才把 GPS 拉起来，出围栏就降档 —— 精度只在需要时花钱。
    ///
    /// 半径最小 100 米（系统下限），这里用 300 米：给「回家 / 到公司」留足提前量。
    func startFence(lat: Double, lng: Double, radius: Double = 300) {
        guard CLLocationManager.isMonitoringAvailable(for: CLCircularRegion.self) else { return }
        if let old = fence {
            m.stopMonitoring(for: old)
        }
        let center = CLLocationCoordinate2D(latitude: lat, longitude: lng)
        let r = max(100, min(radius, 1000))
        let region = CLCircularRegion(center: center, radius: r, identifier: "sxkc.car")
        region.notifyOnEntry = true
        region.notifyOnExit = true
        fence = region
        m.startMonitoring(for: region)
        // 显著位置变化是围栏的兜底：系统偶尔会漏掉 region 回调，
        // 而「换了个基站」这种粗粒度事件几乎不会漏，且同样不耗电。
        m.startMonitoringSignificantLocationChanges()
    }

    func stopFence() {
        if let f = fence {
            m.stopMonitoring(for: f)
        }
        fence = nil
        m.stopMonitoringSignificantLocationChanges()
    }

    /// 当前是否挂着一个指向该坐标的围栏（避免每拍都 stop/start）
    func fenceMatches(lat: Double, lng: Double) -> Bool {
        guard let f = fence else { return false }
        let d = CLLocation(latitude: lat, longitude: lng)
            .distance(from: CLLocation(latitude: f.center.latitude, longitude: f.center.longitude))
        return d < 50
    }

    // MARK: 启停

    func start() {
        askPermission()
        guard authorized else { return }
        if running { return }
        running = true
        m.startUpdatingLocation()
    }

    func stop() {
        if !running { return }
        running = false
        m.stopUpdatingLocation()
    }

    // MARK: 代理

    func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        guard let l = locations.last else { return }
        // 负的精度表示这个点无效
        if l.horizontalAccuracy < 0 { return }
        let t = Int64(l.timestamp.timeIntervalSince1970 * 1000)

        // 手里那个点如果还很新鲜、而且比新点准，就别用新点覆盖
        if fixAt > 0 && (CarAPI.nowMs() - fixAt) < 5000 && l.horizontalAccuracy > acc {
            return
        }

        lat = l.coordinate.latitude
        lng = l.coordinate.longitude
        acc = l.horizontalAccuracy
        fixAt = t
        onChange?()
    }

    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        auth = manager.authorizationStatus
        if authorized && running {
            manager.startUpdatingLocation()
        }
        onChange?()
    }

    func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        // 定位失败不要停：可能只是暂时没信号，下一拍还会来
    }

    func locationManager(_ manager: CLLocationManager, didEnterRegion region: CLRegion) {
        guard region.identifier == "sxkc.car" else { return }
        // 回到车附近：升到细档，让判距能真正算出 10 米
        setMode(.fine)
        if !running {
            start()
        } else {
            manager.stopUpdatingLocation()
            manager.startUpdatingLocation()
        }
        onFence?(true)
    }

    func locationManager(_ manager: CLLocationManager, didExitRegion region: CLRegion) {
        guard region.identifier == "sxkc.car" else { return }
        // 离开围栏：降到粗档省电。注意**不能停掉定位** ——
        // 判「走远了该锁车」还要靠它给出方向，只是不需要 10 米级的精度了。
        setMode(.coarse)
        onFence?(false)
    }
}
