import Foundation

/// 本地配置。密码只存 SHA1，不存明文。
///
/// 对应 Android 版 Store.java（SharedPreferences → UserDefaults）。
enum StoreKey {
    static let user = "user"
    static let passhash = "passhash"
    static let tid = "tid"
    static let btkey = "btkey"
    static let devname = "devname"
    static let expire = "expire"
    static let autoOn = "auto_on"
    static let autoUnlock = "auto_unlock"
    static let autoLock = "auto_lock"
    static let thr = "rssi_threshold"
    static let away = "away_seconds"
    /// 蓝牙锁车的信号门限
    static let bleLock = "ble_lock_thr"
    /// iOS 专用：已配对车机的 CBPeripheral.identifier（iOS 拿不到 MAC，只能存这个）
    static let peripheralId = "peripheral_id"
    /// iOS 专用：车机蓝牙名，仅用于日志与识别提示（不参与匹配）
    static let peripheralName = "peripheral_name"

    // MARK: 定位（1.14 起）

    /// 定位判距总开关。关掉就完全回到蓝牙 RSSI 判据
    static let geoOn = "geo_on"
    /// 是否申请后台持续定位（false = 只在 App 前台时定位）
    static let locBg = "loc_bg"
    /// 靠近门限（米）
    static let geoNearM = "geo_near_m"
    /// 离开门限（米）
    static let geoFarM = "geo_far_m"
    /// 地理围栏降耗：离车很远时降到粗档
    static let fenceOn = "fence_on"
    /// 双通道竞速：蓝牙与网络同时下发
    static let raceOn = "race_on"
    /// 洗车 / 代客模式截止时刻（毫秒）
    static let washUntil = "wash_until"
    /// 自动动作的通知与震动
    static let notifyOn = "notify_on"
    /// 门没关严不落锁（门位未确认前恒不生效）
    static let doorGuard = "door_guard"
}

final class Store {

    static let shared = Store()

    private let d: UserDefaults

    init() {
        d = UserDefaults.standard
    }

    func str(_ k: String, _ def: String = "") -> String {
        return d.string(forKey: k) ?? def
    }

    func put(_ k: String, _ v: String) {
        d.set(v, forKey: k)
    }

    func num(_ k: String, _ def: Int) -> Int {
        if d.object(forKey: k) == nil { return def }
        return d.integer(forKey: k)
    }

    func putNum(_ k: String, _ v: Int) {
        d.set(v, forKey: k)
    }

    func flag(_ k: String, _ def: Bool) -> Bool {
        if d.object(forKey: k) == nil { return def }
        return d.bool(forKey: k)
    }

    func putFlag(_ k: String, _ v: Bool) {
        d.set(v, forKey: k)
    }

    func lng(_ k: String, _ def: Int64) -> Int64 {
        if d.object(forKey: k) == nil { return def }
        return Int64(d.double(forKey: k))
    }

    func putLng(_ k: String, _ v: Int64) {
        d.set(Double(v), forKey: k)
    }

    func saveSession(tid: String, btkey: String, devName: String, expire: Int64) {
        put(StoreKey.tid, tid)
        put(StoreKey.btkey, btkey)
        put(StoreKey.devname, devName)
        putLng(StoreKey.expire, expire)
    }

    /// 退出登录（换账号）。
    ///
    /// 清掉：密码摘要、tid、btkey、车名、有效期、自动模式。
    ///
    /// **刻意保留 `user`**：只用来给登录页预填手机号。自动进主界面的条件是
    /// 「账号 + 密码摘要 + tid 三者都有」，摘要清掉了就进不去。
    ///
    /// **绝不默认清 `peripheralId`**：iOS 拿不到车机 MAC，只认系统分配的 identifier；
    /// 车机平时又不广播，清掉之后很可能再也扫不回来（不像 Android 还能按 MAC 重连）。
    /// 所以这里只在 `forgetDevice == true` 时删，界面上默认不提供这个选项。
    func logout(forgetDevice: Bool = false) {
        for k in [StoreKey.passhash, StoreKey.tid, StoreKey.btkey,
                  StoreKey.devname, StoreKey.expire] {
            d.removeObject(forKey: k)
        }
        if forgetDevice {
            d.removeObject(forKey: StoreKey.peripheralId)
            d.removeObject(forKey: StoreKey.peripheralName)
        }
        putFlag(StoreKey.autoOn, false)
    }

    // MARK: - 带默认值的常用项

    var thr: Int {
        get { return num(StoreKey.thr, -72) }
        set { putNum(StoreKey.thr, newValue) }
    }

    var awaySeconds: Int {
        get { return num(StoreKey.away, 30) }
        set { putNum(StoreKey.away, newValue) }
    }

    var bleLockThr: Int {
        get { return num(StoreKey.bleLock, -90) }
        set { putNum(StoreKey.bleLock, newValue) }
    }

    var autoOn: Bool {
        get { return flag(StoreKey.autoOn, false) }
        set { putFlag(StoreKey.autoOn, newValue) }
    }

    var autoUnlock: Bool {
        get { return flag(StoreKey.autoUnlock, true) }
        set { putFlag(StoreKey.autoUnlock, newValue) }
    }

    var autoLock: Bool {
        get { return flag(StoreKey.autoLock, true) }
        set { putFlag(StoreKey.autoLock, newValue) }
    }

    var cfg: Logic.Cfg {
        var c = Logic.Cfg()
        c.autoUnlock = autoUnlock
        c.autoLock = autoLock
        c.thr = thr
        c.awayMs = Int64(awaySeconds) * 1000
        c.bleThr = bleLockThr
        return c
    }

    // MARK: - 定位

    /// 定位判距总开关。默认**开**：这一版的重点就是它，装完不用去设置里翻。
    var geoOn: Bool {
        get { return flag(StoreKey.geoOn, true) }
        set { putFlag(StoreKey.geoOn, newValue) }
    }

    /// 后台持续定位。默认**关**：先按省电跑，用户需要锁屏也生效时自己打开。
    var locBg: Bool {
        get { return flag(StoreKey.locBg, false) }
        set { putFlag(StoreKey.locBg, newValue) }
    }

    /// 靠近门限（米）。实车上 GPS 抖 3~5 米很常见，默认 10 米，
    /// 觉得「走到车边要等一下才开」就调到 12~15。
    var geoNearM: Double {
        get {
            let v = d.object(forKey: StoreKey.geoNearM) as? Double ?? 10
            return v < 3 ? 10 : v
        }
        set { d.set(newValue, forKey: StoreKey.geoNearM) }
    }

    /// 离开门限（米）。保持「至少是靠近门限的 2 倍」，中间那段是死区。
    var geoFarM: Double {
        get {
            let v = d.object(forKey: StoreKey.geoFarM) as? Double ?? 30
            if v <= geoNearM { return geoNearM * 2 }
            return v
        }
        set { d.set(newValue, forKey: StoreKey.geoFarM) }
    }

    var geoCfg: Geo.Cfg {
        var c = Geo.Cfg()
        c.enabled = geoOn
        c.autoUnlock = autoUnlock
        c.autoLock = autoLock
        c.inM = geoNearM
        c.outM = geoFarM
        c.awayMs = Int64(awaySeconds) * 1000
        c.unlockCooldownMs = 60_000
        c.lockCooldownMs = 60_000
        return c
    }

    /// 围栏降耗。默认**开**：精度只在需要时花钱。
    var fenceOn: Bool {
        get { return flag(StoreKey.fenceOn, true) }
        set { putFlag(StoreKey.fenceOn, newValue) }
    }

    /// 双通道竞速。默认**开**：两条都是幂等指令，并发没有副作用。
    var raceOn: Bool {
        get { return flag(StoreKey.raceOn, true) }
        set { putFlag(StoreKey.raceOn, newValue) }
    }

    /// 通知与震动。默认**开**。
    var notifyEnabled: Bool {
        get { return flag(StoreKey.notifyOn, true) }
        set { putFlag(StoreKey.notifyOn, newValue) }
    }

    /// 洗车 / 代客模式的截止时刻；0 表示没开
    var washUntil: Int64 {
        get { return lng(StoreKey.washUntil, 0) }
        set { putLng(StoreKey.washUntil, newValue) }
    }
}
