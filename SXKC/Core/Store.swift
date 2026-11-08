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
}
