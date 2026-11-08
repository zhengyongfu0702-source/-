import Foundation
import Combine
import CoreBluetooth
import CoreLocation
import UIKit

/// 自动模式引擎（iOS 版 1.14）。
///
/// ## 和 Android 的根本差异：这里一个定时器都没有
///
/// Android 必须自己管节拍（Handler 每 1.5 秒一拍）+ 主动断连睡觉，因为它的后台真的会
/// 把 CPU 叫醒、真的一直耗电。iOS 相反：`bluetooth-central` 后台模式下，BLE 连接由系统
/// 维持，App 进程被挂起时几乎不耗 CPU，只有车机推来一帧才会把它叫醒几毫秒。
///
/// 所以 1.11 那套「休眠状态机 + 运动传感器 + 兜底闹钟」在 iOS 上是**负优化**，
/// 主动断连反而会丢掉 iOS 最值钱的能力：系统级断线自动重连。这里有三个触发点：
///
/// 1. `bleConnected(true)` —— 连上（含系统后台自动重连）→ 判「该不该开锁」；
/// 2. `bleConnected(false)` —— 断开 → 判「该不该立刻锁车」；
/// 3. `bleArmed` —— 车机 3 秒一帧的状态帧，天然心跳 → 顺便判一次。
///
/// 人车分离时没有任何事件，引擎完全不跑。这就是 iOS 上的省电答案。
///
/// 平台限制（不是实现问题）：没有前台服务，App 被系统杀掉或手机重启后不会自己恢复，
/// 需要用户手动打开一次才能重新挂上。
final class AutoEngine: NSObject, ObservableObject {

    static let shared = AutoEngine()

    let ble = BleCentral()
    let api = CarAPI()

    // MARK: 对外状态（SwiftUI 直接订阅）

    @Published var logs: [String] = []
    @Published var connected = false
    @Published var rssi = -127
    @Published var armed = false
    @Published var armedKnown = false
    @Published var running = false
    @Published var acting = false
    @Published var powerText = ""
    @Published var car: CarAPI.Car?
    @Published var signedIn = false
    @Published var devName = ""
    @Published var lastResult = ""
    /// 打码后的当前账号，界面上显示「你登的是谁」
    @Published var accountText = ""

    // MARK: 定位（1.14 起）

    /// 「距车 8 米（误差 ±5 米）」这类文案
    @Published var distText = ""
    /// 定位授权 / 模式说明
    @Published var locText = ""
    /// 这一拍是不是用「定位」判的（界面上标「定位 / 蓝牙」）
    @Published var geoActive = false
    /// 后台定位开关，界面直接绑定
    @Published var locBackground = false
    /// 定位判距总开关（界面绑定）
    @Published var geoEnabled = false

    // MARK: 双通道竞速 / 洗车模式 / 统计（1.16）

    /// 双通道竞速开关（界面绑定）
    @Published var raceEnabled = false
    /// 围栏降耗开关（界面绑定）
    @Published var fenceEnabled = false
    /// 通知与震动开关（界面绑定）
    @Published var notifyEnabled = false
    /// 洗车模式剩余文案；空串表示没开
    @Published var washText = ""
    /// 罚站率统计摘要
    @Published var statsText = ""
    /// 车门状态文案（门位未逆出来，恒为「未知」）
    @Published var doorText = "车门：状态未知（门位还没逆出来）"

    // 诊断页
    @Published var diagDevices: [DiagDevice] = []
    @Published var diagServices: [String] = []
    @Published var diagScanning = false

    private let store = Store.shared
    private var st = Logic.St()
    /// 定位判据自己的计数（近/远拍数、离开起点）。与 Logic.St 分开存，
    /// 但 visited / unlockedThisVisit 这类「本次到访」语义每拍两边同步。
    private var geoSt = Geo.St()
    let loc = Loc()

    private var lastUnlockAt: Int64 = 0
    private var lastLockAt: Int64 = 0
    private var lastPollAt: Int64 = 0
    private var lastRssiValue = -127
    private var lastRssiAt: Int64 = 0
    private var rssiSmooth = -127
    private var reconnectFails = 0
    private var nextReconnectAt: Int64 = 0
    /// 断线重试令牌：重新排一次就把旧的那次作废，避免每次断开都叠一个定时器
    private var reconnectToken = 0

    /// 自动锁车失败后的重试时刻；0 表示没有待重试的任务
    private var autoLockRetryAt: Int64 = 0
    /// 这一轮自动锁车已经失败几次（最多 3 次就停手，交给用户手动锁）
    private var autoLockFails = 0
    /// 本次指令是不是用户手动点的。手动失败不自动重试，避免和用户抢方向盘
    private var pendingManual = false
    /// 这条指令在「网络 ↔ 蓝牙」之间已经互转了几次。最多一次，
    /// 否则两条都失败时会在两个回调里来回弹，把同一条指令发个没完。
    private var fallbackRound = 0

    private var pendingUnlock = false
    private var pendingChannel = 0
    private var loginInFlight = false
    /// 会话代号：退出登录时 +1，用来作废「正在路上」的登录回调。
    /// 否则点退出的瞬间恰好有登录请求在飞，它回来会把旧账号的 tid/btkey 写回本地。
    private var sessionEpoch = 0
    /// 本次「到访」是否已经因为断开发过锁车指令了。
    /// 断开即锁是每个到访周期一次的，不能因为车机抖动反复下发。
    private var lockedForThisVisit = false
    /// 最近一次发出的动作是不是开锁；回执核实用它判断「意图有没有被反向覆盖」
    private var lastActionUnlock = false

    // 蓝牙回执后的待核实状态（与 Android 1.10 对称）
    private var bleLockPending = false
    private var bleLockPendingAt: Int64 = 0
    private var lockFallbackRounds = 0
    private var bleUnlockPending = false
    private var bleUnlockPendingAt: Int64 = 0
    private var unlockFallbackRounds = 0

    // MARK: 双通道竞速（1.16）
    /// 这一笔是否正在竞速
    private var raceActive = false
    /// 竞速编号：迟到的回调靠它认出「这一轮已经结束了」
    private var raceId = 0
    /// 本轮已有几条通道返回失败
    private var raceArrived = 0
    /// 先到的通道：0=未定，1=蓝牙，2=网络
    private var raceWinner = 0
    /// 竞速起点
    private var raceT0: Int64 = 0
    /// 本轮是开锁还是锁车
    private var raceUnlock = false
    /// 本轮是不是自动决策触发的（决定失败要不要重试、成功要不要通知）
    private var raceAuto = false
    /// 蓝牙那一路还在飞
    private var raceBlePending = false
    /// 下发时刻，用来算真实耗时
    private var actionT0: Int64 = 0

    // MARK: 洗车 / 门位（1.16）
    /// 上一次的洗车状态，只用来在进入 / 退出时打一条日志
    private var washWasOn = false
    /// 门位是否已知。门位字节没逆出来之前恒为 false，不影响任何现有行为
    private var doorKnown = false
    private var doorOpen = false

    /// 围栏半径（米）。只影响耗电与唤醒时机，不参与「10 米开锁 / 30 米锁车」的判定
    private let fenceRadiusM = 300.0

    // MARK: 初始化

    override init() {
        super.init()
        ble.delegate = self
        signedIn = !store.str(StoreKey.tid).isEmpty && !store.str(StoreKey.btkey).isEmpty
        devName = store.str(StoreKey.devname)
        accountText = AutoEngine.maskUser(store.str(StoreKey.user))
        ble.configure(tid: store.str(StoreKey.tid), btkeyHex: store.str(StoreKey.btkey))
        loc.onChange = { [weak self] in self?.onLocUpdate() }
        loc.onFence = { [weak self] inside in
            guard let s = self else { return }
            s.log(inside ? "进入车辆围栏 → 定位升到精细档" : "离开车辆围栏 → 定位降到粗档（省电）")
            s.evaluate("围栏变化")
        }
        locBackground = store.locBg
        geoEnabled = store.geoOn
        raceEnabled = store.raceOn
        fenceEnabled = store.fenceOn
        notifyEnabled = store.notifyEnabled
        locText = loc.statusText
        statsText = Stats.summary()
        Notify.shared.setup()
        log("iOS 版启动")
        log("提示：iOS 拿不到车机 MAC，改用 0xFFE0 指纹 + 已记住的 identifier 连接")
    }

    /// 138****8888：够认出是谁，又不会在别人面前裸奔
    static func maskUser(_ u: String) -> String {
        if u.isEmpty { return "未登录" }
        let chars = Array(u)
        if chars.count == 11 {
            return String(chars[0..<3]) + "****" + String(chars[7..<11])
        }
        if chars.count > 6 {
            return String(chars[0..<3]) + "****" + String(chars[(chars.count - 2)...])
        }
        return u
    }

    // MARK: 会话

    func login(user: String, password: String, completion: @escaping (Bool, String) -> Void) {
        let passHash = Crypto.sha1Upper(password)
        store.put(StoreKey.user, user)
        store.put(StoreKey.passhash, passHash)
        accountText = AutoEngine.maskUser(user)
        let epoch = sessionEpoch
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                try self.api.login(name: user, passHash: passHash)
                let tid = self.api.tid
                let btkey = self.api.btkey
                DispatchQueue.main.async {
                    guard epoch == self.sessionEpoch else { return }
                    self.store.saveSession(tid: tid, btkey: btkey,
                                           devName: self.api.devName, expire: self.api.expire)
                    self.devName = self.api.devName
                    self.signedIn = !tid.isEmpty && !btkey.isEmpty
                    self.ble.configure(tid: tid, btkeyHex: btkey)
                    self.car = self.api.lastReport
                    if let c = self.api.lastReport {
                        self.armed = c.armed
                        self.armedKnown = true
                    }
                    self.log("登录成功 \(self.api.devName)  tid=\(tid)")
                    completion(true, "登录成功")
                    self.refreshStatus()
                }
            } catch {
                DispatchQueue.main.async {
                    guard epoch == self.sessionEpoch else { return }
                    let m = (error as? LocalizedError)?.errorDescription ?? "\(error)"
                    self.log("✗ 登录失败 \(m)")
                    completion(false, m)
                }
            }
        }
    }

    private func ensureSession(_ done: @escaping (Bool) -> Void) {
        if api.hasSession {
            done(true)
            return
        }
        let user = store.str(StoreKey.user)
        let pass = store.str(StoreKey.passhash)
        guard !user.isEmpty, !pass.isEmpty else {
            done(false)
            return
        }
        if loginInFlight { return }
        loginInFlight = true
        let epoch = sessionEpoch
        DispatchQueue.global(qos: .userInitiated).async {
            var ok = false
            do {
                try self.api.login(name: user, passHash: pass)
                ok = true
            } catch {
                self.log("✗ 自动重登失败 \(error.localizedDescription)")
            }
            DispatchQueue.main.async {
                guard epoch == self.sessionEpoch else {
                    // 登录回来时已经退出登录了：这份结果属于上一个账号，一律作废
                    self.loginInFlight = false
                    return
                }
                self.loginInFlight = false
                if ok {
                    self.store.saveSession(tid: self.api.tid, btkey: self.api.btkey,
                                           devName: self.api.devName, expire: self.api.expire)
                    self.ble.configure(tid: self.api.tid, btkeyHex: self.api.btkey)
                }
                done(ok)
            }
        }
    }

    // MARK: 自动模式

    func start() {
        guard !running else { return }
        running = true
        store.autoOn = true
        ble.clearDiagMode()
        ble.setKeepAlive(true)
        log("▶ 自动模式开启（定位判距为主，蓝牙兜底；后台仍靠连接/断开事件）")
        ensureSession { ok in
            if !ok { self.log("⚠︎ 没有有效会话，网络通道不可用（蓝牙仍可用）") }
        }
        // 手动开启自动模式 = 用户现在就要用，退避计数从头算
        reconnectFails = 0
        nextReconnectAt = 0
        if store.geoOn { startLoc() }
        ble.ensureConnected()
    }

    func stop() {
        guard running else { return }
        running = false
        store.autoOn = false
        ble.setKeepAlive(false)
        // 关掉自动模式后，任何"待核实补发"都不该再发生
        bleLockPending = false
        bleUnlockPending = false
        lockFallbackRounds = 0
        unlockFallbackRounds = 0
        st.visited = false
        st.unlockedThisVisit = false
        st.awayTicks = 0
        st.lastNearAt = 0
        geoSt = Geo.St()
        lockedForThisVisit = false
        reconnectToken += 1          // 作废挂着的那次断线重试
        reconnectFails = 0
        nextReconnectAt = 0
        autoLockRetryAt = 0
        autoLockFails = 0
        loc.stop()
        geoActive = false
        distText = ""
        log("■ 自动模式关闭")
        powerText = ""
    }

    // MARK: 退出登录（换账号）

    /// 退出前清场。只动内存与蓝牙，不动账号存储 —— 那一步由 `logout()` 负责，
    /// 因为它和界面上的二次确认是同一个动作。
    private func resetForLogout() {
        sessionEpoch &+= 1
        stop()
        loginInFlight = false
        connected = false
        armedKnown = false
        armed = false
        rssi = -127
        rssiSmooth = -127
        lastRssiValue = -127
        lastRssiAt = 0
        lastUnlockAt = 0
        lastLockAt = 0
        lastPollAt = 0
        lastNetAt = 0
        netRetried = false
        lastResult = ""
        car = nil
        lockedForThisVisit = false
        api.uid = ""
        api.ssk = ""
        api.tid = ""
        api.btkey = ""
        api.devName = ""
        api.expire = 0
        api.lastReport = nil
        ble.releaseSession()
    }

    /// 界面上的「退出登录」。车机记录默认保留，见 Store.logout 的注释。
    func logout(forgetDevice: Bool = false) {
        log("▶ 退出登录\(forgetDevice ? "，并忘记车机" : "，车机记录保留")")
        resetForLogout()
        store.logout(forgetDevice: forgetDevice)
        signedIn = false
        devName = ""
        accountText = AutoEngine.maskUser(store.str(StoreKey.user))
    }

    // MARK: 决策（只在事件里跑，绝不自己派定时器）

    /// iOS 没有前台服务，`Timer` 进后台必被挂起。所以这里不再有"每 1.5 秒一拍"，
    /// 改为由 BLE 事件驱动：连上、断开、状态帧、RSSI 回调。
    ///
    /// 代价是「离开后延时 N 秒锁车」做不了（后台没有可靠定时器），
    /// 改为用户选的策略：**断开即锁**（见 `handleLinkLost`）。
    private func evaluate(_ reason: String) {
        let now = CarAPI.nowMs()
        let cfg = store.cfg

        st.connected = ble.isConnected
        st.armedKnown = armedKnown
        st.armed = armed
        st.moving = car?.moving ?? false
        st.busy = ble.busy || acting
        st.fresh = ble.lastSeenMs > 0 && (now - ble.lastSeenMs) < cfg.freshMs
        st.now = now
        st.lastSeen = ble.lastSeenMs
        st.lastUnlockAt = lastUnlockAt
        st.lastLockAt = lastLockAt

        // iOS 专用口径：有新鲜 RSSI 就按门限，没有就信"连上了"。
        // decide 只看 st.rssi，所以这里在"无信号"时把它顶到门限，
        // 等价于把 near 判成 true，而不必改动共享的决策函数。
        let rssiFresh = lastRssiAt > 0 && (now - lastRssiAt) < Logic.RSSI_FRESH_MS
        let near = Logic.nearAssumeByLink(rssi: rssiSmooth, thr: cfg.thr, fresh: rssiFresh)
        st.rssi = near && !rssiFresh ? cfg.thr : rssiSmooth

        // 断线后按退避重连（人车分离时不要 4 秒一次地空转）
        if running && !ble.isConnected && !ble.busy && now >= nextReconnectAt {
            let d = Power.reconnectDelayMs(fails: max(1, reconnectFails), screenOn: true)
            nextReconnectAt = now + d
            reconnectFails = min(reconnectFails + 1, 6)
            ble.ensureConnected()
        }

        // 洗车 / 代客模式：只暂停自动判定，手动按钮照旧
        let wash = store.washUntil > now
        if wash != washWasOn {
            washWasOn = wash
            if wash {
                log("洗车 / 代客模式：暂停自动开锁与锁车 \(max(1, (store.washUntil - now) / 60000)) 分钟（手动照常）")
            } else {
                log("洗车 / 代客模式结束，恢复自动判定")
            }
        }
        washText = wash ? "洗车模式 · 剩余 \(max(1, (store.washUntil - now) / 60000)) 分钟" : ""

        // 定位优先：定位可用就按真实距离判，否则回落到蓝牙 RSSI（decideAction 内部处理）
        let act = wash ? Logic.NONE : decideAction(now: now, cfg: cfg)
        let src = geoActive ? "定位" : "蓝牙"
        if act == Logic.UNLOCK {
            log("◇ 判定（\(reason) · \(src)）：靠近且已锁 → 开锁")
            requestAction(unlock: true, auto: true)
        } else if act == Logic.LOCK {
            // 门没关严不落锁：门位未确认前 doorKnown 恒为 false，这一步永远放行
            if store.flag(StoreKey.doorGuard, false), Logic.doorBlocksLock(doorKnown: doorKnown, doorOpen: doorOpen) {
                log("⚠ 有车门没关严，本轮不落锁")
            } else {
                log("◇ 判定（\(reason) · \(src)）：确认离开 → 锁车")
                requestAction(unlock: false, auto: true)
            }
        }

        // 到点的锁车重试。只在 App 还活着时有效：后台被挂起时这里不会执行，
        // 所以重试失败不影响「断开即锁」那条主路。
        if running, autoLockRetryAt > 0, now >= autoLockRetryAt, !acting, !wash {
            autoLockRetryAt = 0
            if !armed && st.visited {
                log("↻ 到点重试自动锁车（第 \(autoLockFails)/3 次）")
                requestAction(unlock: false, auto: true)
            } else {
                autoLockFails = 0
            }
        }

        updatePowerText()
        checkVerify(now: now)
    }

    // MARK: 定位判据

    /// 把「车机位置 + 手机位置 + 蓝牙佐证」拼成一次判定的输入。
    ///
    /// 三份数据各有各的坑，全部在 `Geo.usable` 里挡：
    /// - 车机位置：没定位成功时平台会回 `0,0`，必须挡掉；
    /// - 手机位置：精度差、时间旧都不算数；
    /// - 蓝牙：既能佐证「贴着车」，也能否决「已离开」。
    private func buildGeo(_ now: Int64, _ cfg: Logic.Cfg, _ gcfg: Geo.Cfg) -> Geo.St {
        var g = geoSt
        g.now = now
        g.armedKnown = armedKnown
        g.armed = armed
        g.moving = car?.moving ?? false
        g.busy = ble.busy || acting
        g.visited = st.visited
        g.unlockedThisVisit = st.unlockedThisVisit
        g.lastUnlockAt = lastUnlockAt
        g.lastLockAt = lastLockAt

        if let c = car {
            let clat = Double(c.lat) ?? 0
            let clng = Double(c.lng) ?? 0
            if Geo.valid(clat, clng) {
                g.carValid = true
                g.carLat = clat
                g.carLng = clng
                g.carLocAt = c.reportedAt
            } else {
                g.carValid = false
            }
        } else {
            g.carValid = false
        }

        g.phoneValid = loc.fixAt > 0 && loc.acc > 0 && loc.acc < 9999
        g.phoneLat = loc.lat
        g.phoneLng = loc.lng
        g.phoneAcc = loc.acc
        g.phoneFixAt = loc.fixAt
        g.dist = (g.carValid && g.phoneValid)
            ? Geo.distance(g.phoneLat, g.phoneLng, g.carLat, g.carLng)
            : Double.nan

        let rssiFresh = lastRssiAt > 0 && (now - lastRssiAt) < Logic.RSSI_FRESH_MS
        g.bleNear = ble.isConnected && rssiFresh && lastRssiValue >= cfg.thr
        // 否决权有两条限权，缺一不可：
        //   ① 信号必须没比「靠近门限」弱太多 —— 穿墙的弱信号不算贴着车；
        //   ② 否决最多持续 vetoMaxMs —— 人上楼待一夜不能一夜不锁车。
        // -120 以下是从没读到过 RSSI 的哨兵值（默认 -127），此时保守地保留否决，
        // 因为刚连上还没读到读数，半秒后就有真值了。
        let rssiKnown = lastRssiValue > -120
        let vetoRaw = ble.isConnected && rssiFresh
            && (!rssiKnown || lastRssiValue >= cfg.thr - gcfg.vetoSlackDb)
        if vetoRaw {
            if g.vetoSince == 0 { g.vetoSince = now }
            g.bleVeto = (now - g.vetoSince) < gcfg.vetoMaxMs
        } else {
            g.vetoSince = 0
            g.bleVeto = false
        }
        return g
    }

    /// 定位优先、蓝牙兜底。两条判据共用「本次到访」的语义，避免一边开了锁、
    /// 另一边不知道又把车解开。
    private func decideAction(now: Int64, cfg: Logic.Cfg) -> Int {
        let gcfg = store.geoCfg
        var g = buildGeo(now, cfg, gcfg)
        let ok = Geo.usable(g, gcfg)
        if geoActive != ok { geoActive = ok }
        updateDistText(g)

        // 围栏降耗：离车很远时把精度降到粗档，回到附近再升回来。
        // 精度只在需要时花钱 —— 人在三公里外还开着 GPS 高频，纯属白耗电。
        if store.geoOn {
            let target: Loc.Mode = (store.fenceOn
                && Logic.canGoCoarse(dist: g.dist, acc: g.phoneAcc, fenceM: fenceRadiusM))
                ? .coarse : .fine
            loc.setMode(target)
            // 车的位置已知就挂一个系统级围栏：App 被挂起也能在「回到车附近」时被叫醒
            if g.carValid, !loc.fenceMatches(lat: g.carLat, lng: g.carLng) {
                loc.startFence(lat: g.carLat, lng: g.carLng, radius: fenceRadiusM)
            }
        }

        if ok {
            let a = Geo.decide(&g, gcfg)
            geoSt = g
            st.visited = g.visited
            st.unlockedThisVisit = g.unlockedThisVisit
            return a
        }

        // 回落蓝牙：定位自己的计数清零，否则恢复定位的瞬间会凭旧计数立刻动作
        geoSt.nearTicks = 0
        geoSt.farTicks = 0
        geoSt.farSince = 0
        geoSt.vetoSince = 0
        return Logic.decide(&st, cfg)
    }

    private func updateDistText(_ g: Geo.St) {
        var t: String
        if g.carValid && g.phoneValid && !g.dist.isNaN {
            t = Geo.distanceText(g.dist) + String(format: "（误差 ±%.0f 米）", max(0, g.phoneAcc))
        } else if !loc.authorized {
            t = "定位未授权"
        } else if !g.carValid {
            t = "车机没有回传定位"
        } else if loc.fixAt <= 0 {
            t = "正在定位…"
        } else {
            t = "定位数据过期"
        }
        if t != distText { distText = t }
        let lt = loc.statusText
        if lt != locText { locText = lt }
    }

    /// 定位更新回调。前台每移动几米一次；后台模式下由系统唤醒 App 时也会来。
    private func onLocUpdate() {
        let now = CarAPI.nowMs()
        let g = buildGeo(now, store.cfg, store.geoCfg)
        updateDistText(g)
        guard running else { return }
        evaluate("定位更新")
    }

    private func startLoc() {
        loc.setBackground(store.locBg)
        loc.askPermission()
        loc.start()
        locText = loc.statusText
        log("▶ 定位已启动（\(loc.statusText)，门限 \(Int(store.geoNearM)) / \(Int(store.geoFarM)) 米）")
    }

    /// 界面切换「仅前台 / 前台+后台」
    func setLocBackground(_ on: Bool) {
        store.locBg = on
        locBackground = on
        loc.setBackground(on)
        if on && !loc.authorized { loc.askPermission() }
        if on && loc.auth == .authorizedWhenInUse {
            log("⚠︎ 要后台定位，请在系统弹窗里选「始终允许」")
        }
        log(on ? "▶ 定位模式：前台 + 后台（锁屏也判距）" : "▶ 定位模式：仅前台（切后台停定位）")
        locText = loc.statusText
        if running { startLoc() }
    }

    /// 界面开关「定位判距」
    func setGeoEnabled(_ on: Bool) {
        store.geoOn = on
        geoEnabled = on
        log(on ? "▶ 定位判距：开" : "▶ 定位判距：关（改用蓝牙信号）")
        if on {
            if running { startLoc() }
        } else {
            loc.stop()
            geoActive = false
            distText = ""
        }
    }

    // MARK: 一键启动 / 熄火

    func startEngine() { engine(start: true) }
    func stopEngine() { engine(start: false) }

    /// 走网络，不需要蓝牙在附近。实车抓包：303120 启动、303125 熄火。
    private func engine(start: Bool) {
        guard !acting else {
            log("⚠︎ 上一条指令还在执行")
            return
        }
        log("▶ \(start ? "一键启动" : "熄火")")
        acting = true
        ensureSession { ok in
            guard ok else {
                self.acting = false
                self.log("✗ 无有效会话，网络通道不可用")
                self.lastResult = "未登录"
                return
            }
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let r = start ? (try self.api.startEngine()) : (try self.api.stopEngine())
                    DispatchQueue.main.async {
                        self.acting = false
                        if r.ok {
                            self.log("✓ \(start ? "启动" : "熄火")成功")
                            self.lastResult = start ? "启动成功" : "熄火成功"
                            self.refreshStatus()
                        } else {
                            self.log("✗ \(start ? "启动" : "熄火")失败 \(r.code) \(r.msg)")
                            self.lastResult = "\(r.code)"
                        }
                    }
                } catch {
                    DispatchQueue.main.async {
                        self.acting = false
                        self.log("✗ 网络异常 \(error.localizedDescription)")
                        self.lastResult = "网络异常"
                    }
                }
            }
        }
    }

    /// 蓝牙断开的那一刻。用户选的策略是「断开立刻锁」，但只对"本次到访确实开过锁"生效，
    /// 否则路过连一下断掉也会去锁别人的车。
    private func handleLinkLost() {
        let now = CarAPI.nowMs()
        let cfg = store.cfg
        guard running, cfg.autoLock else { return }
        guard st.unlockedThisVisit, !lockedForThisVisit else { return }
        guard !acting else {
            log("断开时正有指令在执行，这次不追加锁车")
            return
        }
        if car?.moving == true {
            log("断开时车辆在行驶，不锁车")
            return
        }
        if now - lastLockAt <= cfg.lockCooldownMs {
            log("距上次锁车不足冷却时间，跳过")
            return
        }
        lockedForThisVisit = true
        log("◇ 蓝牙断开且本次到访开过锁 → 立即锁车")
        requestAction(unlock: false, auto: true)
    }

    private func updatePowerText() {
        let text = "事件驱动 · 连上判开锁 / 断开即锁 · 无定时唤醒"
        if text != powerText { powerText = text }
    }

    // MARK: 动作

    /// 手动按钮：定位可用时网络为主，否则蓝牙优先；失败自动转另一条
    func manual(unlock: Bool) {
        log("▶ 手动\(unlock ? "开锁" : "锁车")")
        requestAction(unlock: unlock, manual: true)
    }

    /// 通知栏「手动锁车」按下来的入口
    func manualLockNow() {
        log("▶ 通知栏手动锁车")
        requestAction(unlock: false, manual: true)
    }

    /// 纯网络按钮
    func netOnly(unlock: Bool) {
        log("▶ 网络\(unlock ? "开锁" : "锁车")")
        pendingUnlock = unlock
        pendingChannel = Logic.CH_NET
        pendingManual = true
        acting = true
        actionT0 = CarAPI.nowMs()
        netPerform(unlock: unlock)
    }

    /// - Parameters:
    ///   - auto: 系统自动触发（可重试、成功要通知）
    ///   - manual: 用户手动点的（失败不重试）
    private func requestAction(unlock: Bool, auto: Bool = false, manual: Bool = false) {
        guard !acting else {
            log("⚠︎ 上一条指令还在执行")
            return
        }
        pendingManual = manual
        fallbackRound = 0
        actionT0 = CarAPI.nowMs()

        // 两条通道都够得着时并发下发 —— 这是「点了就开」和「点完站十秒」的区别
        if tryRace(unlock: unlock, auto: auto, manual: manual) {
            return
        }

        let cfg = store.cfg
        let rssiAge: Int64 = lastRssiAt > 0 ? CarAPI.nowMs() - lastRssiAt : -1
        // 定位判定成立时，人和车的关系已经由距离说清楚了，网络就是主力通道；
        // 只有定位用不了（没授权 / 车机没回定位 / 精度太差）才回到蓝牙优先。
        let ch: Int
        if geoActive {
            ch = Logic.CH_NET
        } else if unlock {
            ch = Logic.unlockChannel(hasTarget: ble.hasSavedTarget, connected: ble.isConnected,
                                     rssiAgeMs: rssiAge, rssi: lastRssiValue, cfg)
        } else {
            ch = Logic.lockChannel(hasTarget: ble.hasSavedTarget, connected: ble.isConnected,
                                   rssiAgeMs: rssiAge, rssi: lastRssiValue, cfg)
        }

        // 信号值只在「还在有效期内」时才有意义：-127 是没读到的哨兵值，
        // 67 秒前的 -90dBm 也不代表现在离车多远，直接打出来只会误导。
        let sigText: String
        if rssiAge < 0 || lastRssiValue <= -120 {
            sigText = "无信号记录"
        } else if rssiAge > cfg.bleReachMs {
            sigText = "\(lastRssiValue)dBm 已过期（\(rssiAge / 1000)s 前）"
        } else {
            sigText = "\(lastRssiValue)dBm（\(rssiAge / 1000)s 前）"
        }
        log("通道选择：\(Logic.channelName(ch))（\(sigText)）")
        pendingUnlock = unlock
        pendingChannel = ch
        acting = true
        lastActionUnlock = unlock
        // 方向变了，上一条待核实就作废（Logic.verify 里也有同样的意图判断，这里是双保险）
        if unlock {
            bleLockPending = false
        } else {
            bleUnlockPending = false
        }

        if ch == Logic.CH_BLE {
            ble.perform(unlock: unlock)
        } else {
            netPerform(unlock: unlock)
        }
    }

    // MARK: - 双通道竞速（1.16）

    /// 竞速：蓝牙与网络**同时**下发，谁先回执算谁，另一条结果丢弃。
    ///
    /// 为什么不是「主备切换」：蓝牙本地 0.2~1 秒，网络 3~10 秒，主备永远是网络的 10 秒。
    /// 并发之后 P95 直接落在蓝牙那一侧，而网络那条本来也没有副作用 ——
    /// 锁车 / 开锁都是幂等指令，两条都成功等于同一条执行两次。
    ///
    /// **启动 / 熄火永远不走这里**：那两条不幂等，重复触发会伤启动机。
    ///
    /// - Returns: true 表示已按竞速发出，调用方不要再走单通道逻辑
    private func tryRace(unlock: Bool, auto: Bool, manual: Bool) -> Bool {
        guard store.raceOn, !raceActive, !ble.busy else { return false }
        let cfg = store.cfg
        let now = CarAPI.nowMs()
        let rssiAge: Int64 = lastRssiAt > 0 ? now - lastRssiAt : -1
        guard Logic.shouldRace(hasTarget: ble.hasSavedTarget,
                               connected: ble.isConnected,
                               rssiAgeMs: rssiAge,
                               rssi: lastRssiValue,
                               hasSession: signedIn,
                               cfg) else { return false }

        raceId += 1
        let id = raceId
        raceActive = true
        raceArrived = 0
        raceWinner = 0
        raceT0 = now
        raceUnlock = unlock
        raceAuto = auto
        raceBlePending = true
        pendingUnlock = unlock
        pendingChannel = Logic.CH_BLE
        pendingManual = manual
        lastActionUnlock = unlock
        acting = true
        if unlock {
            bleLockPending = false
        } else {
            bleUnlockPending = false
        }

        log("双通道竞速：\(unlock ? "开锁" : "锁车")，蓝牙与网络同时下发（谁先回算谁）")
        ble.perform(unlock: unlock)
        netRaceSend(unlock: unlock, id: id)
        DispatchQueue.main.asyncAfter(deadline: .now() + 15) { [weak self] in
            self?.raceTimeout(id)
        }
        return true
    }

    /// 竞速里的网络那一路：单独一条，不走 netPerform 的兜底逻辑
    private func netRaceSend(unlock: Bool, id: Int) {
        let now = CarAPI.nowMs()
        if lastNetAt > 0 && now - lastNetAt < netMinGapMs {
            // 服务端限频：这一笔竞速只用蓝牙，网络那条直接判负，别白等
            log("网络侧距上一条不足 \(netMinGapMs / 1000) 秒，本轮竞速只用蓝牙")
            raceArrive(id: id, ch: Logic.CH_NET, ok: false, msg: "限频冷却")
            return
        }
        if !signedIn {
            raceArrive(id: id, ch: Logic.CH_NET, ok: false, msg: "未登录")
            return
        }
        lastNetAt = now
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let r = unlock ? (try self.api.unlock()) : (try self.api.lock())
                DispatchQueue.main.async {
                    self.raceArrive(id: id, ch: Logic.CH_NET, ok: r.ok,
                                    msg: r.ok ? "已受理" : "失败 \(r.code)")
                }
            } catch {
                DispatchQueue.main.async {
                    self.raceArrive(id: id, ch: Logic.CH_NET, ok: false,
                                    msg: "异常 \(error.localizedDescription)")
                }
            }
        }
    }

    /// 某一路回来了。只有第一路的成功算数；两路都失败才算这一笔失败。
    private func raceArrive(id: Int, ch: Int, ok: Bool, msg: String) {
        guard id == raceId else { return }
        let ms = CarAPI.nowMs() - raceT0
        if !raceActive {
            // 胜负已定，迟到的那一路只记一笔，不做任何状态变更
            if ok { log("（\(Logic.channelName(ch)) 稍后也返回成功，已忽略）") }
            return
        }
        if ok {
            raceActive = false
            raceWinner = ch
            log("✓ 先到：\(Logic.channelName(ch)) · \(fmtSec(ms))（另一条通道已丢弃）")
            applyRaceSuccess(unlock: raceUnlock, ch: ch, ms: ms, auto: raceAuto)
            return
        }
        raceArrived += 1
        log("这一路没成功（\(Logic.channelName(ch))：\(msg)），等另一路")
        if raceArrived >= 2 {
            raceActive = false
            acting = false
            log("✗ 两条通道都没成功（竞速）")
            if raceUnlock {
                Stats.unlockResult(ch: 0, ms: ms, ok: false, raced: true)
                lastResult = "开锁失败（两条通道都没通）"
            } else {
                Stats.lockResult(ok: false)
                lastResult = "锁车失败（两条通道都没通）"
                if raceAuto {
                    noteLockFailed("竞速两条通道都失败")
                } else {
                    Notify.shared.failTick()
                }
            }
            statsText = Stats.summary()
        }
    }

    private func raceTimeout(_ id: Int) {
        guard id == raceId, raceActive else { return }
        raceActive = false
        acting = false
        let ms = CarAPI.nowMs() - raceT0
        log("✗ 竞速 15 秒内两条通道都没回执，这一笔放弃")
        if raceUnlock {
            Stats.unlockResult(ch: 0, ms: ms, ok: false, raced: true)
        } else {
            Stats.lockResult(ok: false)
            if raceAuto { noteLockFailed("竞速超时") }
        }
        statsText = Stats.summary()
    }

    /// 竞速胜出后的状态落地。语义与 markDone 保持一致
    private func applyRaceSuccess(unlock: Bool, ch: Int, ms: Int64, auto: Bool) {
        acting = false
        let now = CarAPI.nowMs()
        armed = !unlock
        armedKnown = true
        if unlock {
            lastUnlockAt = now
            st.unlockedThisVisit = true
            st.visited = true
            // 开锁成功 = 新的一次到访开始，断开时允许再锁一次
            lockedForThisVisit = false
            if ch == Logic.CH_BLE {
                bleUnlockPending = true
                bleUnlockPendingAt = now
                unlockFallbackRounds = 0
            }
            Stats.unlockResult(ch: ch, ms: ms, ok: true, raced: true)
            if store.notifyEnabled { Notify.shared.unlockTick() }
            lastResult = "开锁成功（\(Logic.channelName(ch))）"
        } else {
            lastLockAt = now
            st.visited = false
            st.unlockedThisVisit = true
            lockedForThisVisit = true
            autoLockFails = 0
            autoLockRetryAt = 0
            Notify.shared.clearLockFailed()
            if ch == Logic.CH_BLE {
                bleLockPending = true
                bleLockPendingAt = now
                lockFallbackRounds = 0
            }
            Stats.lockResult(ok: true)
            if auto && store.notifyEnabled {
                let d = notifyDistText()
                Notify.shared.autoLocked(distText: d)
                log("· 已发通知：已自动锁车" + (d.isEmpty ? "" : " · \(d)"))
            }
            lastResult = "锁车成功（\(Logic.channelName(ch))）"
        }
        statsText = Stats.summary()
        DispatchQueue.main.asyncAfter(deadline: .now() + 9) { [weak self] in
            self?.refreshStatus()
        }
    }

    /// 通知里的距离文案：精度差就不报数，别让「距车 480 米」误导人
    private func notifyDistText() -> String {
        let d = geoSt.dist
        if !d.isNaN, loc.acc > 0, loc.acc <= 60 {
            return "距车 \(Int(d.rounded())) 米"
        }
        return ""
    }

    private func fmtSec(_ ms: Int64) -> String {
        return String(format: "%.1f 秒", Double(ms) / 1000.0)
    }

    // MARK: - 洗车 / 代客模式、开关

    /// 洗车、代客泊车时车辆会频繁移动，自动判定只会反复开锁关锁。
    /// 一键暂停 30 分钟，到点自动恢复。
    /// - Parameter minutes: 0 表示立刻结束
    func setWash(minutes: Int) {
        let until = minutes <= 0 ? 0 : CarAPI.nowMs() + Int64(minutes) * 60_000
        store.washUntil = until
        washText = minutes <= 0 ? "" : "洗车模式 · 剩余 \(minutes) 分钟"
        log(minutes <= 0
            ? "洗车 / 代客模式：已结束，恢复自动判定"
            : "洗车 / 代客模式：开启 \(minutes) 分钟，期间不自动开锁 / 锁车")
        evaluate("洗车模式")
    }

    func setRace(_ on: Bool) {
        store.raceOn = on
        raceEnabled = on
        log(on ? "双通道竞速：已开启" : "双通道竞速：已关闭（回到单通道优先逻辑）")
    }

    func setFence(_ on: Bool) {
        store.fenceOn = on
        fenceEnabled = on
        log(on ? "围栏降耗：已开启（离车 300 米外只用粗定位）" : "围栏降耗：已关闭（一直用精细定位）")
        evaluate("围栏开关")
    }

    func setNotify(_ on: Bool) {
        store.notifyEnabled = on
        notifyEnabled = on
        if on { Notify.shared.setup() }
        log(on ? "通知与震动：已开启" : "通知与震动：已关闭")
    }

    func resetStats() {
        Stats.reset()
        statsText = Stats.summary()
        log("已清空开锁统计")
    }

    func refreshStats() {
        statsText = Stats.summary()
    }

    /// 服务端对同一账号的连续控制有频率限制：实测「锁车成功后 2 秒再开锁」直接回
    /// `TE2026 操作过快`，指令白丢一条。本地先等够 4 秒再发，别让用户看到莫名其妙的失败。
    private let netMinGapMs: Int64 = 4000
    private var lastNetAt: Int64 = 0
    /// TE2026 只自动重试一次，避免撞上限频时死循环
    private var netRetried = false

    private func netPerform(unlock: Bool) {
        let now = CarAPI.nowMs()
        if lastNetAt > 0 && now - lastNetAt < netMinGapMs {
            let waitMs = netMinGapMs - (now - lastNetAt)
            let waitS = (waitMs + 999) / 1000
            log("⚠︎ 距上一条网络指令不足 \(netMinGapMs / 1000)s，等 \(waitS)s 再发（服务端限频）")
            DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(Int(waitMs))) { [weak self] in
                self?.netPerform(unlock: unlock)
            }
            return
        }
        lastNetAt = now
        ensureSession { ok in
            guard ok else {
                self.acting = false
                self.log("✗ 无有效会话，网络通道不可用")
                self.lastResult = "未登录"
                self.afterNetFail(unlock: unlock, why: "无有效会话")
                return
            }
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let r = unlock ? (try self.api.unlock()) : (try self.api.lock())
                    DispatchQueue.main.async {
                        if r.ok {
                            self.acting = false
                            self.netRetried = false
                            self.markDone(unlock: unlock, channel: Logic.CH_NET)
                            self.log("✓ 网络\(unlock ? "开锁" : "锁车")成功")
                            self.lastResult = "网络成功"
                        } else if (r.code == "TE2026" || r.msg.contains("过快")) && !self.netRetried {
                            self.netRetried = true
                            self.lastNetAt = 0     // 重试不再受本地冷却挡
                            self.log("✗ 网络失败 \(r.code) \(r.msg) → 3 秒后自动重试一次")
                            DispatchQueue.main.asyncAfter(deadline: .now() + 3.0) { [weak self] in
                                self?.netPerform(unlock: unlock)
                            }
                        } else {
                            self.acting = false
                            self.netRetried = false
                            self.log("✗ 网络失败 \(r.code) \(r.msg)")
                            self.lastResult = "网络失败 \(r.code)"
                            self.afterNetFail(unlock: unlock, why: "网络 \(r.code)")
                        }
                    }
                } catch {
                    DispatchQueue.main.async {
                        self.acting = false
                        self.netRetried = false
                        self.log("✗ 网络异常 \(error.localizedDescription)")
                        self.lastResult = "网络异常"
                        self.afterNetFail(unlock: unlock, why: "网络异常")
                    }
                }
            }
        }
    }

    /// 网络通道没成 → 如果蓝牙还够得着，换蓝牙再试一次；否则收尾。
    /// 两个通道互转最多一轮（`fallbackRound`），否则两边都失败时会互相弹个没完。
    private func afterNetFail(unlock: Bool, why: String) {
        if fallbackRound < 1, ble.hasSavedTarget, ble.isConnected {
            fallbackRound += 1
            log("网络没成功（\(why)），改用蓝牙再试")
            pendingChannel = Logic.CH_BLE
            acting = true
            ble.perform(unlock: unlock)
            return
        }
        acting = false
        if !unlock { noteLockFailed(why) }
    }

    /// 自动锁车没成 → 60 秒后再判一次，最多 3 次。
    ///
    /// 60 秒是对齐 `Logic` 里的锁车冷却：比它更早重试会被冷却直接挡掉，白跑一趟。
    /// 手动点的动作不重试——用户自己看得见失败，再自动补一次反而像在抢方向盘。
    private func noteLockFailed(_ why: String) {
        guard running, !pendingManual, store.cfg.autoLock, !armed else { return }
        if autoLockFails >= 3 {
            autoLockRetryAt = 0
            log("✗ 自动锁车连续失败，先停手，请手动锁一次")
            // 这是唯一需要人当场介入的情形：强提醒 + 通知栏「手动锁车」
            if store.notifyEnabled {
                Notify.shared.lockFailed(why: why)
                log("· 已发强提醒（通知上可直接手动锁车）")
            }
            return
        }
        autoLockFails += 1
        autoLockRetryAt = CarAPI.nowMs() + 60_000
        log("自动锁车没成功（\(why)），60 秒后重试（第 \(autoLockFails)/3 次）")
    }

    private func markDone(unlock: Bool, channel: Int) {
        let now = CarAPI.nowMs()
        let wasAutoLock = !pendingManual && !unlock
        let elapsed = actionT0 > 0 ? now - actionT0 : 0
        lastActionUnlock = unlock
        if unlock {
            lastUnlockAt = now
            st.unlockedThisVisit = true
            st.visited = true
            // 开锁成功 = 新的一次到访开始，断开时允许再锁一次
            lockedForThisVisit = false
            if channel == Logic.CH_BLE {
                // 回执只代表"车机收到了"，车锁有没有真的弹开要看状态帧
                bleUnlockPending = true
                bleUnlockPendingAt = now
                unlockFallbackRounds = 0
            }
            Stats.unlockResult(ch: channel, ms: elapsed, ok: true, raced: false)
            if store.notifyEnabled { Notify.shared.unlockTick() }
        } else {
            lastLockAt = now
            st.visited = false
            // 锁上了就清掉重试计数
            autoLockFails = 0
            autoLockRetryAt = 0
            // 站在车旁用手机锁了车，本次到访就不要再「靠近自动开锁」。
            // 否则人只要在车边站够 60 秒冷却，车就会自己又解开一次。
            // 真正走开（awayLong）之后 Logic 会把它重置，下次走近照常开锁。
            st.unlockedThisVisit = true
            lockedForThisVisit = true
            if channel == Logic.CH_BLE {
                // 回执 ≠ 车真的锁了（实测状态帧 2.6 秒后才翻），留个待核实标记
                bleLockPending = true
                bleLockPendingAt = now
                lockFallbackRounds = 0
            }
            Stats.lockResult(ok: true)
            Notify.shared.clearLockFailed()
            if wasAutoLock && store.notifyEnabled {
                let d = notifyDistText()
                Notify.shared.autoLocked(distText: d)
                log("· 已发通知：已自动锁车" + (d.isEmpty ? "" : " · \(d)"))
            }
        }
        statsText = Stats.summary()
        // 网络成功是"权威"的，直接把状态改过来，并清掉蓝牙待核实；
        // 蓝牙成功则交给状态帧确认
        if channel == Logic.CH_NET {
            armed = !unlock
            armedKnown = true
            bleLockPending = false
            bleUnlockPending = false
        }
    }

    /// 蓝牙回执后的二次核实。每次 armed 变化、以及每一拍都跑一遍。
    ///
    /// 注意这里有个「静默期」：刚拿到回执时车锁还没动（实测状态帧 2.5~3 秒后才翻），
    /// 此刻立刻核实必然得出「不符合预期」，会立刻触发一次网络补发 = 每条指令都发两遍。
    /// 所以回执后 6 秒内不核实（车机 3 秒一帧，6 秒足够看到两帧）。
    private let verifySettleMs: Int64 = 6000

    private func checkVerify(now: Int64) {
        if bleLockPending {
            let age = now - bleLockPendingAt
            if age >= verifySettleMs {
                let v = Logic.verify(expectArmed: true, armedNow: armed,
                                     ageMs: age,
                                     lastWasUnlock: lastActionUnlock,
                                     rounds: lockFallbackRounds)
                if v == Logic.V_CONFIRMED {
                    bleLockPending = false
                    lockFallbackRounds = 0
                    log("✓ 状态核实：已锁车")
                } else if v == Logic.V_FALLBACK {
                    // 只有真的把补发指令发出去，才清掉待核实；否则下一拍还能重试
                    if dispatchFallback(unlock: false) {
                        lockFallbackRounds += 1
                        bleLockPending = false
                        log("蓝牙回执成功，但车机仍报未锁 → 改用网络补锁")
                    }
                } else if v == Logic.V_EXPIRE {
                    bleLockPending = false
                    log("锁车核实超时或已被后续操作覆盖，不再补发")
                }
            }
        }

        if bleUnlockPending {
            let age = now - bleUnlockPendingAt
            if age >= verifySettleMs {
                let v = Logic.verify(expectArmed: false, armedNow: armed,
                                     ageMs: age,
                                     lastWasUnlock: lastActionUnlock,
                                     rounds: unlockFallbackRounds)
                if v == Logic.V_CONFIRMED {
                    bleUnlockPending = false
                    unlockFallbackRounds = 0
                    log("✓ 状态核实：已解锁")
                } else if v == Logic.V_FALLBACK {
                    if dispatchFallback(unlock: true) {
                        unlockFallbackRounds += 1
                        bleUnlockPending = false
                        log("蓝牙回执成功，但车机仍报已锁 → 改用网络补开锁")
                    }
                } else if v == Logic.V_EXPIRE {
                    bleUnlockPending = false
                    log("开锁核实超时或已被后续操作覆盖，不再补发")
                }
            }
        }
    }

    /// 核实失败时补一次网络指令。补发前把通道标记改成网络，
    /// 否则网络成功后 markDone 会以为还是蓝牙，又留下一个待核实标记。
    ///
    /// - Returns: 是否真的发出去了。false 表示此刻正有别的指令在跑，
    ///   调用方不要清掉待核实标记，下一拍再试。
    @discardableResult
    private func dispatchFallback(unlock: Bool) -> Bool {
        guard !acting else { return false }
        pendingUnlock = unlock
        pendingChannel = Logic.CH_NET
        lastActionUnlock = unlock
        acting = true
        netPerform(unlock: unlock)
        return true
    }

    // MARK: 状态刷新

    func refreshStatus() {
        let epoch = sessionEpoch
        ensureSession { ok in
            guard ok, epoch == self.sessionEpoch else { return }
            DispatchQueue.global(qos: .userInitiated).async {
                let c = self.api.status()
                DispatchQueue.main.async {
                    guard epoch == self.sessionEpoch, let c = c else { return }
                    self.car = c
                    if c.reportedAt > 0 {
                        // 1.15 的修复搬过来：这里以前是直接 `armed = c.armed`，
                        // 绕过了「车辆自锁抑制」。蓝牙断着、只能靠网络查状态时，
                        // 熄火关门车自己上锁，人还在旁边，下一拍就会把车又解开。
                        self.applyArmed(c.armed)
                        // 网络状态是权威的，可直接用来核实蓝牙回执
                        self.checkVerify(now: CarAPI.nowMs())
                    }
                }
            }
        }
    }

    /// App 回到前台。原来靠定时器轮询网络，现在没有定时器了，
    /// 改成「一进前台就补一次真实状态」——这也正是用户最需要看到最新状态的时候。
    func onForeground() {
        guard signedIn else { return }
        log("· 回到前台")
        lastPollAt = CarAPI.nowMs()
        refreshStatus()
        refreshStats()
        if running {
            // 仅前台模式下，进后台时定位被停掉了，回前台要重新拉起来
            if store.geoOn && !loc.running { startLoc() }
            // 顺手把连接催一下：ensureConnected 内部有 4 秒间隔，不会因为来回切前后台就狂连
            ble.ensureConnected()
            evaluate("回到前台")
        }
    }

    /// 进后台。只有「仅前台定位」这一档才真的停；
    /// 开了后台定位就必须让它继续跑，否则锁屏后判不了距离。
    func onBackground() {
        if !store.locBg {
            loc.stop()
            geoActive = false
        }
    }

    // MARK: 日志

    func log(_ s: String) {
        let t = CarAPI.fmt("HH:mm:ss")
        let line = "\(t) \(s)"
        if Thread.isMainThread {
            append(line)
        } else {
            DispatchQueue.main.async { self.append(line) }
        }
    }

    private func append(_ line: String) {
        appendDisplay(line)
        // 落盘一份：App 被系统回收后，这是唯一能回溯的现场
        RunLog.shared.write(line)
    }

    /// 只进界面、不落盘。读回归档日志时用它，否则会把读出来的内容又写一遍，越滚越大。
    private func appendDisplay(_ line: String) {
        logs.append(line)
        if logs.count > 400 {
            logs.removeFirst(logs.count - 400)
        }
    }

    func clearLog() {
        logs.removeAll()
    }

    /// 诊断页「后台日志」：读出落盘内容
    func readRunLog() {
        let text = RunLog.shared.readAll()
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        if lines.isEmpty {
            log("· 还没有落盘日志")
            return
        }
        logs = Array(lines.suffix(400))
        log("· 已载入落盘日志 \(lines.count) 行（最多 512KB×2，只显示最后 400 行）")
    }

    /// 诊断页「删除落盘日志文件」
    func clearRunLog() {
        RunLog.shared.clear()
        log("· 落盘日志已清空")
    }

    // MARK: 诊断页

    func startDiagScan() {
        diagDevices.removeAll()
        diagServices.removeAll()
        diagScanning = true
        ble.startDiagScan()
    }

    func stopDiagScan() {
        diagScanning = false
        ble.stopDiagScan()
    }

    func connectDiag(_ d: DiagDevice) {
        diagScanning = false
        diagServices.removeAll()
        ble.connectManually(d.peripheral)
    }

    func diagControl(unlock: Bool) {
        ble.sendControlFrame(unlock: unlock)
    }

    func sendHex(_ s: String) {
        ble.sendRawHex(s)
    }

    func readBattery() {
        if let c = ble.chargerCharacteristic {
            ble.peripheral?.readValue(for: c)
        }
    }
}

/// 诊断页的一行设备
struct DiagDevice: Identifiable {
    let id: UUID
    let name: String
    let rssi: Int
    let hasCarSvc: Bool
    let peripheral: CBPeripheral
}

// MARK: - BleCentralDelegate

extension AutoEngine: BleCentralDelegate {

    func bleLog(_ b: BleCentral, _ s: String) {
        log(s)
    }

    func bleLink(_ b: BleCentral, _ s: String) {
        log("· \(s)")
    }

    func bleConnected(_ b: BleCentral, _ c: Bool) {
        connected = c
        if c {
            reconnectFails = 0
            nextReconnectAt = 0
            // 新连接还没读到 RSSI：先标成"没有新鲜值"，
            // 让 nearAssumeByLink 走"连上即视为在附近"那一支
            lastRssiAt = 0
            rssiSmooth = -127
            ble.readRssi(force: true)
            evaluate("蓝牙已连接")
        } else {
            rssi = -127
            rssiSmooth = -127
            handleLinkLost()
            if running {
                let d = Power.reconnectDelayMs(fails: max(1, reconnectFails), screenOn: true)
                nextReconnectAt = CarAPI.nowMs() + d
                reconnectFails = min(reconnectFails + 1, 6)
                log("已断开，\(d / 1000)s 后重连")
                // 两个动作缺一不可：
                // 1) 立刻提交一次 connect。App 被挂起后 DispatchQueue 的定时器一律不跑，
                //    只有「已经交给 CoreBluetooth 的连接请求」能在后台替我们等车机重新广播
                //    —— 这是 iOS 上唯一的自动重连手段。
                ble.ensureConnected()
                // 2) 前台再补一次定时重试。didFailToConnect 不会回调到这一层，
                //    只有上面那一次提交失败的话，就再也连不上了（原来日志里断开后就一直
                //    挂着，直到用户手动点一下才恢复，就是这个原因）。
                reconnectToken += 1
                let tk = reconnectToken
                DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(Int(d))) { [weak self] in
                    guard let self = self, self.reconnectToken == tk,
                          self.running, !self.ble.isConnected else { return }
                    self.nextReconnectAt = 0
                    self.ble.ensureConnected()
                    self.evaluate("重连重试")
                }
            }
        }
    }

    func bleRssi(_ b: BleCentral, _ r: Int) {
        rssi = r
        lastRssiValue = r
        lastRssiAt = CarAPI.nowMs()
        if rssiSmooth == -127 {
            rssiSmooth = r
        } else {
            rssiSmooth = (rssiSmooth * 3 + r) / 4
        }
        // 前台时才靠 RSSI 补判「走近了」；后台这个回调本来就不稳，
        // 真正的主力是 bleConnected(true) 那一次判定。
        guard running, UIApplication.shared.applicationState == .active else { return }
        if rssiSmooth >= store.cfg.thr && armed && !st.unlockedThisVisit {
            evaluate("信号转强")
        }
    }

    func bleArmed(_ b: BleCentral, _ a: Bool) {
        applyArmed(a)
        checkVerify(now: CarAPI.nowMs())
        // 状态帧 3 秒一帧，这就是 iOS 版天然的心跳：车机在推帧说明就在旁边，
        // 顺手判一次「该不该开锁」。人车分离时没有帧，也就完全不跑 —— 无需定时器。
        if running {
            evaluate("状态帧")
        }
    }

    /// 此刻是否判定为「在车旁」。定位能用就以距离为准，否则按原来的蓝牙口径。
    private func isNearNow() -> Bool {
        let now = CarAPI.nowMs()
        let g = buildGeo(now, store.cfg, store.geoCfg)
        if Geo.usable(g, store.geoCfg) {
            return g.bleNear || (g.dist <= store.geoNearM && g.phoneAcc <= store.geoCfg.accNearM)
        }
        guard ble.isConnected else { return false }
        let seen = ble.lastSeenMs
        if seen <= 0 || now - seen > Logic.RSSI_FRESH_MS {
            return false
        }
        let rssiFresh = lastRssiAt > 0 && (now - lastRssiAt) < Logic.RSSI_FRESH_MS
        return Logic.nearAssumeByLink(rssi: rssiSmooth, thr: store.cfg.thr, fresh: rssiFresh)
    }

    /// 改「车锁状态」的唯一入口。状态帧和网络查询都必须走这里，
    /// 否则两条路各改各的，自锁抑制就只在一半路径上生效——人站车旁车会被自己弹开。
    private func applyArmed(_ a: Bool) {
        let prev = armedKnown ? armed : a
        let nearNow = isNearNow()
        armed = a
        armedKnown = true
        if Logic.suppressUnlockOnArmedFlip(wasArmed: prev, nowArmed: a, near: nearNow) {
            // 熄火下车关门，车辆自己上锁，而手机还在旁边 → 绝不能立刻又解开
            st.unlockedThisVisit = true
            geoSt.unlockedThisVisit = true
            log("车辆刚上锁（人还在车旁）→ 本次到访不再自动开锁，走开再回来才恢复")
        }
    }

    func bleDone(_ b: BleCentral, ok: Bool, msg: String) {
        // 竞速里的蓝牙那一路：结果交给竞速判定，不再走「失败就转网络」的老逻辑
        if raceBlePending {
            raceBlePending = false
            log((ok ? "✓ " : "✗ ") + msg)
            raceArrive(id: raceId, ch: Logic.CH_BLE, ok: ok, msg: msg)
            return
        }
        let wasActing = acting
        acting = false
        if ok {
            lastResult = msg
            if wasActing && pendingChannel == Logic.CH_BLE {
                markDone(unlock: pendingUnlock, channel: Logic.CH_BLE)
            }
        } else {
            if wasActing && pendingChannel == Logic.CH_BLE {
                if fallbackRound < 1 {
                    fallbackRound += 1
                    log("蓝牙失败（\(msg)），自动转网络")
                    pendingChannel = Logic.CH_NET
                    acting = true
                    netPerform(unlock: pendingUnlock)
                } else {
                    log("✗ 蓝牙失败（\(msg)），两条通道都试过了")
                    lastResult = msg
                    if !pendingUnlock { noteLockFailed(msg) }
                }
            } else {
                lastResult = msg
            }
        }
    }

    func bleDiscovered(_ b: BleCentral, _ p: CBPeripheral, rssi: Int, adv: [String: Any]) {
        guard diagScanning || b.diagMode else { return }
        let svcs = (adv[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID]) ?? []
        let has = svcs.contains(BleCentral.svcCar)
        let name = p.name ?? (adv[CBAdvertisementDataLocalNameKey] as? String) ?? ""
        let d = DiagDevice(id: p.identifier, name: name, rssi: rssi, hasCarSvc: has, peripheral: p)
        if let i = diagDevices.firstIndex(where: { $0.id == d.id }) {
            diagDevices[i] = d
        } else {
            diagDevices.append(d)
        }
        diagDevices.sort { $0.rssi > $1.rssi }
    }

    func bleServices(_ b: BleCentral, _ services: [CBService]) {
        diagServices = services.map { "\($0.uuid.uuidString)" }
    }
}
