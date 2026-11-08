import Foundation
import Combine
import CoreBluetooth
import UIKit

/// 自动模式引擎（iOS 版 1.12）。
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

    // 诊断页
    @Published var diagDevices: [DiagDevice] = []
    @Published var diagServices: [String] = []
    @Published var diagScanning = false

    private let store = Store.shared
    private var st = Logic.St()

    private var lastUnlockAt: Int64 = 0
    private var lastLockAt: Int64 = 0
    private var lastPollAt: Int64 = 0
    private var lastRssiValue = -127
    private var lastRssiAt: Int64 = 0
    private var rssiSmooth = -127
    private var reconnectFails = 0
    private var nextReconnectAt: Int64 = 0

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

    // MARK: 初始化

    override init() {
        super.init()
        ble.delegate = self
        signedIn = !store.str(StoreKey.tid).isEmpty && !store.str(StoreKey.btkey).isEmpty
        devName = store.str(StoreKey.devname)
        accountText = AutoEngine.maskUser(store.str(StoreKey.user))
        ble.configure(tid: store.str(StoreKey.tid), btkeyHex: store.str(StoreKey.btkey))
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
        ble.setKeepAlive(true)
        log("▶ 自动模式开启（事件驱动：连上判开锁、断开判锁车，不再定时唤醒）")
        ensureSession { ok in
            if !ok { self.log("⚠︎ 没有有效会话，网络通道不可用（蓝牙仍可用）") }
        }
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
        lockedForThisVisit = false
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

        let act = Logic.decide(&st, cfg)
        if act == Logic.UNLOCK {
            log("◇ 判定（\(reason)）：靠近且已锁 → 开锁")
            requestAction(unlock: true)
        } else if act == Logic.LOCK {
            log("◇ 判定（\(reason)）：确认离开 → 锁车")
            requestAction(unlock: false)
        }

        updatePowerText()
        checkVerify(now: now)
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
        requestAction(unlock: false)
    }

    private func updatePowerText() {
        let text = "事件驱动 · 连上判开锁 / 断开即锁 · 无定时唤醒"
        if text != powerText { powerText = text }
    }

    // MARK: 动作

    /// 手动按钮：蓝牙优先，失败自动转网络
    func manual(unlock: Bool) {
        log("▶ 手动\(unlock ? "开锁" : "锁车")")
        requestAction(unlock: unlock)
    }

    /// 纯网络按钮
    func netOnly(unlock: Bool) {
        log("▶ 网络\(unlock ? "开锁" : "锁车")")
        pendingUnlock = unlock
        pendingChannel = Logic.CH_NET
        acting = true
        netPerform(unlock: unlock)
    }

    private func requestAction(unlock: Bool) {
        guard !acting else {
            log("⚠︎ 上一条指令还在执行")
            return
        }
        let cfg = store.cfg
        let rssiAge: Int64 = lastRssiAt > 0 ? CarAPI.nowMs() - lastRssiAt : -1
        let ch = unlock
            ? Logic.unlockChannel(hasTarget: ble.hasSavedTarget, connected: ble.isConnected,
                                  rssiAgeMs: rssiAge, rssi: lastRssiValue, cfg)
            : Logic.lockChannel(hasTarget: ble.hasSavedTarget, connected: ble.isConnected,
                                rssiAgeMs: rssiAge, rssi: lastRssiValue, cfg)

        let ageText = rssiAge < 0 ? "无记录" : "\(rssiAge / 1000)s 前"
        log("通道选择：\(Logic.channelName(ch))（信号 \(lastRssiValue)dBm，\(ageText)）")
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

    private func netPerform(unlock: Bool) {
        ensureSession { ok in
            guard ok else {
                self.acting = false
                self.log("✗ 无有效会话，网络通道不可用")
                self.lastResult = "未登录"
                return
            }
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let r = unlock ? (try self.api.unlock()) : (try self.api.lock())
                    DispatchQueue.main.async {
                        self.acting = false
                        if r.ok {
                            self.markDone(unlock: unlock, channel: Logic.CH_NET)
                            self.log("✓ 网络\(unlock ? "开锁" : "锁车")成功")
                            self.lastResult = "网络成功"
                        } else {
                            self.log("✗ 网络失败 \(r.code) \(r.msg)")
                            self.lastResult = "网络失败 \(r.code)"
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

    private func markDone(unlock: Bool, channel: Int) {
        let now = CarAPI.nowMs()
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
        } else {
            lastLockAt = now
            st.visited = false
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
        }
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
                        self.armed = c.armed
                        self.armedKnown = true
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
        lastPollAt = CarAPI.nowMs()
        refreshStatus()
        if running {
            ble.ensureConnected()
            evaluate("回到前台")
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
        // 先取"上一拍"的状态再覆盖，用来识别 未锁→已锁 的那一次翻转
        let prev = armedKnown ? armed : a
        let nearNow = isNearNow()
        armed = a
        armedKnown = true
        if Logic.suppressUnlockOnArmedFlip(wasArmed: prev, nowArmed: a, near: nearNow) {
            // 熄火下车关门，车辆自己上锁，而手机还在旁边 → 绝不能立刻又解开
            st.unlockedThisVisit = true
            log("车辆刚上锁（人还在车旁）→ 本次到访不再自动开锁，走开再回来才恢复")
        }
        checkVerify(now: CarAPI.nowMs())
        // 状态帧 3 秒一帧，这就是 iOS 版天然的心跳：车机在推帧说明就在旁边，
        // 顺手判一次「该不该开锁」。人车分离时没有帧，也就完全不跑 —— 无需定时器。
        if running {
            evaluate("状态帧")
        }
    }

    /// 此刻是否判定为「在车旁」，口径与 evaluate 里的 near 保持一致
    private func isNearNow() -> Bool {
        guard ble.isConnected else { return false }
        let now = CarAPI.nowMs()
        let seen = ble.lastSeenMs
        if seen <= 0 || now - seen > Logic.RSSI_FRESH_MS {
            return false
        }
        let rssiFresh = lastRssiAt > 0 && (now - lastRssiAt) < Logic.RSSI_FRESH_MS
        return Logic.nearAssumeByLink(rssi: rssiSmooth, thr: store.cfg.thr, fresh: rssiFresh)
    }

    func bleDone(_ b: BleCentral, ok: Bool, msg: String) {
        let wasActing = acting
        acting = false
        if ok {
            lastResult = msg
            if wasActing && pendingChannel == Logic.CH_BLE {
                markDone(unlock: pendingUnlock, channel: Logic.CH_BLE)
            }
        } else {
            if wasActing && pendingChannel == Logic.CH_BLE {
                log("蓝牙失败（\(msg)），自动转网络")
                pendingChannel = Logic.CH_NET
                acting = true
                netPerform(unlock: pendingUnlock)
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
