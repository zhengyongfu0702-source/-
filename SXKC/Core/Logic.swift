import Foundation

/// 自动控车的纯决策逻辑。与 Android 版 Logic.java 一一对应，可直接对着单测核对。
///
/// 全部是纯函数：不碰 IO、不碰线程、不存状态，只回答一个问题——
/// 「此刻该开锁、该锁车，还是什么都不做」。
///
/// 关键前提（实车验证）：车机**不广播**带绑定 ID 的名字，所以「扫到广播 = 车在旁边」
/// 这条判据不成立。靠近与否只能靠「连上之后的 RSSI」判断。
enum Logic {

    static let NONE = 0
    static let UNLOCK = 1
    static let LOCK = 2

    /// 通道：蓝牙（快、不依赖网络）
    static let CH_BLE = 1
    /// 通道：网络（蓝牙够不着或蓝牙失败后的兜底）
    static let CH_NET = 2

    /// 一次决策所需的全部输入
    struct St {
        var connected = true
        var armedKnown = false
        var armed = false
        var moving = false
        var busy = false
        var fresh = false
        var rssi = -127
        var now: Int64 = 0
        var lastSeen: Int64 = 0
        /// 最近一次判定「在近处」的时刻；离开计时以它为准
        var lastNearAt: Int64 = 0
        var lastUnlockAt: Int64 = 0
        var lastLockAt: Int64 = 0

        /// 自上次锁车成功以来，是否在范围内出现过（防止"车不在身边"也去锁车）
        var visited = false
        /// 本次到访已经自动开过锁（防止车辆自身回锁后又被反复开锁）
        var unlockedThisVisit = false
        /// 连续多少拍判定为「已离开」，用于抗丢包
        var awayTicks = 0
    }

    struct Cfg {
        var autoUnlock = true
        var autoLock = true
        var thr = -72
        var awayMs: Int64 = 30000
        var freshMs: Int64 = 10000
        var unlockCooldownMs: Int64 = 60000
        var lockCooldownMs: Int64 = 60000
        var awayConfirmTicks = 3
        /// 蓝牙锁车的距离门限（dBm）。离开判定触发时，如果最近一次读到的信号还强于它，
        /// 说明人还没走远、蓝牙大概率连得上，就先走蓝牙；否则直接走网络，别白等连接超时。
        var bleThr = -90
        /// 断开之后多久之内还认为「值得为锁车重连一次」
        var bleReachMs: Int64 = 20000
    }

    /// 纯函数式决策；会顺带更新 St 里的 visited / awayTicks / unlockedThisVisit / lastNearAt。
    static func decide(_ s: inout St, _ c: Cfg) -> Int {
        // 先用「上一拍」的近处时刻算是否已经离开，再刷新 lastNearAt。
        // 反过来的话，刚走近的那一拍 lastNearAt 已被刷成 now，awayLong 永远是 false，
        // 「走开很久再回来」就再也不会触发开锁了。
        let nearRef = s.lastNearAt > 0 ? s.lastNearAt : s.lastSeen
        let awayLong = nearRef > 0 && (s.now - nearRef) > c.awayMs

        let near = s.connected && s.fresh && s.rssi >= c.thr
        if near {
            s.visited = true
            s.awayTicks = 0
            s.lastNearAt = s.now
        } else {
            s.awayTicks += 1
        }

        // 离开得足够久 → 下一次靠近算「新的一次到访」，允许再开一次锁
        if awayLong {
            s.unlockedThisVisit = false
        }

        if s.busy || !s.armedKnown {
            return NONE
        }

        // ① 靠近且已锁 → 开锁
        if c.autoUnlock && s.armed && !s.moving && near && !s.unlockedThisVisit
            && (s.now - s.lastUnlockAt) > c.unlockCooldownMs {
            return UNLOCK
        }

        // ② 确认离开 → 落锁。必须曾经真的靠近过，否则车停别处会无限下发锁车
        let away = awayLong && s.awayTicks >= c.awayConfirmTicks
        if c.autoLock && !s.armed && !s.moving && s.visited && !near && away
            && (s.now - s.lastLockAt) > c.lockCooldownMs {
            return LOCK
        }

        return NONE
    }

    /// 锁车通道选择：**默认蓝牙优先**，够不着才直接走网络。
    ///
    /// 判断依据是「还连得上吗」，不是「离车多远」——RSSI 只能粗略折成距离，
    /// 而 BLE 能不能连才是决定 0.2 秒发出还是白等 13 秒超时的关键。
    ///
    /// - Parameters:
    ///   - hasMac: 是否已记住车机（iOS 上是已保存的 peripheral identifier）
    ///   - rssiAgeMs: 距上次读到 RSSI 过去了多久；没读过传 -1
    static func lockChannel(hasTarget: Bool,
                            connected: Bool,
                            rssiAgeMs: Int64,
                            rssi: Int,
                            _ c: Cfg?) -> Int {
        guard hasTarget else { return CH_NET }
        if connected { return CH_BLE }
        guard let c = c, rssiAgeMs >= 0 else {
            // 从没读到过信号：不知道远近，宁可走网络也别赌 13 秒超时
            return CH_NET
        }
        if rssiAgeMs <= c.bleReachMs && rssi >= c.bleThr {
            // 刚断开不久，且断开前信号还不错 → 值得花 ~1 秒重连一次
            return CH_BLE
        }
        return CH_NET
    }

    /// 开锁通道选择：**同样默认蓝牙优先**，但门槛比锁车宽松。
    ///
    /// 区别的原因：开锁时人一定在车旁（或马上要用车），蓝牙连接只要 ~0.5 秒，
    /// 而锁车时人正在走远，赌一次连接可能白等 13 秒。
    /// 所以这里只在「有明确证据表明够不着」时才跳过蓝牙：
    /// 没记住车机、或断开已久且断开前信号已经很弱。
    /// 没有信号记录（刚装好 / 诊断页连的）不算证据，照样先试蓝牙。
    static func unlockChannel(hasTarget: Bool,
                              connected: Bool,
                              rssiAgeMs: Int64,
                              rssi: Int,
                              _ c: Cfg?) -> Int {
        guard hasTarget else { return CH_NET }
        if connected { return CH_BLE }
        guard let c = c, rssiAgeMs >= 0 else {
            // 不知道远近 → 按"优先蓝牙"试一次，连不上会自动转网络
            return CH_BLE
        }
        if rssiAgeMs <= c.bleReachMs && rssi >= c.bleThr {
            return CH_BLE
        }
        return CH_NET
    }

    static func channelName(_ ch: Int) -> String {
        return ch == CH_BLE ? "蓝牙" : "网络"
    }

    // MARK: - 双通道竞速（1.16）

    /// 这一笔该不该「两条通道同时发」。
    ///
    /// 竞速能成立的前提是两条通道**都还够得着**：没有网络会话、没有车机标识、
    /// 蓝牙明显够不着时，起竞速等于白开一次连接。只有一条路时单通道更快也更省电。
    ///
    /// **启动 / 熄火永远不竞速**（写死在调用方）：那两条不幂等，重复触发会伤启动机。
    static func shouldRace(hasTarget: Bool,
                           connected: Bool,
                           rssiAgeMs: Int64,
                           rssi: Int,
                           hasSession: Bool,
                           _ c: Cfg?) -> Bool {
        guard hasTarget, hasSession else { return false }
        if connected { return true }
        guard let c = c, rssiAgeMs >= 0 else {
            // 从没读到过信号：希望不明，但并发一次不亏
            return true
        }
        return rssiAgeMs <= c.bleReachMs && rssi >= c.bleThr
    }

    /// 门没关严就落锁 == 没锁。
    ///
    /// 门没关严就落锁 == 没锁。
    ///
    /// 门位已经逆出来了：状态帧 `body[3]` 低 4 位非零 = 有车门开着。
    /// 这台车机不区分具体是哪一扇门（开任意一门，四位全置 1，原版 App 上也是四个门一起亮），
    /// 所以只看"有没有门开着"，不看是哪一扇。
    ///
    /// `doorKnown` 由调用方保证"这份门位是新鲜的" —— 断连、省电熄屏之后门位会停在旧值上，
    /// 拿过期数据拦锁车比不拦更危险，那种情况要传 false。
    static func doorBlocksLock(doorKnown: Bool, doorOpen: Bool) -> Bool {
        return doorKnown && doorOpen
    }

    /// 围栏外的降耗判据：只有「确实离得很远、且结论可信」时才允许降到粗档。
    ///
    /// - Parameters:
    ///   - dist: 手机与车的距离（米），NaN 表示算不出来
    ///   - acc: 手机定位精度（米）
    ///   - fenceM: 围栏半径（米）
    static func canGoCoarse(dist: Double, acc: Double, fenceM: Double) -> Bool {
        if dist.isNaN || fenceM <= 0 { return false }
        if acc > 500 { return false }
        // 留 20% 余量：漂到围栏边上就先升档，别等真的走到车边才反应
        return dist > fenceM * 1.2
    }

    /// 「车锁状态由未锁翻成已锁」的那一刻，人是不是就在车旁？
    ///
    /// 这个判断专门用来堵一个很危险的误触发：熄火下车、关门后车辆**自己上锁**，
    /// 此时手机还在裤兜里（蓝牙连着、信号很强）。若不做处理，下一拍就会判定
    /// 「靠近 + 已锁 + 本次到访还没开过」→ 立刻把车又解开。
    ///
    /// 判据不能只看「已锁 + 靠近」，因为「走向一辆本来就锁着的车」也是这个形状，
    /// 那种情况必须正常开锁。区别在于：车辆自锁会发生一次 **false → true 的翻转**，
    /// 而走向一辆锁着的车没有翻转。
    static func suppressUnlockOnArmedFlip(wasArmed: Bool, nowArmed: Bool, near: Bool) -> Bool {
        return !wasArmed && nowArmed && near
    }

    // MARK: iOS 专用的「靠近」判定

    /// 「靠近」在 iOS 上怎么算。与 Android 有一处关键差异，别照抄。
    ///
    /// Android 后台能稳定读 RSSI，所以 near 完全由信号决定。
    /// iOS 的 `readRSSI` 在后台会被系统限流甚至直接不回调，常常拿不到新鲜值；
    /// 如果坚持用 -127 判距，后台就**永远**不会自动开锁 —— 功能等于没有。
    ///
    /// 所以这里的口径是（已与用户确认的取舍）：
    /// - 有新鲜信号（10 秒内读到过）→ 严格按用户设的门限；
    /// - 没有信号 → 信「能连上」这件事本身。车机能被连上，本身已经意味着
    ///   大概在 10 米以内，比"一律当作很远"更接近事实。
    ///
    /// 误开的兜底不在这里，而在 `decide` 的三道闸门：本次到访已开过不再开、
    /// 开锁冷却 60 秒、车辆行驶中不开。
    static func nearAssumeByLink(rssi: Int, thr: Int, fresh: Bool) -> Bool {
        return fresh ? rssi >= thr : true
    }

    /// RSSI 多旧就算「没有新鲜值」。车机 3 秒一帧，10 秒已经足够宽裕。
    static let RSSI_FRESH_MS: Int64 = 10000

    // MARK: 回执后的二次核实

    /// 没有待核实的事
    static let V_NONE = 0
    /// 车机状态已符合预期
    static let V_CONFIRMED = 1
    /// 不符合预期，但还来得及 → 补一次网络指令
    static let V_FALLBACK = 2
    /// 超出有效窗口 / 用户已经下过反向指令 / 已经补过一次 → 放弃
    static let V_EXPIRE = 3

    /// 待核实状态的有效期：实测回执到状态帧翻转是 2.5~3 秒，20 秒足够宽裕
    static let VERIFY_WINDOW_MS: Int64 = 20000

    /// 蓝牙指令拿到回执之后，用真实状态做二次核实。
    ///
    /// 为什么必须有这一步：实测「控制回执 code=0x00」只代表车机**收到了**，
    /// 车锁有没有真的动要看随后那一帧状态。出现过回执成功但车没锁的情况，
    /// 所以只信回执就直接报「已锁车」是假成功。
    ///
    /// 三种放弃情形都很关键，少一个就会出事故：
    /// - **超出窗口**：20 秒前那次锁车，不能拿现在"未锁"当依据，中间用户可能自己开过锁；
    /// - **意图已变**：核实锁车时若最近的指令是开锁，说明用户改主意了，再补锁就是违逆操作；
    /// - **已补过一次**：防止状态持续不符时无限补发，把同一条指令刷成刷屏。
    ///
    /// - Parameters:
    ///   - expectArmed: 这条指令期望的最终状态（锁车 true / 开锁 false）
    ///   - armedNow: 车机当前上报的状态
    ///   - ageMs: 距拿到回执过去了多久
    ///   - lastWasUnlock: 最近一次动作是不是开锁（用来判断意图有没有变）
    ///   - rounds: 这条指令已经补发过几次
    static func verify(expectArmed: Bool, armedNow: Bool, ageMs: Int64,
                       lastWasUnlock: Bool, rounds: Int) -> Int {
        if armedNow == expectArmed {
            return V_CONFIRMED
        }
        if ageMs > VERIFY_WINDOW_MS {
            return V_EXPIRE
        }
        // 最近一次动作的方向要和 expectArmed 一致，否则说明中间已经被反向操作覆盖
        let sameIntent = (lastWasUnlock != expectArmed)
        if !sameIntent {
            return V_EXPIRE
        }
        if rounds >= 1 {
            return V_EXPIRE
        }
        return V_FALLBACK
    }

    /// 省电退避阈值：信号弱到这个程度就主动断开蓝牙，省得空耗。
    ///
    /// 必须**明显低于**用户设的解锁门限——否则「门限还没到就先断了」，
    /// 靠近判定永远不成立，用户把门限调低（比如 -90）反而彻底开不了锁。
    static func dropThreshold(_ unlockThr: Int) -> Int {
        return min(-88, unlockThr - 15)
    }
}
