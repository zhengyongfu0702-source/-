import Foundation

/// 按「手机与车的实际距离」决定开锁 / 锁车。
///
/// 与 `Logic.decide`（蓝牙 RSSI 判据）二选一，由 `AutoEngine` 按 `Geo.usable` 的结果挑选。
/// 与 Android 的 `Logic.decideGeo` 一一对应，三处刻意的不对称全部保留，原因都写在下面对应位置。
enum Geo {

    static let NONE = Logic.NONE
    static let UNLOCK = Logic.UNLOCK
    static let LOCK = Logic.LOCK

    // MARK: 门限

    struct Cfg {
        /// 总开关。关掉就永远回落到蓝牙判据
        var enabled = true
        var autoUnlock = true
        var autoLock = true

        /// 靠近门限（米）：点估计落在它之内算「在车旁」
        var inM: Double = 10
        /// 离开门限（米）：必须明显超过它才算「走了」。
        /// 与 inM 之间这段是**死区**，专门吃掉 GPS 在门限线上来回飘导致的
        /// 开锁→锁车→开锁连发。
        var outM: Double = 30

        /// 判「近」能容忍的最大定位误差（米）。误差比门限本身还大时，判近没有意义
        var accNearM: Double = 30
        /// 判「远」放宽一些，否则在地库里永远不敢锁车
        var accFarM: Double = 80

        /// 手机定位多久算新鲜。超过它就不用这份数据——人可能已经走远，系统还没更新
        var phoneFreshMs: Int64 = 120_000
        /// 车机位置最旧能接受多久。停车后本来就不再上报，所以给得很宽
        var carLocMaxAgeMs: Int64 = 30 * 24 * 3600 * 1000

        /// 连续多少拍方向一致才动作
        var confirmTicks = 2
        var unlockCooldownMs: Int64 = 60_000
        var lockCooldownMs: Int64 = 60_000
        /// 离开多久之后重置「本次到访已开过锁」，下次走近才能再开
        var awayMs: Int64 = 30_000

        /// 行使否决权所需的信号余量（dB）：RSSI 至少强于「靠近门限」这么多，才允许否决判远。
        ///
        /// 蓝牙能穿墙。这台车贴车时在 -70 上下，隔一层楼板衰减 10~15dB 变成 -82~-85。
        /// 若只判「连着就否决」，人在二楼、车在楼下 25 米，就既不开锁也不锁车——
        /// 车整夜停着没锁，而卡片显示「距车 25 米 · 判据：定位」，一切看着正常。
        var vetoSlackDb = 6

        /// 否决最长有效时长。超过之后 GPS 说远就照锁，不再听蓝牙的。
        ///
        /// 5 分钟是权衡：真贴着车走动的人不会在外面站 5 分钟还被判远；
        /// 而「人在楼里、车在楼下」这种，最多晚 5 分钟锁上，不会整夜不锁。
        var vetoMaxMs: Int64 = 5 * 60 * 1000
    }

    // MARK: 输入状态

    struct St {
        // 车机位置
        var carValid = false
        var carLat = 0.0
        var carLng = 0.0
        /// 车机最后一次上报定位的时刻；停车后不再更新，用来看这个位置有多旧
        var carLocAt: Int64 = 0

        // 手机位置
        var phoneValid = false
        var phoneLat = 0.0
        var phoneLng = 0.0
        /// 水平精度半径（米）
        var phoneAcc = 9999.0
        var phoneFixAt: Int64 = 0

        var now: Int64 = 0
        var armedKnown = false
        var armed = false
        var moving = false
        var busy = false

        /// 算出来的直线距离（米）。NaN 表示算不出来
        var dist = Double.nan

        /// 蓝牙佐证：连着、有新鲜帧、信号够强 —— 人确实贴着车
        var bleNear = false
        /// 蓝牙否决：连着、有新鲜帧、信号没弱太多 → 无论 GPS 说什么都不该判「离开」
        ///
        /// 两条限权见 `Cfg.vetoSlackDb` / `Cfg.vetoMaxMs`。少了任何一条，
        /// 人在楼上、蓝牙穿墙还连着，就永远不会判「离开」—— 车整夜不锁。
        var bleVeto = false
        /// 本轮否决从什么时候开始；0 表示当前没有在否决
        var vetoSince: Int64 = 0

        var visited = false
        var unlockedThisVisit = false
        var lastUnlockAt: Int64 = 0
        var lastLockAt: Int64 = 0
        /// 连续判定在近处 / 远处的次数，由 decide 就地累加
        var nearTicks = 0
        var farTicks = 0
        /// 本次「离开」从什么时候开始算；0 表示没在离开
        var farSince: Int64 = 0
        /// 最近一次判定在近处的时刻
        var lastNearAt: Int64 = 0
    }

    // MARK: 几何

    private static let earthR = 6_371_000.0

    /// 坐标是否可信。`(0,0)` 必须挡掉：没定位成功时平台常回 0，
    /// 拿它去算距离会得出「车在几内亚湾」，后果是站在车边被判成几千公里外。
    static func valid(_ lat: Double, _ lng: Double) -> Bool {
        if !lat.isFinite || !lng.isFinite { return false }
        if lat == 0 && lng == 0 { return false }
        if abs(lat) > 90 || abs(lng) > 180 { return false }
        return true
    }

    /// Haversine 直线距离（米）
    static func distance(_ lat1: Double, _ lng1: Double,
                         _ lat2: Double, _ lng2: Double) -> Double {
        if !valid(lat1, lng1) || !valid(lat2, lng2) { return Double.nan }
        let rad = Double.pi / 180
        let p1 = lat1 * rad
        let p2 = lat2 * rad
        let dp = (lat2 - lat1) * rad
        let dl = (lng2 - lng1) * rad
        let a = sin(dp / 2) * sin(dp / 2) + cos(p1) * cos(p2) * sin(dl / 2) * sin(dl / 2)
        let c = 2 * atan2(sqrt(a), sqrt(max(0, 1 - a)))
        return earthR * c
    }

    /// 这套判据此刻能不能用。
    ///
    /// 四个条件缺一个就必须老实回落到蓝牙——而不是「拿个大概的数字凑合判一下」。
    /// 因为两个方向的误判都很难受：30 米外把车解开（东西可能被顺走），
    /// 或者站在车边被锁上（还得掏手机）。
    static func usable(_ s: St, _ c: Cfg) -> Bool {
        if !c.enabled { return false }
        if !s.carValid || !s.phoneValid { return false }
        if s.dist.isNaN { return false }
        if s.phoneAcc > max(c.accNearM, c.accFarM) { return false }
        if s.now - s.phoneFixAt > c.phoneFreshMs { return false }
        if s.carLocAt > 0 && s.now - s.carLocAt > c.carLocMaxAgeMs { return false }
        return true
    }

    // MARK: 决策

    /// 纯函数式决策；会就地更新 nearTicks / farTicks / farSince / visited / unlockedThisVisit。
    static func decide(_ s: inout St, _ c: Cfg) -> Int {
        if !usable(s, c) {
            s.nearTicks = 0
            s.farTicks = 0
            return NONE
        }

        let near = s.bleNear || (s.dist <= c.inM && s.phoneAcc <= c.accNearM)
        let far = !s.bleNear && !s.bleVeto && s.dist >= c.outM && s.phoneAcc <= c.accFarM

        if near {
            s.nearTicks += 1
            s.farTicks = 0
            s.farSince = 0
            s.visited = true
            s.lastNearAt = s.now
        } else if far {
            s.farTicks += 1
            s.nearTicks = 0
            if s.farSince == 0 { s.farSince = s.now }
        } else {
            // 死区 / 数据勉强：两个计数都清零，谁也别想靠累积蒙过去
            s.nearTicks = 0
            s.farTicks = 0
            s.farSince = 0
        }

        // 确认「真的走了」之后本次到访才算结束。这里用「离开持续时长」而不是
        // 「判远一次」——否则 GPS 跳一下就把「刚在车旁手动锁过车」这个保护清掉，
        // 车会自己又弹开。
        if s.farSince > 0 && (s.now - s.farSince) > c.awayMs {
            s.unlockedThisVisit = false
        }

        if s.busy || !s.armedKnown { return NONE }

        // ① 在车旁且车锁着 → 开锁。
        // 判近要连续两拍；但蓝牙同时证明「贴着了」就免确认——那条信号比 GPS 精确得多。
        let needNear = s.bleNear ? 1 : max(1, c.confirmTicks)
        if c.autoUnlock && s.armed && !s.moving && near && !s.unlockedThisVisit
            && s.nearTicks >= needNear
            && (s.now - s.lastUnlockAt) > c.unlockCooldownMs {
            return UNLOCK
        }

        // ② 确实走远了 → 锁车。必须本次到访真的到过车旁，
        // 否则车停别处会无限下发锁车指令。
        if c.autoLock && !s.armed && !s.moving && s.visited && !near && far
            && s.farTicks >= max(1, c.confirmTicks)
            && (s.now - s.lastLockAt) > c.lockCooldownMs {
            return LOCK
        }

        return NONE
    }

    /// 给界面用的一句话：「距车 8 米（误差 ±5 米）」
    static func distanceText(_ meters: Double) -> String {
        if meters.isNaN { return "—" }
        if meters < 1000 {
            return String(format: "距车 %.0f 米", meters)
        }
        return String(format: "距车 %.1f 公里", meters / 1000)
    }
}
