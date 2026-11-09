//
//  顺心控车 Lite · iOS 全部源码（单文件版）
//
//  为什么合并：GitHub 网页上传时，二十几个文件分散在多个目录里，
//  要重复多次「进目录 → Upload files → 选文件 → 提交」，容易漏、
//  也容易传错目录；一旦漏传，编译出的包会出现「版本号是新的、
//  功能还是旧的」这种最难查的情况。
//
//  合并后，整个工程的源码只在这个文件里，上传一次就覆盖全部。
//  小组件的两个文件不在这里 —— 它们是独立 target，单独上传。
//
//  各段顺序与原文件名一一对应，段落之间用分隔线标出。
//

import Foundation
import CommonCrypto
import CoreLocation
import UIKit
import UserNotifications
import CoreBluetooth
import Combine
import WidgetKit
import SwiftUI


// ==========================================================================
//  SXKC/Core/Hex.swift  ——  基础：十六进制
// ==========================================================================

/// 十六进制与字节数组互转。与 Android 版 Hex.java 行为逐字节一致：
/// 输入含非法字符时返回空数组，长度为奇数时左补 0。
enum Hex {

    private static let upper: [Character] = Array("0123456789ABCDEF")

    static func of(_ b: [UInt8]) -> String {
        var out = ""
        out.reserveCapacity(b.count * 2)
        for v in b {
            out.append(upper[Int(v >> 4)])
            out.append(upper[Int(v & 0x0F)])
        }
        return out
    }

    static func of(_ d: Data) -> String {
        return of([UInt8](d))
    }

    static func to(_ s: String) -> [UInt8] {
        var t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.isEmpty { return [] }
        if t.count % 2 != 0 { t = "0" + t }
        var out = [UInt8]()
        out.reserveCapacity(t.count / 2)
        var idx = t.startIndex
        while idx < t.endIndex {
            let next = t.index(idx, offsetBy: 2)
            guard let byte = UInt8(t[idx..<next], radix: 16) else { return [] }
            out.append(byte)
            idx = next
        }
        return out
    }

    static func data(_ s: String) -> Data {
        return Data(to(s))
    }
}


// ==========================================================================
//  SXKC/Core/Crypto.swift  ——  基础：加解密
// ==========================================================================

/// AES-128-ECB / SHA1 / HMAC-SHA1。
///
/// 与 Android 版 Crypto.java 对齐：ECB、无填充、单块 16 字节。
/// HMAC 这里手写（而不是直接调 CCHmac），是为了在空密钥时行为与 Java 端完全一致，
/// 避免 CCHmac 对 NULL 指针的处理差异导致签名对不上、服务端报错。
enum Crypto {

    enum CryptoError: Error, LocalizedError {
        case aesFailed(Int32)
        case badKeySize

        var errorDescription: String? {
            switch self {
            case .aesFailed(let s): return "AES 运算失败 (CCCrypt status=\(s))"
            case .badKeySize: return "密钥不是 16 字节"
            }
        }
    }

    // MARK: - AES-128-ECB / NoPadding

    static func aesEncrypt(_ key: [UInt8], _ data: [UInt8]) throws -> [UInt8] {
        return try crypt(op: CCOperation(kCCEncrypt), key: key, data: data)
    }

    static func aesDecrypt(_ key: [UInt8], _ data: [UInt8]) throws -> [UInt8] {
        return try crypt(op: CCOperation(kCCDecrypt), key: key, data: data)
    }

    private static func crypt(op: CCOperation, key: [UInt8], data: [UInt8]) throws -> [UInt8] {
        let blockSize = 16
        guard key.count == 16 else { throw CryptoError.badKeySize }
        guard !data.isEmpty, data.count % blockSize == 0 else {
            throw CryptoError.aesFailed(-1)
        }
        var out = [UInt8](repeating: 0, count: data.count + blockSize)
        // 容量必须先取出来：下面 withUnsafeMutableBytes 的闭包持有 out 的独占写权限，
        // 在闭包里再读 out.count 会触发 "overlapping accesses to 'out'" 编译错误。
        let outCap = out.count
        var outLen = 0
        let status: CCCryptorStatus = key.withUnsafeBytes { keyPtr -> CCCryptorStatus in
            data.withUnsafeBytes { dataPtr -> CCCryptorStatus in
                out.withUnsafeMutableBytes { outPtr -> CCCryptorStatus in
                    CCCrypt(op,
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionECBMode),
                            keyPtr.baseAddress, key.count, nil,
                            dataPtr.baseAddress, data.count,
                            outPtr.baseAddress, outCap,
                            &outLen)
                }
            }
        }
        guard status == kCCSuccess else { throw CryptoError.aesFailed(status) }
        return Array(out[0..<outLen])
    }

    // MARK: - SHA1

    static func sha1(_ bytes: [UInt8]) -> [UInt8] {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        if bytes.isEmpty {
            CC_SHA1(nil, 0, &digest)
        } else {
            bytes.withUnsafeBytes { p in
                _ = CC_SHA1(p.baseAddress, CC_LONG(bytes.count), &digest)
            }
        }
        return digest
    }

    static func sha1Upper(_ text: String) -> String {
        return Hex.of(sha1(Array(text.utf8)))
    }

    /// 协议签名：HMAC-SHA1 后转大写 HEX，密钥为空串（与 Java 端手写实现等价）
    static func hmacSha1Upper(_ key: String, _ text: String) -> String {
        var k = [UInt8](repeating: 0, count: 64)
        let raw = Array(key.utf8)
        let n = min(raw.count, 64)
        for i in 0..<n { k[i] = raw[i] }

        var ipad = [UInt8](repeating: 0, count: 64)
        var opad = [UInt8](repeating: 0, count: 64)
        for i in 0..<64 {
            ipad[i] = 0x36 ^ k[i]
            opad[i] = 0x5C ^ k[i]
        }
        let inner = sha1(ipad + Array(text.utf8))
        return Hex.of(sha1(opad + inner))
    }
}


// ==========================================================================
//  SXKC/Core/Frame.swift  ——  组帧与解析（门位就在这里）
// ==========================================================================

/// 蓝牙帧构造。已用实车抓包逐字节验证：
/// ```
/// 明文 19B : FF 12 <11|12> type seq payload(14B)
/// 线上 20B : FF 12 <11|12> + AES128-ECB(key, 明文[3..19]) + CRC8
/// CRC8     : sum(明文 19 字节) & 0xFF
/// key      : 握手=btkey，业务=btrand
/// btrand   : btrandkey + "FFFF"；btrandkey 由毫秒时间戳派生
/// ```
enum Frame {

    static let TYPE_CTRL = 0x12
    static let TYPE_HANDSHAKE = 0x31
    static let TYPE_STATUS = 0x69

    static func crc(_ plain: [UInt8]) -> UInt8 {
        var s = 0
        for b in plain { s += Int(b) }
        return UInt8(s & 0xFF)
    }

    static func build(type: Int,
                      seq: Int,
                      payload: [UInt8],
                      key: [UInt8],
                      handshake: Bool) throws -> [UInt8] {

        var body = [UInt8](repeating: 0, count: 16)
        body[0] = UInt8(type & 0xFF)
        body[1] = UInt8(seq & 0xFF)
        let n = min(payload.count, 14)
        if n > 0 {
            for i in 0..<n { body[2 + i] = payload[i] }
        }

        var plain = [UInt8](repeating: 0, count: 19)
        plain[0] = 0xFF
        plain[1] = 0x12
        plain[2] = handshake ? 0x11 : 0x12
        for i in 0..<16 { plain[3 + i] = body[i] }

        let cipher = try Crypto.aesEncrypt(key, body)

        var out = [UInt8](repeating: 0, count: 20)
        out[0] = plain[0]
        out[1] = plain[1]
        out[2] = plain[2]
        for i in 0..<16 { out[3 + i] = cipher[i] }
        out[19] = crc(plain)
        return out
    }

    /// 解密线上帧的 16 字节主体；**帧头或 CRC 不对就返回 nil**。
    ///
    /// 这一步必须校验：AES/ECB/NoPadding 解密任何 16 字节都会"成功"，
    /// 若只靠返回值判断，用错密钥时拿到的是 16 字节随机数，永远不会走到兜底分支。
    static func open(_ frame: [UInt8], _ key: [UInt8]) -> [UInt8]? {
        guard frame.count >= 20, key.count == 16 else { return nil }
        guard frame[0] == 0xFF, frame[1] == 0x12 else { return nil }

        let body = Array(frame[3..<19])
        guard let plain = try? Crypto.aesDecrypt(key, body), plain.count == 16 else { return nil }

        var full = [UInt8](repeating: 0, count: 19)
        full[0] = 0xFF
        full[1] = 0x12
        full[2] = frame[2]
        for i in 0..<16 { full[3 + i] = plain[i] }

        guard frame[19] == crc(full) else { return nil }
        return plain
    }

    /// btrandkey：28 位，由毫秒时间戳派生（原样照抄 BleG801.cmdValid）
    static func btrandKey(_ tMs: Int64) -> String {
        var s = String(tMs)
            + String(tMs / 123456)
            + String(tMs / 1234567)
            + String(tMs / 12345678)
        if s.count >= 28 {
            return String(s.prefix(28))
        }
        while s.count < 28 { s += "0" }
        return s
    }

    /// 状态帧 body[5] 的 0x20 位表示已设防（已锁）
    static func armedOfStatusBody(_ body: [UInt8]) -> Bool {
        return body.count > 5 && (body[5] & 0x20) != 0
    }

    /// 状态帧 body[5] 的原始字节，日志里直接打出来方便对比
    static func statusFlags(_ body: [UInt8]) -> String {
        guard body.count > 5 else { return "--" }
        return String(format: "%02X", body[5])
    }

    /// 是否有车门开着。
    ///
    /// 门位在 `body[3]` 的低 4 位，来自原版 `UtilsField.parseVstStatus`：
    /// `dor_lf=0x08 / dor_lb=0x02 / dor_rf=0x04 / dor_rb=0x01`。
    ///
    /// **但这台车机不区分具体是哪扇门**：实测开任意一扇门，原版 App 的车模上
    /// 四个门全部显示"已打开"，帧里就是 `0x0F`；四门全关时是 `0x00`。
    /// 所以这里只做布尔判断，不去解析单独某扇门 —— 解析了也是假的。
    static func anyDoorOpen(_ body: [UInt8]) -> Bool {
        return body.count > 3 && (body[3] & 0x0F) != 0
    }

    /// 尾箱位：`body[3]` 的 bit4（原版 `trunk` 用的就是这个掩码）
    static func trunkOpen(_ body: [UInt8]) -> Bool {
        return body.count > 3 && (body[3] & 0x10) != 0
    }
}


// ==========================================================================
//  SXKC/Core/Geo.swift  ——  地理计算
// ==========================================================================

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


// ==========================================================================
//  SXKC/Core/Loc.swift  ——  定位服务
// ==========================================================================

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


// ==========================================================================
//  SXKC/Core/Logic.swift  ——  判定逻辑（门位闸门在这里）
// ==========================================================================

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


// ==========================================================================
//  SXKC/Core/Power.swift  ——  省电与重连退避
// ==========================================================================

/// 待机省电策略。全部是纯函数，方便脱机断言。
///
/// 三笔耗电账，别凭感觉优化：
/// 1. **网络轮询**（原来 60 秒一次）：每次都要唤醒射频、建 TCP、收发 JSON，
///    射频拖尾通常 5~15 秒。1 分钟一次 ≈ 一天 1400+ 次，这是真正的耗电大头。
/// 2. **蓝牙连接间隔**：常连状态下链路层按连接间隔收发空包。车机状态帧 3 秒才一帧，
///    放宽间隔完全不受影响。
/// 3. **连不上还死命重连**：人车分离时每 4 秒试一次等于让蓝牙控制器空转。
///
/// iOS 补充：CoreBluetooth 不允许自定义连接间隔，所以这里只管节拍与退避；
/// 真正的省电靠「后台不进轮询，只在 BLE 事件里跑一拍」。
enum Power {

    /// 断开状态下重连尝试的最小间隔（熄屏/后台）
    static let RECONNECT_MIN_SCREEN_OFF: Int64 = 30000
    /// 断开状态下重连尝试的最小间隔（亮屏/前台，用户可能就在车边）
    static let RECONNECT_MIN_SCREEN_ON: Int64 = 12000
    /// 重连退避上限
    static let RECONNECT_MAX_SCREEN_OFF: Int64 = 90000
    static let RECONNECT_MAX_SCREEN_ON: Int64 = 45000

    /// 主循环节拍。
    ///
    /// 断开时没必要 1.5 秒醒一次——那时候真正决定效率的是重连退避，不是循环频率。
    /// 连着但在远处（信号弱于门限）放宽到 2.5 秒：走近的过程 2.5 秒足够捕捉到。
    static func tickMs(connected: Bool, near: Bool) -> Int64 {
        if !connected { return 8000 }
        return near ? 1500 : 2500
    }

    /// 网络轮询间隔。
    ///
    /// 关键判断：**蓝牙状态帧在流的时候，锁车状态本来就知道**（车机每 3 秒推一帧），
    /// 这时候再每分钟去服务器问一遍纯属浪费射频。所以有蓝牙就把网络降到 5~10 分钟，
    /// 只当兜底；没有蓝牙（人在外面）才用 3~5 分钟。
    static func pollMs(bleFresh: Bool, screenOn: Bool) -> Int64 {
        if bleFresh {
            return screenOn ? 300000 : 600000
        }
        return screenOn ? 180000 : 300000
    }

    /// 断线后隔多久再尝试连接。连续失败次数越多，退避越久（防止人车分离时长期空转）。
    /// 亮屏时明显更积极：用户拿起手机往往就是要用车。一旦连上就把失败计数清零。
    static func reconnectDelayMs(fails: Int, screenOn: Bool) -> Int64 {
        let base = screenOn ? RECONNECT_MIN_SCREEN_ON : RECONNECT_MIN_SCREEN_OFF
        let cap = screenOn ? RECONNECT_MAX_SCREEN_ON : RECONNECT_MAX_SCREEN_OFF
        var d = base
        var i = 1
        while i < fails && d < cap {
            d *= 2
            i += 1
        }
        return min(d, cap)
    }

    /// 界面说明用：这个轮询间隔相当于一天请求多少次
    static func pollsPerDay(_ pollMs: Int64) -> Int {
        guard pollMs >= 1000 else { return 0 }
        return Int(86400000 / pollMs)
    }

    /// 一天省下来的请求次数（相对 60 秒一次的老逻辑），界面文案用
    static func savedPollsPerDay(_ pollMs: Int64) -> Int {
        return max(0, pollsPerDay(60000) - pollsPerDay(pollMs))
    }
}


// ==========================================================================
//  SXKC/Core/RunLog.swift  ——  运行日志存储
// ==========================================================================

/// 运行日志落盘。
///
/// iOS 的 App 被系统回收时不会有任何回调，界面里的日志全部丢失。
/// 自动模式出问题时（比如该开锁没开、该锁没锁），唯一能回溯的现场就是这份文件。
///
/// 落盘策略与 Android 版一致：
/// - 追加写 `Documents/logs/run.log`；
/// - 超过 512KB 滚动一代到 `run.1.log`，只留一代，不会无限涨；
/// - 异步串行写，绝不阻塞 BLE 回调线程。
///
/// iOS 补充：Documents 目录在「文件」App 里可见（需 Info.plist 打开文件共享），
/// 用户可以把日志导出来，不需要连电脑。
final class RunLog {

    static let shared = RunLog()

    private let queue = DispatchQueue(label: "cn.sxkc.runlog", qos: .utility)
    private let maxBytes: Int = 512 * 1024

    private lazy var dir: URL = {
        let fm = FileManager.default
        let base = fm.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let d = base.appendingPathComponent("logs", isDirectory: true)
        if !fm.fileExists(atPath: d.path) {
            try? fm.createDirectory(at: d, withIntermediateDirectories: true)
        }
        return d
    }()

    private lazy var file: URL = dir.appendingPathComponent("run.log")
    private lazy var bak: URL = dir.appendingPathComponent("run.1.log")

    private lazy var ts: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "MM-dd HH:mm:ss"
        return f
    }()

    private init() {}

    /// 追加一行。任意线程可调用
    func write(_ line: String) {
        let text = ts.string(from: Date()) + "  " + line + "\n"
        queue.async { [weak self] in
            guard let self = self else { return }
            self.rotateIfNeeded()
            guard let data = text.data(using: .utf8) else { return }
            if let h = try? FileHandle(forWritingTo: self.file) {
                h.seekToEndOfFile()
                h.write(data)
                h.closeFile()
            } else {
                try? data.write(to: self.file, options: .atomic)
            }
        }
    }

    private func rotateIfNeeded() {
        let fm = FileManager.default
        guard let attrs = try? fm.attributesOfItem(atPath: file.path),
              let size = attrs[.size] as? Int, size > maxBytes else { return }
        try? fm.removeItem(at: bak)
        try? fm.moveItem(at: file, to: bak)
    }

    /// 读出全部日志（诊断页「后台日志」按钮用）
    func readAll() -> String {
        var out = ""
        if let s = try? String(contentsOf: bak, encoding: .utf8), !s.isEmpty {
            out += "===== 上一代（run.1.log） =====\n" + s + "\n"
        }
        if let s = try? String(contentsOf: file, encoding: .utf8), !s.isEmpty {
            out += "===== 本次（run.log） =====\n" + s
        }
        return out.isEmpty ? "（还没有落盘日志）" : out
    }

    /// 清空：文件与备份一起删
    func clear() {
        queue.async { [weak self] in
            guard let self = self else { return }
            try? FileManager.default.removeItem(at: self.file)
            try? FileManager.default.removeItem(at: self.bak)
        }
    }
}


// ==========================================================================
//  SXKC/Core/Stats.swift  ——  罚站率统计
// ==========================================================================

/// 「罚站率」统计。对应 Android 的 `Stats.java`。
///
/// 行业里衡量数字钥匙好坏只有一个数字：走到车前，多久能开。UWB 约 1% 失败，
/// 纯蓝牙约 10%，头部厂商号称 99.5% 一次成功。没有这个数字，所有门限调整都是凭感觉。
///
/// 口径刻意简单：
/// - **一次成功**：第一次下发就成功，且耗时 ≤ 3 秒；
/// - **慢**：成功了但超过 3 秒 —— 人已经在车门前站着了，这就是罚站；
/// - **失败**：两条通道都没成。
///
/// 罚站率 =（慢 + 失败）/ 总次数。
enum Stats {

    private static let kUN = "st_u_n"
    private static let kUOK = "st_u_ok"
    private static let kUSlow = "st_u_slow"
    private static let kUBle = "st_u_ble"
    private static let kUNet = "st_u_net"
    private static let kURace = "st_u_race"
    private static let kUMs = "st_u_ms"
    private static let kUMsn = "st_u_msn"
    private static let kULat = "st_u_lat"
    private static let kLN = "st_l_n"
    private static let kLOK = "st_l_ok"
    private static let kLast = "st_last"

    /// 超过这个耗时就算「罚站」
    static let slowMs: Int64 = 3000
    /// 保留多少个耗时样本用来算 P95
    private static let keep = 40

    private static var d: UserDefaults { UserDefaults.standard }

    /// 记一次开锁结果。
    /// - Parameters:
    ///   - ch: `Logic.CH_BLE` / `Logic.CH_NET`；没成功传 0
    ///   - ms: 从下发到确认成功（或放弃）的耗时
    ///   - ok: 最终是否开成
    ///   - raced: 这一笔是不是双通道竞速
    static func unlockResult(ch: Int, ms: Int64, ok: Bool, raced: Bool) {
        let n = d.integer(forKey: kUN) + 1
        d.set(n, forKey: kUN)
        if ok {
            d.set(d.integer(forKey: kUOK) + 1, forKey: kUOK)
            if ms > slowMs {
                d.set(d.integer(forKey: kUSlow) + 1, forKey: kUSlow)
            }
            if ch == Logic.CH_BLE {
                d.set(d.integer(forKey: kUBle) + 1, forKey: kUBle)
            } else if ch == Logic.CH_NET {
                d.set(d.integer(forKey: kUNet) + 1, forKey: kUNet)
            }
            if raced {
                d.set(d.integer(forKey: kURace) + 1, forKey: kURace)
            }
            d.set(d.double(forKey: kUMs) + Double(max(0, ms)), forKey: kUMs)
            d.set(d.integer(forKey: kUMsn) + 1, forKey: kUMsn)
            d.set(pushLat(ms), forKey: kULat)
        }
        d.set((ok ? "✓ 开锁 " : "✗ 开锁失败 ") + (ms > 0 ? String(format: "%.1f 秒", Double(ms) / 1000.0) : ""),
              forKey: kLast)
    }

    /// 记一次锁车结果（只关心成功率，锁车慢一点人不难受）
    static func lockResult(ok: Bool) {
        d.set(d.integer(forKey: kLN) + 1, forKey: kLN)
        if ok {
            d.set(d.integer(forKey: kLOK) + 1, forKey: kLOK)
        }
    }

    /// 给人看的一段摘要
    static func summary() -> String {
        let n = d.integer(forKey: kUN)
        if n == 0 {
            return "还没有开锁记录。用几天后再来看这个数字。"
        }
        let ok = d.integer(forKey: kUOK)
        let slow = d.integer(forKey: kUSlow)
        let bled = d.integer(forKey: kUBle)
        let neted = d.integer(forKey: kUNet)
        let raced = d.integer(forKey: kURace)
        let sum = d.double(forKey: kUMs)
        let msn = d.integer(forKey: kUMsn)
        let stuck = (n - ok) + slow

        var s = "开锁 \(n) 次 · 一次成功 \(ok)（\(pct(ok, n))%）"
        if msn > 0 {
            s += " · 均 \(one(sum / Double(msn) / 1000.0)) 秒"
        }
        let p95 = percentile(95)
        if p95 > 0 {
            s += " · P95 \(one(Double(p95) / 1000.0)) 秒"
        }
        s += "\n罚站 \(stuck) 次 · 罚站率 \(pct(stuck, n))%（慢 \(slow) / 失败 \(n - ok)）"
        s += "\n通道：蓝牙 \(bled) · 网络 \(neted)"
        if raced > 0 {
            s += " · 竞速 \(raced)"
        }
        let ln = d.integer(forKey: kLN)
        if ln > 0 {
            s += "\n锁车 \(ln) 次 · 成功 \(d.integer(forKey: kLOK))（\(pct(d.integer(forKey: kLOK), ln))%）"
        }
        let last = d.string(forKey: kLast) ?? ""
        if !last.isEmpty {
            s += "\n最近：\(last)"
        }
        return s
    }

    static func reset() {
        for k in [kUN, kUOK, kUSlow, kUBle, kUNet, kURace, kUMs, kUMsn, kULat,
                  kLN, kLOK, kLast] {
            d.removeObject(forKey: k)
        }
    }

    // MARK: - 内部

    private static func pushLat(_ ms: Int64) -> String {
        var list = (d.string(forKey: kULat) ?? "")
            .split(separator: ",")
            .compactMap { Int64($0) }
        list.append(ms)
        while list.count > keep {
            list.removeFirst()
        }
        return list.map(String.init).joined(separator: ",")
    }

    private static func percentile(_ p: Int) -> Int64 {
        let list = (d.string(forKey: kULat) ?? "")
            .split(separator: ",")
            .compactMap { Int64($0) }
            .sorted()
        if list.count < 3 { return 0 }
        var idx = Int(ceil(Double(list.count) * Double(p) / 100.0)) - 1
        if idx < 0 { idx = 0 }
        if idx >= list.count { idx = list.count - 1 }
        return list[idx]
    }

    private static func pct(_ a: Int, _ b: Int) -> String {
        if b <= 0 { return "0" }
        return one(Double(a) * 100.0 / Double(b))
    }

    private static func one(_ v: Double) -> String {
        return String(format: "%.1f", v)
    }
}


// ==========================================================================
//  SXKC/Core/Store.swift  ——  本地存储
// ==========================================================================

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


// ==========================================================================
//  SXKC/Core/Notify.swift  ——  通知（门没关好的强提醒在这里）
// ==========================================================================

/// 自动动作的「声音与手感」。
///
/// 对应 Android 的 `Notify.java`。三个场景、三种处理：
/// - **自动锁车成功** → 一条本地通知「已自动锁车 · 距车 42 米」。安静，事后能查；
/// - **开锁成功** → 只轻震一下（UIImpactFeedbackGenerator），不弹通知；
/// - **自动锁车连续 3 次失败** → 强提醒 + 「手动锁车」按钮，点一下就在后台锁。
///
/// 为什么必须有：之前自动锁车完全静默，车锁了、手机在兜里，用户只能回头看车灯。
/// 特斯拉 2026 年那次「人在五楼、车没锁、后备箱被偷」的案子，问题不只是没锁，
/// 还在于车主**一直以为锁了** —— 没有任何反馈。
final class Notify: NSObject {

    static let shared = Notify()

    /// 通知里的「手动锁车」动作标识
    static let actionManualLock = "SXKC_MANUAL_LOCK"
    /// 通知分类：带「手动锁车」按钮
    static let catLockFailed = "SXKC_LOCK_FAILED"
    /// 通知分类：门没关好所以没锁车，带「仍然锁车」按钮
    static let catDoorOpen = "SXKC_DOOR_OPEN"

    private var asked = false

    private override init() {
        super.init()
    }

    /// 注册分类 + 申请权限。重复调用无副作用。
    func setup() {
        let center = UNUserNotificationCenter.current()
        let lock = UNNotificationAction(identifier: Notify.actionManualLock,
                                        title: "手动锁车",
                                        options: [.foreground])
        let cat = UNNotificationCategory(identifier: Notify.catLockFailed,
                                         actions: [lock],
                                         intentIdentifiers: [],
                                         options: [])
        let still = UNNotificationAction(identifier: Notify.actionManualLock,
                                         title: "仍然锁车",
                                         options: [.foreground])
        let cat2 = UNNotificationCategory(identifier: Notify.catDoorOpen,
                                          actions: [still],
                                          intentIdentifiers: [],
                                          options: [])
        center.setNotificationCategories([cat, cat2])

        if asked { return }
        asked = true
        center.requestAuthorization(options: [.alert, .sound, .badge]) { ok, err in
            if !ok {
                // 拿不到权限不是错误路径：后面的 notify 会静默失败，功能本身照常
                AutoEngine.shared.log("⚠ 通知未授权，自动锁车不会有提醒（可在系统设置里打开）")
            }
            if let e = err {
                AutoEngine.shared.log("⚠ 通知授权异常：\(e.localizedDescription)")
            }
        }
    }

    /// 自动锁车成功。
    /// - Parameter distText: 例如「距车 42 米」；算不出距离时传空串
    @discardableResult
    func autoLocked(distText: String) -> Bool {
        let c = UNMutableNotificationContent()
        c.title = "已自动锁车"
        c.body = distText.isEmpty ? "车辆已上锁" : distText
        // 不设 sound：锁车是"应该发生的事"，出声反而吵
        c.sound = nil
        post(id: "sxkc.auto.locked", content: c)
        return true
    }

    /// 自动锁车连续失败 —— 唯一需要人当场介入的情形。
    @discardableResult
    func lockFailed(why: String) -> Bool {
        let c = UNMutableNotificationContent()
        c.title = "车还没锁上"
        c.body = "连续 3 次自动锁车都没成功，点「手动锁车」立刻再试一次"
        c.sound = .default
        c.categoryIdentifier = Notify.catLockFailed
        post(id: "sxkc.auto.lockfailed", content: c)
        return true
    }

    /// 门没关好，所以这次没有下发锁车指令。
    ///
    /// 和「锁车失败」并列但性质不同：失败是发了指令车没应，
    /// 这里是**我们主动没发**，因为门开着锁了也不算数。
    /// 通知上给「仍然锁车」：有时候人就是想先把车锁上再去关门，不能被判断卡住。
    @discardableResult
    func doorBlocked(doorOpen: Bool, trunk: Bool) -> Bool {
        let what: String
        if doorOpen && trunk {
            what = "车门和尾箱都没关好"
        } else if trunk {
            what = "尾箱没关好"
        } else {
            what = "有车门没关好"
        }
        let c = UNMutableNotificationContent()
        c.title = "\(what)，没有自动锁车"
        c.body = "门开着锁了也等于没锁。关好门会自动补锁；想现在就锁，点「仍然锁车」。"
        c.sound = .default
        c.categoryIdentifier = Notify.catDoorOpen
        post(id: "sxkc.auto.dooropen", content: c)
        return true
    }

    /// 门关好了就把那条「没锁车」撤掉，否则会一直挂在通知中心里
    func clearDoorBlocked() {
        UNUserNotificationCenter.current()
            .removeDeliveredNotifications(withIdentifiers: ["sxkc.auto.dooropen"])
        UNUserNotificationCenter.current()
            .removePendingNotificationRequests(withIdentifiers: ["sxkc.auto.dooropen"])
    }

    /// 锁上之后把失败通知撤掉，免得留在通知中心误导
    func clearLockFailed() {
        UNUserNotificationCenter.current()
            .removeDeliveredNotifications(withIdentifiers: ["sxkc.auto.lockfailed"])
        UNUserNotificationCenter.current()
            .removePendingNotificationRequests(withIdentifiers: ["sxkc.auto.lockfailed"])
    }

    /// 开锁成功：只给手感。`UIImpactFeedbackGenerator` 在主线程用，且要 prepare 才跟手
    func unlockTick() {
        let g = UIImpactFeedbackGenerator(style: .light)
        g.prepare()
        g.impactOccurred()
    }

    /// 手动操作失败：更轻的一下，不打扰
    func failTick() {
        let g = UINotificationFeedbackGenerator()
        g.notificationOccurred(.warning)
    }

    // MARK: - 内部

    private func post(id: String, content: UNMutableNotificationContent) {
        let req = UNNotificationRequest(identifier: id, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(req) { err in
            if let e = err {
                AutoEngine.shared.log("⚠ 通知发送失败：\(e.localizedDescription)")
            }
        }
    }
}


// ==========================================================================
//  SXKC/Core/Cards.swift  ——  卡片顺序与隐藏
// ==========================================================================

/// 主界面卡片的身份。顺序与「显示 / 隐藏」存在本地，改完立刻生效。
///
/// 为什么要有这一层：卡片原本是写死在 `VStack` 里的九块，谁想把自己不看的
/// 「运行日志」挪到底下、把「手动控车」顶到最上面，只能等我改代码重新出包。
/// 现在顺序是数据，不是代码。
///
/// `allCases` 的声明顺序就是**默认顺序**，也就是 1.16 之前的写死顺序 —— 老用户
/// 升级上来看到的布局和以前一模一样，不会突然被重排。
enum CardID: String, CaseIterable {
    case status    // 车辆状态
    case actions   // 手动控车
    case loc       // 定位判距
    case auto      // 自动模式
    case wash      // 洗车 / 代客模式
    case stats     // 开锁表现
    case slider    // 距离与延时
    case console   // 运行日志
    case account   // 账号

    var title: String {
        switch self {
        case .status:  return "车辆状态"
        case .actions: return "手动控车"
        case .loc:     return "定位判距"
        case .auto:    return "自动模式"
        case .wash:    return "洗车 / 代客模式"
        case .stats:   return "开锁表现"
        case .slider:  return "距离与延时"
        case .console: return "运行日志"
        case .account: return "账号与版本"
        }
    }

    /// 一句话说明，排序页里给人看，避免只看标题不知道那张卡是干嘛的
    var hint: String {
        switch self {
        case .status:  return "锁车状态、蓝牙信号、与车的距离"
        case .actions: return "开锁 / 锁车 / 启动 / 熄火"
        case .loc:     return "定位判距开关、后台定位、当前距离"
        case .auto:    return "自动模式总开关，竞速 / 围栏 / 通知"
        case .wash:    return "洗车、代客泊车时暂停自动判定"
        case .stats:   return "罚站率、P95 耗时、各通道次数"
        case .slider:  return "靠近门限、信号门限、蓝牙锁车门限"
        case .console: return "最近运行日志，出问题先看这里"
        case .account: return "当前账号、退出登录、版本号"
        }
    }
}

enum Cards {
    private static let kOrder = "card_order"
    private static let kHidden = "card_hidden"

    private static var d: UserDefaults { UserDefaults.standard }

    /// 当前顺序。存的是逗号分隔的 rawValue。
    ///
    /// 读取时做两件事：丢掉已经不存在的 id（版本升级删过卡片时），
    /// 把新加的卡片补到末尾。这样老数据永远不会让界面漏卡或崩。
    static var order: [CardID] {
        get {
            var out: [CardID] = []
            let raw = d.string(forKey: kOrder) ?? ""
            for p in raw.split(separator: ",") {
                if let c = CardID(rawValue: String(p)), !out.contains(c) {
                    out.append(c)
                }
            }
            for c in CardID.allCases where !out.contains(c) {
                out.append(c)
            }
            return out
        }
        set {
            d.set(newValue.map { $0.rawValue }.joined(separator: ","), forKey: kOrder)
        }
    }

    static var hidden: Set<String> {
        get {
            let raw = d.string(forKey: kHidden) ?? ""
            return Set(raw.split(separator: ",").map { String($0) })
        }
        set {
            d.set(newValue.sorted().joined(separator: ","), forKey: kHidden)
        }
    }

    static func isHidden(_ c: CardID) -> Bool {
        return hidden.contains(c.rawValue)
    }

    /// 主界面真正要渲染的卡片，顺序已排好、隐藏的已剔除
    static var visible: [CardID] {
        return order.filter { !isHidden($0) }
    }

    /// 至少留一张。全关掉主界面就是一片空白，用户会以为 App 坏了。
    static func canHide(_ c: CardID) -> Bool {
        if isHidden(c) { return true }
        return visible.count > 1
    }

    static func reset() {
        d.removeObject(forKey: kOrder)
        d.removeObject(forKey: kHidden)
    }
}


// ==========================================================================
//  SXKC/Net/CarAPI.swift  ——  网络协议
// ==========================================================================

// MARK: - 极简 JSON 构造器（保持字段顺序）

enum JV {
    case s(String)
    case raw(String)

    var text: String {
        switch self {
        case .s(let v): return "\"" + JEsc.escape(v) + "\""
        case .raw(let v): return v
        }
    }
}

enum JEsc {
    static func escape(_ s: String) -> String {
        var b = ""
        b.reserveCapacity(s.count + 8)
        for scalar in s.unicodeScalars {
            switch scalar {
            case "\"": b += "\\\""
            case "\\": b += "\\\\"
            case "\n": b += "\\n"
            case "\r": b += "\\r"
            case "\t": b += "\\t"
            default:
                if scalar.value < 0x20 {
                    b += String(format: "\\u%04x", scalar.value)
                } else {
                    b.unicodeScalars.append(scalar)
                }
            }
        }
        return b
    }
}

enum JB {
    static func o(_ kv: [(String, JV)]) -> String {
        var b = "{"
        for (i, pair) in kv.enumerated() {
            if i > 0 { b += "," }
            b += "\"" + JEsc.escape(pair.0) + "\":" + pair.1.text
        }
        return b + "}"
    }
}

// MARK: - 会话

/// 登录 / 查状态 / 下发指令。
///
/// 关键约束（实测得出）：
/// - distribute 必须是 sxkc，否则 SE1004 账号不存在
/// - chnl 固定 android，密码字段是 SHA1 大写
/// - 端口 3050（指令）、3010（状态推送）
///
/// iOS 版刻意保留 `chnl=android` 与 `build_model` 伪装的机型串：
/// 服务端按渠道做校验，改成 ios 会被拒。
final class CarAPI {

    static let HOST = "www.zxy268.com"
    static let PORT: UInt16 = 3050
    static let DISTRIBUTE = "sxkc"
    static let CHNL = "android"
    static let VER = "1.0"
    static let AVER = "1.3.3"
    static let CLI_KEY = "android-070466c235ec281d"

    static let CODE_LOGIN = "10001003"
    static let CODE_STATUS = "203100"
    static let CODE_LOCK = "303110"
    static let CODE_UNLOCK = "303115"
    /// 一键启动 / 熄火。实车抓包得来：303120 = 启动，303125 = 熄火
    static let CODE_START = "303120"
    static let CODE_STOP = "303125"

    var uid = ""
    var ssk = ""
    var tid = ""
    var btkey = ""
    var devName = ""
    var user = ""
    var expire: Int64 = 0
    var lastReport: Car?

    private var seq = 1
    /// 保护 seq 的互斥锁。
    /// 注意：**不能叫 `lock`** —— 下面有 `func lock()`（锁车指令），
    /// Swift 不允许同一个类型里属性和方法同名（invalid redeclaration）。
    private let mutex = NSLock()

    var hasSession: Bool {
        return !ssk.isEmpty && !tid.isEmpty
    }

    // MARK: 时间格式

    static func fmt(_ pattern: String, _ date: Date = Date()) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone.current
        f.dateFormat = pattern
        return f.string(from: date)
    }

    static func nowMs() -> Int64 {
        return Int64(Date().timeIntervalSince1970 * 1000)
    }

    private func ssn() -> String {
        mutex.lock()
        seq = (seq + 1) % 10000
        let s = seq
        mutex.unlock()
        return uid + CarAPI.fmt("HHmmss") + String(format: "%04d", s)
    }

    private func sysHead(_ code: String) -> String {
        let now = Date()
        return JB.o([
            ("ver", .s(CarAPI.VER)),
            ("code", .s(code)),
            ("consumer_ssn", .s(ssn())),
            ("trans_date", .s(CarAPI.fmt("yyyyMMdd", now))),
            ("trans_time", .s(CarAPI.fmt("HHmmss", now))),
            ("chnl", .s(CarAPI.CHNL)),
            ("build_make", .s("Xiaomi")),
            ("build_model", .s("M2012K11AC")),
            ("build_release", .s("13")),
            ("distribute", .s(CarAPI.DISTRIBUTE)),
            ("aver", .s(CarAPI.AVER)),
            ("version", .s(CarAPI.AVER))
        ])
    }

    private func appHead(_ useSsk: String, _ useTid: String) -> String {
        return JB.o([
            ("lang", .s("cn")),
            ("ssk", .s(useSsk)),
            ("tid", .s(useTid)),
            ("uid", .s(uid))
        ])
    }

    // MARK: 登录

    /// - Parameter passHash: 明文密码的 SHA1 大写
    func login(name: String, passHash: String) throws {
        let now = Date()
        let head = JB.o([
            ("ver", .s(CarAPI.VER)),
            ("code", .s(CarAPI.CODE_LOGIN)),
            ("consumer_ssn", .s(CarAPI.fmt("HHmmss", now) + "0001")),
            ("trans_date", .s(CarAPI.fmt("yyyyMMdd", now))),
            ("trans_time", .s(CarAPI.fmt("HHmmss", now))),
            ("chnl", .s(CarAPI.CHNL)),
            ("build_make", .s("Xiaomi")),
            ("build_model", .s("M2012K11AC")),
            ("build_release", .s("13")),
            ("distribute", .s(CarAPI.DISTRIBUTE)),
            ("version", .s(CarAPI.AVER))
        ])
        let body = JB.o([
            ("name", .s(name)),
            ("paswd", .s(passHash)),
            ("timezone", .s("8")),
            ("pushid", .s("")),
            ("pushchnl", .s("")),
            ("cli_key", .s(CarAPI.CLI_KEY))
        ])
        let req = JB.o([
            ("sys_head", .raw(head)),
            ("app_head", .raw(appHead(CarAPI.CLI_KEY, ""))),
            ("body", .raw(body))
        ])

        let text = try NetClient.call(req, host: CarAPI.HOST, port: CarAPI.PORT)
        guard let data = text.data(using: .utf8),
              let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            throw IllegalState("登录响应不是合法 JSON")
        }
        let sh = root["sys_head"] as? [String: Any]
        let status = (sh?["status"] as? String) ?? ""
        guard status == "S" else {
            let code = (sh?["ret_code"] as? String) ?? "?"
            let msg = (sh?["ret_msg"] as? String) ?? String(text.prefix(120))
            throw IllegalState("登录失败 \(code) \(msg)")
        }
        guard let b = root["body"] as? [String: Any] else {
            throw IllegalState("登录响应缺少 body")
        }
        uid = (b["uid"] as? String) ?? ""
        ssk = (b["ssk"] as? String) ?? ""
        user = name

        if let devs = b["dev"] as? [[String: Any]], let d = devs.first {
            tid = (d["tid"] as? String) ?? ""
            btkey = (d["btkey"] as? String) ?? ""
            devName = (d["dev_name"] as? String) ?? ""
            expire = CarAPI.parseLong((d["expire_date"] as? String) ?? "", 0)
            if let lloc = d["lloc"] as? [String: Any] {
                lastReport = CarAPI.parseCar(lloc, CarAPI.parseLong((lloc["tdt"] as? String) ?? "", 0) * 1000)
            }
        }
    }

    // MARK: 指令

    struct Resp {
        var ok = false
        var code = ""
        var msg = ""
        var raw = ""
        var json: [String: Any]?
    }

    func send(_ code: String, bodyJson: String = "{}") throws -> Resp {
        let req = JB.o([
            ("sys_head", .raw(sysHead(code))),
            ("app_head", .raw(appHead(ssk, tid))),
            ("body", .raw(bodyJson))
        ])
        let text = try NetClient.call(req, host: CarAPI.HOST, port: CarAPI.PORT)
        var r = Resp()
        r.raw = text
        guard let data = text.data(using: .utf8),
              let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            r.ok = false
            r.msg = "响应解析失败"
            return r
        }
        r.json = root
        if let sh = root["sys_head"] as? [String: Any] {
            r.code = (sh["ret_code"] as? String) ?? ""
            r.msg = (sh["ret_msg"] as? String) ?? ""
            r.ok = ((sh["status"] as? String) ?? "") == "S" || r.code == "000000"
        }
        return r
    }

    func lock() throws -> Resp { return try send(CarAPI.CODE_LOCK) }
    func unlock() throws -> Resp { return try send(CarAPI.CODE_UNLOCK) }
    /// 一键启动（远程着车）。走网络，不需要蓝牙在附近。
    func startEngine() throws -> Resp { return try send(CarAPI.CODE_START) }
    /// 熄火
    func stopEngine() throws -> Resp { return try send(CarAPI.CODE_STOP) }

    // MARK: 状态

    /// 查车辆状态。服务端 JSON 有重复键（speed 出现两次），解析失败时走宽松兜底。
    func status() -> Car? {
        do {
            let r = try send(CarAPI.CODE_STATUS, bodyJson: JB.o([("tid", .s(tid))]))
            var c: Car?
            if let b = r.json?["body"] as? [String: Any] {
                let src = (b["lloc"] as? [String: Any]) ?? b
                if let vst = src["vst"] as? String, !vst.isEmpty {
                    c = CarAPI.parseCar(src, CarAPI.nowMs())
                }
            }
            if c == nil && r.raw.contains("\"vst\"") {
                c = CarAPI.parseLoose(r.raw)
            }
            return c
        } catch {
            return nil
        }
    }

    static func parseCar(_ o: [String: Any], _ fetchedAt: Int64) -> Car {
        var c = Car()
        c.vst = (o["vst"] as? String) ?? ""
        c.lat = (o["lat"] as? String) ?? ""
        c.lng = (o["lng"] as? String) ?? ""
        c.volt = (o["volt"] as? String) ?? ""
        c.temp = (o["temp"] as? String) ?? ""
        c.speed = (o["speed"] as? String) ?? ""
        c.power = (o["power"] as? String) ?? ""
        c.mileage = (o["mileage"] as? String) ?? ""
        c.tdt = parseLong((o["tdt"] as? String) ?? "", 0)
        finish(&c, fetchedAt)
        return c
    }

    /// 键重复时退化为按字段抽取（取最后一次出现）
    static func parseLoose(_ raw: String) -> Car {
        var c = Car()
        c.vst = lastOf(raw, "vst")
        c.lat = lastOf(raw, "lat")
        c.lng = lastOf(raw, "lng")
        c.volt = lastOf(raw, "volt")
        c.temp = lastOf(raw, "temp")
        c.speed = lastOf(raw, "speed")
        c.power = lastOf(raw, "power")
        c.mileage = lastOf(raw, "mileage")
        c.tdt = parseLong(lastOf(raw, "tdt"), 0)
        finish(&c, nowMs())
        return c
    }

    static func lastOf(_ raw: String, _ key: String) -> String {
        let pat = "\"" + key + "\""
        guard let r = raw.range(of: pat, options: .backwards) else { return "" }
        var i = r.upperBound
        while i < raw.endIndex && raw[i] != ":" { i = raw.index(after: i) }
        guard i < raw.endIndex else { return "" }
        i = raw.index(after: i)
        while i < raw.endIndex && raw[i].isWhitespace { i = raw.index(after: i) }
        guard i < raw.endIndex else { return "" }
        if raw[i] == "\"" {
            let start = raw.index(after: i)
            guard let end = raw[start...].firstIndex(of: "\"") else { return "" }
            return String(raw[start..<end])
        }
        var end = i
        let stops: Set<Character> = [",", "}", "\"", "]", " ", "\t", "\r", "\n"]
        while end < raw.endIndex && !stops.contains(raw[end]) { end = raw.index(after: end) }
        return String(raw[i..<end])
    }

    private static func finish(_ c: inout Car, _ fetchedAt: Int64) {
        c.armed = armedOfVst(c.vst)
        c.speedKph = Int(parseLong(c.speed, 0))
        c.moving = c.speedKph > 0
        c.reportedAt = c.tdt > 0 ? c.tdt * 1000 : fetchedAt
        c.fetchedAt = fetchedAt
    }

    /// vst 第 3 个字节的 0x20 位 = 已设防。
    ///
    /// 实测：停车未锁 `000001C0…`、停车已锁 `000021C0…`、行驶中 `000018A0…`。
    /// 行驶态该位为 0，所以"未设防"不代表"车一定停着"，调用方必须自己排除行驶。
    static func armedOfVst(_ vst: String) -> Bool {
        let b = Hex.to(vst)
        return b.count > 2 && (b[2] & 0x20) != 0
    }

    static func parseLong(_ s: String, _ def: Int64) -> Int64 {
        let t = s.trimmingCharacters(in: .whitespaces)
        return Int64(t) ?? def
    }

    struct Car {
        var vst = ""
        var lat = ""
        var lng = ""
        var volt = ""
        var temp = ""
        var speed = ""
        var power = ""
        var mileage = ""
        var tdt: Int64 = 0
        var speedKph = 0
        var reportedAt: Int64 = 0
        var moving = false
        var armed = false
        var fetchedAt: Int64 = 0
    }
}

struct IllegalState: Error, LocalizedError {
    let message: String
    init(_ m: String) { message = m }
    var errorDescription: String? { return message }
}


// ==========================================================================
//  SXKC/Net/NetClient.swift  ——  HTTP 客户端
// ==========================================================================

enum NetError: Error, LocalizedError {
    case dns(String)
    case connect(String)
    case io(String)
    case badHeader

    var errorDescription: String? {
        switch self {
        case .dns(let m): return "域名解析失败 \(m)"
        case .connect(let m): return "连接失败 \(m)"
        case .io(let m): return "读写失败 \(m)"
        case .badHeader: return "响应头异常"
        }
    }
}

/// 交易网关：TCP 3050，报文 = 8 位十进制长度 + (JSON + HMAC-SHA1 大写空密钥)。
///
/// 用 BSD socket 而不是 URLSession：服务端是裸 TCP 不是 HTTP，
/// 而且同步阻塞模型和 Android 版一一对应，排查时日志能直接对齐。
enum NetClient {

    static func call(_ json: String,
                     host: String,
                     port: UInt16,
                     connectTimeoutSec: Int32 = 12,
                     ioTimeoutSec: Int = 40) throws -> String {

        let sig = Crypto.hmacSha1Upper("", json)
        let payload = Array((json + sig).utf8)
        let header = Array(String(format: "%08ld", payload.count).utf8)

        let fd = try openSocket(host: host, port: port, timeoutMs: connectTimeoutSec * 1000)
        defer { closeSocket(fd) }

        setTimeouts(fd, seconds: ioTimeoutSec)
        try writeAll(fd, header + payload)

        let hb = try readExactly(fd, 8)
        let hStr = String(bytes: hb, encoding: .ascii)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard let len = Int(hStr), len > 0, len <= 4 * 1024 * 1024 else {
            throw NetError.badHeader
        }
        let body = try readExactly(fd, len)
        guard let text = String(bytes: body, encoding: .utf8) else {
            throw NetError.io("响应不是 UTF-8")
        }
        return text
    }

    // MARK: - socket

    private static func openSocket(host: String, port: UInt16, timeoutMs: Int32) throws -> Int32 {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        hints.ai_protocol = IPPROTO_TCP

        var res: UnsafeMutablePointer<addrinfo>?
        let rc = getaddrinfo(host, String(port), &hints, &res)
        guard rc == 0, let head = res else {
            throw NetError.dns(String(cString: gai_strerror(rc)))
        }
        defer { freeaddrinfo(res) }

        var last = "没有可用地址"
        var cur: UnsafeMutablePointer<addrinfo>? = head

        while let ai = cur {
            let fd = socket(ai.pointee.ai_family, ai.pointee.ai_socktype, ai.pointee.ai_protocol)
            if fd < 0 {
                last = "socket() 失败 errno \(errno)"
                cur = ai.pointee.ai_next
                continue
            }

            let oldFlags = fcntl(fd, F_GETFL, 0)
            _ = fcntl(fd, F_SETFL, oldFlags | O_NONBLOCK)

            var r = connect(fd, ai.pointee.ai_addr, ai.pointee.ai_addrlen)
            if r < 0 && errno == EINPROGRESS {
                var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
                r = poll(&pfd, 1, timeoutMs)
                if r == 0 {
                    last = "连接超时"
                    closeSocket(fd)
                    cur = ai.pointee.ai_next
                    continue
                }
                if r < 0 {
                    last = "poll 失败 errno \(errno)"
                    closeSocket(fd)
                    cur = ai.pointee.ai_next
                    continue
                }
                var soErr: Int32 = 0
                var slen = socklen_t(MemoryLayout<Int32>.size)
                if getsockopt(fd, SOL_SOCKET, SO_ERROR, &soErr, &slen) != 0 || soErr != 0 {
                    last = "被拒绝 errno \(soErr)"
                    closeSocket(fd)
                    cur = ai.pointee.ai_next
                    continue
                }
            } else if r < 0 {
                last = "connect 失败 errno \(errno)"
                closeSocket(fd)
                cur = ai.pointee.ai_next
                continue
            }

            _ = fcntl(fd, F_SETFL, oldFlags)
            return fd
        }

        throw NetError.connect(last)
    }

    private static func closeSocket(_ fd: Int32) {
        if fd >= 0 { _ = close(fd) }
    }

    private static func setTimeouts(_ fd: Int32, seconds: Int) {
        var tv = timeval(tv_sec: seconds, tv_usec: 0)
        let sz = socklen_t(MemoryLayout<timeval>.size)
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sz)
        _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sz)
    }

    private static func writeAll(_ fd: Int32, _ bytes: [UInt8]) throws {
        var off = 0
        while off < bytes.count {
            let n: Int = bytes.withUnsafeBytes { p -> Int in
                let base = p.baseAddress!.advanced(by: off)
                return send(fd, base, bytes.count - off, 0)
            }
            if n <= 0 {
                if errno == EINTR { continue }
                throw NetError.io("发送失败 errno \(errno)")
            }
            off += n
        }
    }

    private static func readExactly(_ fd: Int32, _ count: Int) throws -> [UInt8] {
        var out = [UInt8](repeating: 0, count: count)
        var off = 0
        while off < count {
            let n: Int = out.withUnsafeMutableBytes { p -> Int in
                let base = p.baseAddress!.advanced(by: off)
                return recv(fd, base, count - off, 0)
            }
            if n == 0 { throw NetError.io("连接被对端关闭") }
            if n < 0 {
                if errno == EINTR { continue }
                throw NetError.io("接收失败 errno \(errno)")
            }
            off += n
        }
        return out
    }
}


// ==========================================================================
//  SXKC/Ble/BleCentral.swift  ——  蓝牙中心（状态帧回调在这里）
// ==========================================================================

protocol BleCentralDelegate: AnyObject {
    func bleLog(_ b: BleCentral, _ s: String)
    func bleLink(_ b: BleCentral, _ s: String)
    func bleRssi(_ b: BleCentral, _ rssi: Int)
    func bleArmed(_ b: BleCentral, _ armed: Bool)
    /// 状态帧原始 16 字节。门位（body[3]）从这里取
    func bleStatusBody(_ b: BleCentral, _ body: [UInt8])
    func bleDone(_ b: BleCentral, ok: Bool, msg: String)
    func bleConnected(_ b: BleCentral, _ connected: Bool)
    /// 诊断页：扫描到设备
    func bleDiscovered(_ b: BleCentral, _ p: CBPeripheral, rssi: Int, adv: [String: Any])
    /// 诊断页：服务枚举完成
    func bleServices(_ b: BleCentral, _ services: [CBService])
}

extension BleCentralDelegate {
    func bleLog(_ b: BleCentral, _ s: String) {}
    func bleLink(_ b: BleCentral, _ s: String) {}
    func bleRssi(_ b: BleCentral, _ rssi: Int) {}
    func bleArmed(_ b: BleCentral, _ armed: Bool) {}
    func bleStatusBody(_ b: BleCentral, _ body: [UInt8]) {}
    func bleDone(_ b: BleCentral, ok: Bool, msg: String) {}
    func bleConnected(_ b: BleCentral, _ connected: Bool) {}
    func bleDiscovered(_ b: BleCentral, _ p: CBPeripheral, rssi: Int, adv: [String: Any]) {}
    func bleServices(_ b: BleCentral, _ services: [CBService]) {}
}

/// 蓝牙通道（iOS 重写版）。
///
/// ## 与 Android 版最本质的差别
///
/// Android 能拿到车机 MAC `99:99:16:20:C3:0D` 并按地址直连；**iOS 不允许**。
/// CoreBluetooth 从系统层面屏蔽了 MAC，扫描只返回 `CBPeripheral.identifier`
/// ——一个在本机生成、会随系统重装/抹机变化的 UUID。
///
/// 所以定位方式改成两级：
/// 1. 首次：扫描 → 连上 → 校验 0xFFE0/0xFFE1 指纹 → 把 identifier 存进 UserDefaults；
/// 2. 以后：`retrievePeripherals(withIdentifiers:)` 直接取回对象并 `connect()`。
///
/// 第 2 步不依赖广播包内容，所以即使车机广播里不带 0xFFE0 也能连
/// ——这也正是 Android 那套「记住地址」思路在 iOS 上唯一等价的做法。
///
/// 一次动作的时序（实测）：连接 0.5s → 发现服务 0.4s → 订阅 0.05s →
/// 握手 0.1s → 回执 0.1s。已连状态下开锁只剩「握手 + 指令」约 0.2s。
final class BleCentral: NSObject {

    static let svcCar = CBUUID(string: "FFE0")
    static let chrCar = CBUUID(string: "FFE1")
    static let svcBattery = CBUUID(string: "180F")
    static let chrBattery = CBUUID(string: "2A19")
    private static let restoreId = "cn.sxkc.ios.central"

    private static let CONNECT_TIMEOUT_MS: Int = 10000
    /// 两次发起连接之间的最小间隔。太密没用：刚断的链路在车机侧还没释放，
    /// 连上去只会再超时一次，日志里就是「12s 后重连」却 3 秒就重连、随后又超时的死循环。
    private static let RETRY_GAP_MS: Int64 = 4000

    // MARK: 状态

    weak var delegate: BleCentralDelegate?

    private(set) var central: CBCentralManager!
    private(set) var peripheral: CBPeripheral?
    private var chr: CBCharacteristic?
    private var batteryChr: CBCharacteristic?

    private(set) var ready = false
    private(set) var busy = false
    private(set) var connected = false
    private(set) var rssi = -127
    private(set) var battery = -1

    private var btkey: [UInt8]?
    private var busKey: [UInt8]?
    private var tid = ""
    private var seq = 1

    private var keepAlive = false
    private var wantUnlock = false
    private var done = false
    private var hsTries = 0
    private var lastRssiAt: Int64 = 0
    private var lastAttemptAt: Int64 = 0
    private var lastSeen: Int64 = 0
    private var lastLoggedMissing = ""

    /// 每次动作递增，用于让旧定时器失效
    private var gen = 0

    private var scanning = false
    /// 这一轮扫的是不是「按服务过滤」。重复调用同一种扫描直接忽略，
    /// 否则每调一次就 stopScan + 重扫，把兜底定时器叠成两份（实测同一秒两条「扫描车机」）。
    private var scanningFiltered = false
    /// 扫描代号：每起一轮 +1，上一轮挂着的 6 秒 / 20 秒兜底定时器看它自动失效
    private var scanGen = 0
    /// 正在发起连接。iOS 的 connect() 没有同步返回值，只能自己记一笔，
    /// 否则连点「手动连接」会叠出 4 次 connect + 4 次握手，最后特征引用全乱。
    private var connecting = false
    /// 保活心跳：车机侧 10 秒内没有往来就断链路（实测 12 秒），
    /// 只靠被动收状态帧不够稳，主动 readRSSI 既保活又顺手更新距离。
    private var pingTimer: Timer?
    private var lastStatusFlags = ""
    /// 上一次的门位字节，用来判断门开关是否变化（日志只在变化时记一行）
    private var lastDoorByte: UInt8 = 0xFF

    private var sawAnyDevice = false
    private(set) var diagMode = false

    /// 用户手动清空的日志位置（诊断页）
    var connectHint = ""

    // MARK: 生命周期

    override init() {
        super.init()
        central = CBCentralManager(delegate: self,
                                   queue: .main,
                                   options: [CBCentralManagerOptionRestoreIdentifierKey: BleCentral.restoreId])
    }

    func configure(tid: String, btkeyHex: String) {
        self.tid = tid
        if !btkeyHex.isEmpty {
            let k = Hex.to(btkeyHex)
            if k.count == 16 { btkey = k }
        }
        if let s = savedUuid, let p = central?.retrievePeripherals(withIdentifiers: [s]).first {
            if peripheral == nil {
                peripheral = p
                p.delegate = self
            }
        }
    }

    func setKeepAlive(_ on: Bool) {
        keepAlive = on
        if on { startPing() } else { stopPing() }
    }

    // MARK: 保活

    /// 心跳。车机侧一旦 10 秒左右收不到任何往来就把链路掐掉
    /// （日志里两次典型现场：连上 12 秒后 `The connection has timed out unexpectedly`），
    /// 而它自己的状态帧是「有变化才推」，空闲十几秒很正常 —— 光靠被动收包必断。
    ///
    /// 用 readRSSI 而不是发业务帧：不改车机状态、不需要密钥、还能顺手刷新距离。
    private func startPing() {
        guard keepAlive, ready else { return }
        stopPing()
        let t = Timer(timeInterval: 5.0, repeats: true) { [weak self] _ in
            guard let self = self else { return }
            guard self.connected, let p = self.peripheral, p.state == .connected else { return }
            p.readRSSI()
        }
        RunLoop.main.add(t, forMode: .common)
        pingTimer = t
    }

    private func stopPing() {
        pingTimer?.invalidate()
        pingTimer = nil
    }

    var hasSavedTarget: Bool {
        return savedUuid != nil
    }

    var savedName: String {
        return Store.shared.str(StoreKey.peripheralName)
    }

    private var savedUuid: UUID? {
        let s = Store.shared.str(StoreKey.peripheralId)
        return UUID(uuidString: s)
    }

    var lastSeenMs: Int64 { return lastSeen }
    var isConnected: Bool { return connected }
    var isReady: Bool { return ready && peripheral != nil }
    var chargerCharacteristic: CBCharacteristic? { return batteryChr }
    var batteryLevel: Int { return battery }

    // MARK: - 连接

    /// 需要时连上去；已连或正在连则什么都不做
    func ensureConnected() {
        guard central.state == .poweredOn else {
            logOnce("no-bt", "蓝牙未开启或未授权蓝牙权限")
            return
        }
        if connecting { return }
        if let p = peripheral {
            if p.state == .connected { return }
            if p.state == .connecting { return }
            if CarAPI.nowMs() - lastAttemptAt < BleCentral.RETRY_GAP_MS { return }
            connectHint = p.name ?? p.identifier.uuidString
            log("重连车机 \(connectHint)")
            beginConnect(p)
            return
        }
        if let u = savedUuid,
           let p = central.retrievePeripherals(withIdentifiers: [u]).first {
            // 这一支原来没有节流：只要 peripheral 被清成 nil（比如连接超时后会清），
            // 任何一个 ensureConnected 调用者都能在断开 3 秒后立刻重连，退避形同虚设，
            // 而刚断的链路往往还没恢复，重连必然再超时一次。这里跟上面用同一个间隔。
            if CarAPI.nowMs() - lastAttemptAt < BleCentral.RETRY_GAP_MS { return }
            peripheral = p
            p.delegate = self
            connectHint = p.name ?? u.uuidString
            log("连接已记住的车机 \(p.name ?? u.uuidString)")
            beginConnect(p)
            return
        }
        // 没有任何记录 → 只能扫一遍把车机找出来
        startScan(filtered: true)
    }

    /// 统一入口：记一笔「正在连」+ 起连接超时定时器
    private func beginConnect(_ p: CBPeripheral) {
        connecting = true
        lastAttemptAt = CarAPI.nowMs()
        central.connect(p, options: nil)
        scheduleConnectTimeout()
    }

    func disconnect() {
        gen += 1          // 让所有挂起的超时回调失效
        scanning = false
        scanGen += 1
        connecting = false
        stopPing()
        central.stopScan()
        if let p = peripheral {
            central.cancelPeripheralConnection(p)
        }
        peripheral = nil
        chr = nil
        ready = false
        connected = false
        busKey = nil
        rssi = -127
        log("断开蓝牙")
    }

    /// 退出登录时的清场：断链 + 清掉内存里的会话密钥。
    ///
    /// 与 `disconnect()` 的区别是这里还会清 tid / btkey / 序号，防止换账号后
    /// 残留上一账号的解密密钥；但**不动** Store 里的 `peripheralId` ——
    /// 车机平时不广播，identifier 一删可能就再也找不回来了（iOS 没有 MAC 可兜底）。
    func releaseSession() {
        gen += 1
        keepAlive = false
        scanning = false
        scanGen += 1
        connecting = false
        stopPing()
        diagMode = false
        central?.stopScan()
        if let p = peripheral {
            central?.cancelPeripheralConnection(p)
        }
        peripheral = nil
        chr = nil
        batteryChr = nil
        ready = false
        connected = false
        busy = false
        done = false
        wantUnlock = false
        hsTries = 0
        tid = ""
        btkey = nil
        busKey = nil
        seq = 1
        rssi = -127
        battery = -1
        lastSeen = 0
        lastRssiAt = 0
        lastAttemptAt = 0
        lastStatusFlags = ""
        lastDoorByte = 0xFF
        lastLoggedMissing = ""
        log("已清空蓝牙会话（车机记录保留）")
    }

    private func scheduleConnectTimeout() {
        let g = gen
        DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(BleCentral.CONNECT_TIMEOUT_MS)) { [weak self] in
            guard let self = self, self.gen == g else { return }
            if !self.ready && self.peripheral != nil && !self.connected {
                self.log("连接超时，放弃本次")
                if self.busy && !self.done {
                    self.fail("连不上车机 \(self.connectHint)")
                }
                self.disconnect()
            }
        }
    }

    // MARK: - 扫描

    func startScan(filtered: Bool) {
        guard central.state == .poweredOn else { return }
        // 同一种扫描已经在跑就直接忽略。原来每调一次都 stopScan + 重扫，
        // 6 秒和 20 秒两个兜底定时器会叠成两份 —— 日志里同一秒两条「扫描车机」、
        // 六秒后两条「退化为全量扫描」就是这么来的。
        if scanning && scanningFiltered == filtered { return }
        if scanning { central.stopScan() }   // 过滤 → 全量 是正当降级，允许切换

        scanGen += 1
        let g = scanGen
        scanning = true
        scanningFiltered = filtered
        sawAnyDevice = false
        let services: [CBUUID]? = filtered ? [BleCentral.svcCar] : nil
        log(filtered ? "扫描车机（按 0xFFE0 服务过滤）…" : "全量扫描（不过滤）…")
        central.scanForPeripherals(withServices: services,
                                   options: [CBCentralManagerScanOptionAllowDuplicatesKey: true])

        // 过滤扫不到就退化为全量扫；全量也找不到就提示去诊断页
        if filtered {
            DispatchQueue.main.asyncAfter(deadline: .now() + 6.0) { [weak self] in
                guard let self = self, self.scanGen == g, self.scanning,
                      self.peripheral == nil, !self.sawAnyDevice else { return }
                self.log("广播里没有 0xFFE0，退化为全量扫描")
                self.startScan(filtered: false)
            }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 20.0) { [weak self] in
            guard let self = self, self.scanGen == g, !self.diagMode,
                  self.scanning, self.peripheral == nil else { return }
            self.scanning = false
            self.central.stopScan()
            self.log("扫不到车机。请到「蓝牙诊断」页全量扫描，手动连接一次，之后会自动记住")
        }
    }

    func startDiagScan() {
        diagMode = true
        startScan(filtered: false)
    }

    /// 从诊断页配对完之后 diagMode 会一直留着，而 diagMode 开着时
    /// 自动扫描不会超时、不会提示「扫不到车机」。自动模式启动时清掉它。
    func clearDiagMode() {
        diagMode = false
    }

    func stopDiagScan() {
        scanning = false
        scanGen += 1
        central.stopScan()
        diagMode = false
        log("停止扫描")
    }

    /// 诊断页手动指定设备
    func connectManually(_ p: CBPeripheral) {
        // 同一个设备已经在连 / 已连上：直接回一行日志，别再发一次 connect。
        // 连点四下就是四次握手、四个会话，特征引用最后会指向一个已经废弃的 session，
        // 之后所有写入都报「没有连接或没有可写特征」。
        if p.state == .connecting || connecting {
            log("正在连接 \(p.name ?? "这台设备")，不用重复点")
            return
        }
        if p.state == .connected && peripheral?.identifier == p.identifier {
            log("已经连着 \(p.name ?? "这台设备")")
            return
        }
        diagMode = true
        scanning = false
        scanGen += 1
        central.stopScan()
        if let old = peripheral, old.identifier != p.identifier {
            central.cancelPeripheralConnection(old)
        }
        peripheral = p
        p.delegate = self
        ready = false
        connected = false
        connectHint = p.name ?? p.identifier.uuidString
        log("手动连接 \(p.name ?? "未命名") / \(p.identifier.uuidString)")
        beginConnect(p)
    }

    // MARK: - 动作

    /// 执行一次开锁 / 锁车；结果通过 delegate 回传
    func perform(unlock: Bool) {
        if busy {
            finish(false, "上一条指令还在执行")
            return
        }
        guard let k = btkey, k.count == 16 else {
            finish(false, "还没有 btkey，请先登录成功一次")
            return
        }
        gen += 1
        busy = true
        done = false
        wantUnlock = unlock
        hsTries = 0

        if ready && chr != nil && busKey != nil {
            // 已连好且握过手：0.2 秒就能发出去
            sendAction()
            return
        }
        if connected && chr != nil && btkey != nil {
            // 链路还在，只是握手没成（上一次握手应答丢了 / 刚被车机踢过）：
            // 补一次握手比重新连接快得多，也不用再走 13 秒的连接超时。
            log("链路还在但没有会话密钥，重新握手")
            handshake()
            let g0 = gen
            DispatchQueue.main.asyncAfter(deadline: .now() + 6.0) { [weak self] in
                guard let self = self, self.gen == g0 else { return }
                if self.busy && !self.done && !self.ready { self.fail("握手无应答") }
            }
            return
        }
        ensureConnected()
        let g = gen
        DispatchQueue.main.asyncAfter(deadline: .now() + 13.0) { [weak self] in
            guard let self = self, self.gen == g else { return }
            if self.busy && !self.done && !self.ready {
                self.fail("连不上车机，请靠近车辆再试")
            }
        }
    }

    /// 读一次 RSSI（距离判定的唯一来源；内部 800ms 节流）
    func readRssi(force: Bool = false) {
        guard let p = peripheral, p.state == .connected else { return }
        let now = CarAPI.nowMs()
        if !force && now - lastRssiAt < 800 { return }
        lastRssiAt = now
        p.readRSSI()
    }

    /// 诊断页用：直接发一段 HEX（不加密、不加帧头）
    func sendRawHex(_ s: String) {
        let bytes = Hex.to(s)
        // 两种情况分开报：原来一句「没有连接或没有可写特征」把「输入框是空的」也算进去了，
        // 日志里连续四条一样的报错会让人以为是蓝牙掉了。
        if bytes.isEmpty {
            log("✗ 输入框里没有有效 HEX")
            return
        }
        guard let p = peripheral, let c = chr else {
            log("✗ 没有连接或没有可写特征")
            return
        }
        log("直发 \(Hex.of(bytes))")
        p.writeValue(Data(bytes), for: c, type: .withResponse)
    }

    /// 诊断页用：自动派生 btrand 后发控制帧
    func sendControlFrame(unlock: Bool) {
        guard let k = btkey, k.count == 16 else {
            log("✗ 没有 btkey")
            return
        }
        let rk = Frame.btrandKey(CarAPI.nowMs())
        busKey = Hex.to(rk + "FFFF")
        let payload: [UInt8] = unlock ? [0x01] : [0x00, 0x01]
        guard let f = try? Frame.build(type: Frame.TYPE_CTRL, seq: nextSeq(),
                                       payload: payload, key: busKey!, handshake: false) else {
            log("✗ 组帧失败")
            return
        }
        write(f)
        log((unlock ? "开锁帧 " : "锁车帧 ") + Hex.of(f))
    }

    // MARK: - 握手 / 指令

    private func nextSeq() -> Int {
        seq += 1
        if seq > 0xFFFF { seq = 1 }
        return seq
    }

    private func handshake() {
        guard !ready, let c = chr, let p = peripheral, let k = btkey else { return }
        hsTries += 1
        let rk = Frame.btrandKey(CarAPI.nowMs())
        busKey = Hex.to(rk + "FFFF")
        guard let f = try? Frame.build(type: Frame.TYPE_HANDSHAKE, seq: nextSeq(),
                                       payload: Hex.to(rk), key: k, handshake: true) else {
            fail("握手组帧失败")
            return
        }
        log("握手 #\(hsTries) key=\(rk)")
        p.writeValue(Data(f), for: c, type: .withResponse)

        let g = gen
        if hsTries < 3 {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.9) { [weak self] in
                guard let self = self, self.gen == g, !self.ready, self.peripheral != nil else { return }
                self.handshake()
            }
        } else {
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) { [weak self] in
                guard let self = self, self.gen == g else { return }
                if !self.ready && self.busy && !self.done { self.fail("握手无应答") }
            }
        }
    }

    private func sendAction() {
        guard let k = busKey, let c = chr, let p = peripheral else {
            fail("业务密钥缺失")
            return
        }
        let payload: [UInt8] = wantUnlock ? [0x01] : [0x00, 0x01]
        guard let f = try? Frame.build(type: Frame.TYPE_CTRL, seq: nextSeq(),
                                       payload: payload, key: k, handshake: false) else {
            fail("指令组帧失败")
            return
        }
        p.writeValue(Data(f), for: c, type: .withResponse)
        log((wantUnlock ? "开锁 " : "锁车 ") + Hex.of(f))

        let g = gen
        DispatchQueue.main.asyncAfter(deadline: .now() + 5.0) { [weak self] in
            guard let self = self, self.gen == g else { return }
            if self.busy && !self.done { self.fail("车机未回执") }
        }
    }

    private func write(_ f: [UInt8]) {
        guard let p = peripheral, let c = chr else { return }
        p.writeValue(Data(f), for: c, type: .withResponse)
    }

    // MARK: - 收包

    private func onFrame(_ v: [UInt8]) {
        guard v.count >= 20 else { return }
        lastSeen = CarAPI.nowMs()

        // 接收方向一律先试 btrand（握手应答 / 状态帧 / 回执都是它加密的），再退回 btkey。
        // open() 内部会校验帧头与 CRC，用错密钥必然返回 nil。
        var body: [UInt8]?
        if let k = busKey { body = Frame.open(v, k) }
        if body == nil, let k = btkey { body = Frame.open(v, k) }
        guard let b = body, b.count >= 3 else { return }

        let type = Int(b[0])
        let st = Int(b[2])

        if type == Frame.TYPE_HANDSHAKE {
            if st == 0x00 {
                ready = true
                log("握手成功")
                link("蓝牙就绪")
                startPing()
                if busy && !done { sendAction() }
            } else {
                log("握手被拒 code=\(st)")
                if hsTries >= 2 { fail("握手被拒 code=\(st)") }
            }
        } else if type == Frame.TYPE_STATUS {
            let armed = Frame.armedOfStatusBody(b)
            // 状态帧只在 flags 或门位变化时记一行，且把整帧明文带上 ——
            // 之前只记 armed 的布尔值，01/11/21 之间的来回跳完全看不出来。
            let fl = Frame.statusFlags(b)
            let doorByte: UInt8 = b.count > 3 ? b[3] : 0
            if lastStatusFlags != fl || lastDoorByte != doorByte {
                lastStatusFlags = fl
                lastDoorByte = doorByte
                let doorTxt = Frame.anyDoorOpen(b) ? "有门开着" : "四门全关"
                log("状态帧 flags=\(fl) \(armed ? "已锁" : "未锁") 门位=\(doorTxt) body=\(Hex.of(b))")
            }
            delegate?.bleArmed(self, armed)
            delegate?.bleStatusBody(self, b)
            if busy && !done && armed == !wantUnlock {
                succeed(wantUnlock ? "已解锁" : "已锁车")
            }
        } else if type == Frame.TYPE_CTRL {
            // 没有正在执行的指令时（比如诊断页直接发的帧）只记一行，
            // 不能走 succeed()：它会把 done 置 true，下一条真指令的回执就吞了。
            if busy && !done {
                if st == 0x00 { succeed("车机已执行") } else { fail("车机返回 \(st)") }
            } else {
                log(st == 0x00 ? "← 车机执行回执" : "← 车机返回 \(st)")
            }
        }
    }

    // MARK: - 收尾

    private func succeed(_ msg: String) { finish(true, msg) }
    private func fail(_ msg: String) { finish(false, msg) }

    private func finish(_ ok: Bool, _ msg: String) {
        if done { return }
        done = true
        busy = false
        lastSeen = CarAPI.nowMs()
        log((ok ? "✓ " : "✗ ") + msg)
        delegate?.bleDone(self, ok: ok, msg: msg)
        if !keepAlive {
            let g = gen
            DispatchQueue.main.asyncAfter(deadline: .now() + 8.0) { [weak self] in
                guard let self = self, self.gen == g, !self.busy, !self.keepAlive else { return }
                self.disconnect()
            }
        }
    }

    // MARK: - 工具

    private func log(_ s: String) {
        delegate?.bleLog(self, s)
    }

    private func link(_ s: String) {
        delegate?.bleLink(self, s)
    }

    private func logOnce(_ key: String, _ s: String) {
        if key == lastLoggedMissing { return }
        lastLoggedMissing = key
        log(s)
    }
}

// MARK: - CBCentralManagerDelegate

extension BleCentral: CBCentralManagerDelegate {

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        switch central.state {
        case .poweredOn:
            log("蓝牙就绪")
            if keepAlive { ensureConnected() }
        case .unauthorized:
            log("✗ 蓝牙权限被拒绝：设置 → 隐私 → 蓝牙，打开本 App")
        case .poweredOff:
            log("✗ 系统蓝牙已关闭")
            connected = false
            ready = false
        case .unsupported:
            log("✗ 此设备不支持 BLE")
        default:
            break
        }
    }

    func centralManager(_ central: CBCentralManager,
                        willRestoreState dict: [String: Any]) {
        if let ps = dict[CBCentralManagerRestoredStatePeripheralsKey] as? [CBPeripheral],
           let p = ps.first {
            peripheral = p
            p.delegate = self
            connected = (p.state == .connected)
            log("后台恢复：拿回车机连接")
            if connected {
                // 进程被杀过再恢复时，特征引用和会话密钥都没了，光"连着"发不出指令。
                // 重新走一遍服务发现 → 订阅 → 握手，链路在就不会再花连接时间。
                ready = false
                chr = nil
                busKey = nil
                p.discoverServices(nil)
            }
        }
    }

    func centralManager(_ central: CBCentralManager,
                        didDiscover peripheral: CBPeripheral,
                        advertisementData: [String: Any],
                        rssi RSSI: NSNumber) {
        sawAnyDevice = true
        let adv = advertisementData
        delegate?.bleDiscovered(self, peripheral, rssi: RSSI.intValue, adv: adv)

        if diagMode {
            // 诊断页只看不连，用户手动点
            return
        }
        // allowDuplicates 下一台设备每秒能报好几次，这里必须挡住，
        // 否则每次回调都 connect 一次，叠出多个会话。
        if connecting || peripheral.state == .connecting || peripheral.state == .connected {
            return
        }

        let advServices = (adv[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID]) ?? []
        let hasCarSvc = advServices.contains(BleCentral.svcCar)
        // 车机广播里不一定带 0xFFE0（实测同一台机器时有时无），
        // 但它的设备名就是 tid —— 日志里扫到的正是 `30071067124`。
        // 名字当第二指纹，首配就不用赌广播包内容了。
        let advName = (adv[CBAdvertisementDataLocalNameKey] as? String) ?? peripheral.name ?? ""
        let nameHit = !tid.isEmpty && advName == tid
        let saved = savedUuid

        if let s = saved {
            if peripheral.identifier == s {
                scanning = false
                scanGen += 1
                central.stopScan()
                self.peripheral = peripheral
                peripheral.delegate = self
                log("扫到已记住的车机，连接…")
                beginConnect(peripheral)
            }
            return
        }

        // 第一次用：认 0xFFE0 广播，或认设备名
        if hasCarSvc || nameHit {
            scanning = false
            scanGen += 1
            central.stopScan()
            self.peripheral = peripheral
            peripheral.delegate = self
            log("发现\(hasCarSvc ? "带 0xFFE0" : "名字匹配")的设备 \(advName)，连接校验…")
            beginConnect(peripheral)
        }
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        connecting = false
        self.peripheral = peripheral
        connected = true
        ready = false
        rssi = -127
        log("已连接 \(peripheral.name ?? "未命名") / \(peripheral.identifier.uuidString)")
        link("发现服务…")
        delegate?.bleConnected(self, true)
        peripheral.discoverServices(nil)
    }

    func centralManager(_ central: CBCentralManager,
                        didFailToConnect peripheral: CBPeripheral,
                        error: Error?) {
        connecting = false
        connected = false
        log("连接失败 \(error?.localizedDescription ?? "")")
        if busy && !done { fail("连接失败") }
        self.peripheral = nil
    }

    func centralManager(_ central: CBCentralManager,
                        didDisconnectPeripheral peripheral: CBPeripheral,
                        error: Error?) {
        connecting = false
        connected = false
        ready = false
        rssi = -127
        busKey = nil
        stopPing()
        delegate?.bleConnected(self, false)
        if busy && !done {
            fail("连接断开")
        } else {
            log("蓝牙断开 \(error?.localizedDescription ?? "")")
            link("蓝牙断开")
        }
        self.peripheral = peripheral   // 保留对象，方便下次直接 connect
    }
}

// MARK: - CBPeripheralDelegate

extension BleCentral: CBPeripheralDelegate {

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        if let e = error {
            fail("服务发现失败 \(e.localizedDescription)")
            return
        }
        let services = peripheral.services ?? []
        delegate?.bleServices(self, services)
        log("服务发现完成，共 \(services.count) 个")
        for s in services {
            log("  ├ \(s.uuid.uuidString)")
        }

        var foundCar = false
        for s in services {
            if s.uuid == BleCentral.svcCar {
                foundCar = true
                peripheral.discoverCharacteristics(nil, for: s)
            } else if s.uuid == BleCentral.svcBattery {
                peripheral.discoverCharacteristics(nil, for: s)
            }
        }
        if !foundCar {
            // 身份指纹：没有 0xFFE0/0xFFE1 就不是这台车
            log("✗ 没有 0xFFE0：这不是车机")
            fail("这台设备没有 0xFFE0/0xFFE1，不是车机")
            central.cancelPeripheralConnection(peripheral)
            self.peripheral = nil
        }
    }

    func peripheral(_ peripheral: CBPeripheral,
                    didDiscoverCharacteristicsFor service: CBService,
                    error: Error?) {
        if let e = error {
            log("特征发现失败 \(e.localizedDescription)")
            return
        }
        for c in service.characteristics ?? [] {
            log("  │ \(service.uuid.uuidString) / \(c.uuid.uuidString) \(BleCentral.props(c))")
            if c.uuid == BleCentral.chrCar {
                chr = c
                // 首次校验成功：把 identifier 记下来，以后不再依赖广播
                Store.shared.put(StoreKey.peripheralId, peripheral.identifier.uuidString)
                Store.shared.put(StoreKey.peripheralName, peripheral.name ?? "")
                log("✓ 指纹命中 0xFFE0/0xFFE1，已记住这台车机")
                peripheral.setNotifyValue(true, for: c)
            } else if c.uuid == BleCentral.chrBattery {
                batteryChr = c
                peripheral.readValue(for: c)
            }
        }
    }

    func peripheral(_ peripheral: CBPeripheral,
                    didUpdateNotificationStateFor characteristic: CBCharacteristic,
                    error: Error?) {
        if let e = error {
            fail("订阅通知失败 \(e.localizedDescription)")
            return
        }
        if characteristic.isNotifying {
            // 订阅确认一到就握手，不等固定延时
            log("已订阅通知，开始握手")
            handshake()
        }
    }

    func peripheral(_ peripheral: CBPeripheral,
                    didWriteValueFor characteristic: CBCharacteristic,
                    error: Error?) {
        if let e = error {
            log("写入失败 \(e.localizedDescription)")
        }
    }

    func peripheral(_ peripheral: CBPeripheral,
                    didUpdateValueFor characteristic: CBCharacteristic,
                    error: Error?) {
        guard let d = characteristic.value else { return }
        if characteristic.uuid == BleCentral.chrBattery {
            let b = [UInt8](d)
            if let first = b.first {
                // 这台车机从来不报电量：4 次连接、每次读回来都是 0x00。
                // 别把 0 当 0% 显示（会让人以为车要没电了），直接当无效值。
                if first > 0 && first <= 100 {
                    battery = Int(first)
                    log("车机电池 \(battery)%")
                } else {
                    battery = -1
                    logOnce("battery-invalid", "车机不报电量（读到 0x\(String(format: "%02X", first))），显示 —")
                }
            }
            return
        }
        if characteristic.uuid == BleCentral.chrCar {
            onFrame([UInt8](d))
        }
    }

    func peripheral(_ peripheral: CBPeripheral,
                    didReadRSSI RSSI: NSNumber,
                    error: Error?) {
        if error != nil { return }
        rssi = RSSI.intValue
        lastSeen = CarAPI.nowMs()
        delegate?.bleRssi(self, rssi)
    }

    static func props(_ c: CBCharacteristic) -> String {
        var a: [String] = []
        let p = c.properties
        if p.contains(.read) { a.append("read") }
        if p.contains(.write) { a.append("write") }
        if p.contains(.writeWithoutResponse) { a.append("writeNR") }
        if p.contains(.notify) { a.append("notify") }
        if p.contains(.indicate) { a.append("indicate") }
        return "[" + a.joined(separator: ",") + "]"
    }
}


// ==========================================================================
//  SXKC/Auto/AutoEngine.swift  ——  自动化引擎（门位状态、小组件推送在这里）
// ==========================================================================

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

    /// 构建指纹。
    ///
    /// 版本号来自 `project.yml`，那只是**一个文件**：把它传上去，界面立刻显示
    /// 新版本号，但源码可能一个都没传——于是出现「版本号 v1.19、行为还是 1.17」
    /// 这种最难查的情况。这个常量写在 .swift 里，只有源码真的进了仓库、真的
    /// 参与了编译，界面上才会跟着变。
    ///
    /// 每次改源码就换一个值，装完瞄一眼底部就知道装的是哪一次构建。
    static let buildTag = "b1109w"

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
    /// 距离数值（米），<0 表示未知。
    /// 界面用 `distText`，小组件要的是数值（它自己排版），所以两个都留一份。
    private var lastDistM: Double = -1
    /// 小组件推送节流用：距离每走几米就变一次，没必要每次都惊动它
    private var lastPushAt: TimeInterval = 0
    private var lastPushDist: Double = -999
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
    /// 门没关好就不自动落锁（v1.19）
    @Published var doorGuardEnabled = true
    /// 洗车模式剩余文案；空串表示没开
    @Published var washText = ""
    /// 罚站率统计摘要
    @Published var statsText = ""
    /// 车门状态文案：未收到状态帧时是「车门：状态未知」，
    /// 收到之后在「全关 / 有门开着 / 尾箱开着」之间切换
    @Published var doorText = "车门：状态未知"
    /// 是否已经拿到过有效门位（决定文案用灰还是上色）
    @Published var doorShown = false
    /// 门或尾箱正开着（决定文案用橙色告警）
    @Published var doorAlert = false

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
    /// 门位是否已知（收到过状态帧）
    private var doorKnown = false
    /// 是否有车门开着。这台车机不区分哪一扇，任一门开就是 true
    private var doorOpen = false
    /// 尾箱是否开着
    private var doorTrunk = false
    /// 最近一次拿到门位的时刻（ms）。超过 doorStaleMs 就不采信
    private var doorMs: Int64 = 0
    /// 上一次因为车门没关而拦下锁车的时刻，用来给通知限频
    private var doorBlockAt: Int64 = 0
    /// 门位有效期：3 秒一帧，断开 / 省电之后会停在旧值上，过期就不能再拿它拦锁车
    private let doorStaleMs: Int64 = 30000

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
        doorGuardEnabled = store.flag(StoreKey.doorGuard, true)
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
        log("· 构建 \(AutoEngine.buildTag) · 门位解析已启用")
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
            // 门没关严就落锁 == 没锁。
            // 门位超期（断连 / 省电熄屏 / 刚启动还没收到状态帧）一律当"未知"，
            // 不拦锁车 —— 拿一份过期数据把车卡住不让锁，比不拦更危险。
            let nowMs = CarAPI.nowMs()
            let doorFresh = doorKnown && (nowMs - doorMs) < doorStaleMs
            if store.flag(StoreKey.doorGuard, true),
               Logic.doorBlocksLock(doorKnown: doorFresh, doorOpen: doorOpen || doorTrunk) {
                log("⚠ 检测到\(doorOpen ? "车门" : "尾箱")没关好，本轮不落锁（关好后会自动补锁）")
                if store.notifyEnabled, nowMs - doorBlockAt > 60000 {
                    doorBlockAt = nowMs
                    Notify.shared.doorBlocked(doorOpen: doorOpen, trunk: doorTrunk)
                }
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
        let valid = g.carValid && g.phoneValid && !g.dist.isNaN
        lastDistM = valid ? g.dist : -1
        if valid {
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
        // 距离变了，小组件上的「距车 42 米」也要跟着变
        pushWidget()
    }

    // MARK: 小组件

    /// 把当前状态写进 App Group，并让小组件重新读一次。
    ///
    /// 小组件是**另一个进程**，它不能自己连蓝牙 —— iOS 不给 Widget 长连 BLE 的机会，
    /// 而这台车机平时不广播，不主动连根本扫不到。所以「锁没锁、多远」这两个值
    /// 只能由主 App 写下来、小组件读出去。
    ///
    /// 主 App 没在跑的时候，小组件就停在最后一次快照上，界面上会标「x 分钟前」，
    /// 不让它假装是实时的 —— 一个停在旧数据的「已锁车」，比一个明写「未知」的更危险。
    ///
    /// 距离几乎每帧都在变，所以这里节流：走够 5 米、或者过了 20 秒才推一次；
    /// 锁车状态、连接状态这类关键变化用 `force: true` 立刻推。
    func pushWidget(force: Bool = false) {
        let now = Date().timeIntervalSince1970
        if !force, now - lastPushAt < 20, abs(lastDistM - lastPushDist) < 5 { return }
        lastPushAt = now
        lastPushDist = lastDistM
        let s = SharedKit.Snapshot(armed: armed,
                                   armedKnown: armedKnown,
                                   connected: connected,
                                   distance: lastDistM,
                                   updatedAt: now,
                                   lastResult: lastResult)
        SharedKit.save(s)
        WidgetCenter.shared.reloadAllTimelines()
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

    func setDoorGuard(_ on: Bool) {
        store.putFlag(StoreKey.doorGuard, on)
        doorGuardEnabled = on
        log(on ? "门位保护：已开启（有门开着就不自动落锁）" : "门位保护：已关闭（不看门位，到点就锁）")
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
        // 每次回前台先刷一次小组件：用户很可能是在桌面上看了一眼小组件、
        // 觉得不对才点开 App 的，这时候界面上的数必须和桌面上的对齐。
        pushWidget(force: true)
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
        // 连着还是断着，小组件上要能一眼看出来（断连时整个状态会转灰）
        pushWidget(force: true)
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
            // 断连之后门位就没有来源了，界面如实退回「未知」，
            // 不让上一次的「全关」一直挂在那里骗人
            doorShown = false
            doorAlert = false
            doorText = "车门：状态未知"
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

    /// 状态帧原始 16 字节：门位在这里落定。
    ///
    /// `body[3]` 低 4 位非零 = 有车门开着，bit4 = 尾箱。
    /// 这型车机不区分具体哪一扇门（实测开任意一门，四个门位全置 1），
    /// 所以只维护一个布尔量，不做单门解析。
    /// 只在门位变化时打日志、刷界面 —— 状态帧 3 秒一帧，全打会把日志刷爆。
    func bleStatusBody(_ b: BleCentral, _ body: [UInt8]) {
        let open = Frame.anyDoorOpen(body)
        let trunk = Frame.trunkOpen(body)
        let now = CarAPI.nowMs()
        let wasFresh = doorKnown && (now - doorMs) < doorStaleMs
        let changed = !wasFresh || open != doorOpen || trunk != doorTrunk

        doorKnown = true
        doorOpen = open
        doorTrunk = trunk
        doorMs = now

        guard changed else { return }
        var txt = open ? "有车门开着" : "四门全关"
        if trunk { txt += " · 尾箱开着" }
        doorText = "车门：" + (open ? (trunk ? "有门开着 · 尾箱开着" : "有门开着")
                                    : (trunk ? "尾箱开着" : "全关"))
        doorShown = true
        doorAlert = open || trunk
        log("· 门位 \(Hex.of(body)) → \(txt)")
        if !open && !trunk {
            Notify.shared.clearDoorBlocked()
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
        let wasKnown = armedKnown
        let wasArmed = armed
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
        // 锁车状态变了必须立刻让小组件知道；没变就走节流，别每 3 秒推一次
        pushWidget(force: !wasKnown || wasArmed != a)
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


// ==========================================================================
//  SXKC/UI/Theme.swift  ——  配色与小组件
// ==========================================================================

/// 深色车载风格的基础配色与小组件
enum UI {
    static let bg = Color(red: 0.047, green: 0.059, blue: 0.078)
    static let card = Color(red: 0.086, green: 0.106, blue: 0.137)
    static let cardHi = Color(red: 0.114, green: 0.141, blue: 0.180)
    static let line = Color.white.opacity(0.08)
    static let text = Color(red: 0.925, green: 0.941, blue: 0.961)
    static let dim = Color.white.opacity(0.45)
    static let accent = Color(red: 0.231, green: 0.510, blue: 0.965)
    static let warn = Color(red: 0.961, green: 0.620, blue: 0.043)
    static let ok = Color(red: 0.133, green: 0.773, blue: 0.369)
    static let bad = Color(red: 0.937, green: 0.267, blue: 0.267)
}

struct Card<Content: View>: View {
    let content: Content
    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }
    var body: some View {
        content
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .fill(UI.card)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .stroke(UI.line, lineWidth: 1)
            )
    }
}

struct SectionTitle: View {
    let text: String
    var body: some View {
        Text(text)
            .font(.system(size: 13, weight: .semibold))
            .foregroundColor(UI.dim)
            .tracking(0.5)
    }
}

/// 大圆角主操作按钮
struct BigButton: View {
    let title: String
    let subtitle: String
    let color: Color
    var enabled: Bool = true
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(spacing: 6) {
                Text(title)
                    .font(.system(size: 22, weight: .bold))
                Text(subtitle)
                    .font(.system(size: 12))
                    .opacity(0.7)
            }
            .foregroundColor(.white)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 22)
            .background(
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .fill(color.opacity(enabled ? 1 : 0.35))
            )
        }
        .disabled(!enabled)
    }
}

/// 描边的小按钮（网络备用通道）
struct GhostButton: View {
    let title: String
    let color: Color
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(title)
                .font(.system(size: 14, weight: .semibold))
                .foregroundColor(color)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 12)
                .background(
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .stroke(color.opacity(0.55), lineWidth: 1.2)
                )
        }
    }
}

/// 带数值滑条
struct SliderRow: View {
    let title: String
    let unit: String
    @Binding var value: Double
    let range: ClosedRange<Double>
    let step: Double
    let hint: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(title).font(.system(size: 14, weight: .medium)).foregroundColor(UI.text)
                Spacer()
                Text("\(Int(value))\(unit)")
                    .font(.system(size: 14, weight: .semibold, design: .monospaced))
                    .foregroundColor(UI.accent)
            }
            Slider(value: $value, in: range, step: step)
                .accentColor(UI.accent)
            Text(hint)
                .font(.system(size: 11))
                .foregroundColor(UI.dim)
        }
    }
}


// ==========================================================================
//  SXKC/UI/MainView.swift  ——  主界面
// ==========================================================================

struct MainView: View {
    @EnvironmentObject var e: AutoEngine

    @State private var thr: Double = Double(Store.shared.thr)
    @State private var bleThr: Double = Double(Store.shared.bleLockThr)
    @State private var geoNear: Double = Store.shared.geoNearM
    @State private var showSettings = false
    @State private var showLogout = false
    @State private var showEngine = false
    @State private var engineStart = true
    /// 同一个视图上挂两个 .sheet，在 iOS 14 上只有第一个会生效。
    /// 所以这里用一个可选的枚举统一驱动，而不是两个 isPresented。
    @State private var sheet: SheetKind?

    private enum SheetKind: Int, Identifiable {
        case diag, cards
        var id: Int { return rawValue }
    }

    /// 版本号从 Bundle 读，装完一眼能确认是哪一版，不用去系统设置里翻。
    /// 后面那个构建指纹见 `AutoEngine.buildTag` 的注释——版本号会骗人，它不会。
    static var versionText: String {
        let info = Bundle.main.infoDictionary
        let v = (info?["CFBundleShortVersionString"] as? String) ?? "?"
        let b = (info?["CFBundleVersion"] as? String) ?? "?"
        return "顺心控车 Lite  v\(v) (\(b)) · \(AutoEngine.buildTag)"
    }

    private var armedText: String {
        if !e.armedKnown { return "状态未知" }
        return e.armed ? "已锁车" : "未锁车"
    }

    private var armedColor: Color {
        if !e.armedKnown { return UI.dim }
        return e.armed ? UI.ok : UI.warn
    }

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 14) {
                    // 顺序和显隐来自 Cards（本地存储），不再是写死的九块。
                    // 关掉排序页回来时 showCards 变化会触发重算，这里就会重排。
                    ForEach(Cards.visible, id: \.self) { id in
                        cardView(id)
                    }

                    Button {
                        sheet = .cards
                    } label: {
                        Text("卡片顺序 · 显示与隐藏")
                            .font(.system(size: 12))
                            .foregroundColor(UI.dim)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 10)
                    }
                }
                .padding(16)
                .padding(.bottom, 24)
            }
            .background(UI.bg.ignoresSafeArea())
            .navigationTitle("顺心控车")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("卡片") { sheet = .cards }
                        .foregroundColor(UI.accent)
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("诊断") { sheet = .diag }
                        .foregroundColor(UI.accent)
                }
            }
            .sheet(item: $sheet) { kind in
                if kind == .diag {
                    DiagView().environmentObject(e)
                } else {
                    CardOrderView()
                }
            }
        }
        .navigationViewStyle(.stack)
    }

    /// 卡片 id → 视图。新增卡片只改这里和 Cards 的枚举，主界面不用动。
    @ViewBuilder
    private func cardView(_ id: CardID) -> some View {
        switch id {
        case .status:  statusCard
        case .actions: actionCard
        case .loc:     locCard
        case .auto:    autoCard
        case .wash:    washCard
        case .stats:   statsCard
        case .slider:  sliderCard
        case .console: consoleCard
        case .account: accountCard
        }
    }

    // MARK: 状态

    private var statusCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 14) {
                HStack(alignment: .firstTextBaseline) {
                    Text(armedText)
                        .font(.system(size: 26, weight: .bold))
                        .foregroundColor(armedColor)
                    Spacer()
                    if e.acting {
                        HStack(spacing: 6) {
                            ProgressView().progressViewStyle(CircularProgressViewStyle(tint: UI.accent))
                            Text("执行中").font(.system(size: 12)).foregroundColor(UI.dim)
                        }
                    }
                }

                Text(e.devName.isEmpty ? "未绑定车辆" : e.devName)
                    .font(.system(size: 13))
                    .foregroundColor(UI.dim)

                Divider().background(UI.line)

                HStack(spacing: 18) {
                    statItem("蓝牙",
                             e.connected ? "已连接" : "未连接",
                             e.connected ? UI.ok : UI.dim)
                    statItem("信号",
                             e.rssi > -120 ? "\(e.rssi) dBm" : "--",
                             e.rssi >= Int(thr) ? UI.ok : UI.dim)
                    statItem("判据",
                             e.geoActive ? "定位" : "蓝牙",
                             e.geoActive ? UI.ok : UI.dim)
                }

                if !e.distText.isEmpty {
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Text(e.distText)
                            .font(.system(size: 15, weight: .medium))
                            .foregroundColor(e.geoActive ? UI.ok : UI.dim)
                        Spacer()
                        Text(e.locText)
                            .font(.system(size: 11))
                            .foregroundColor(UI.dim)
                    }
                }

                if !e.lastResult.isEmpty {
                    Text(e.lastResult)
                        .font(.system(size: 12))
                        .foregroundColor(UI.dim)
                }

                // 门位：色点 + 文字。全关绿、有门开着橙、没数据灰。
                // 之前只用 10 号灰字，门开了也看不出来，等于白做。
                HStack(spacing: 7) {
                    Circle()
                        .fill(doorColor)
                        .frame(width: 7, height: 7)
                    Text(e.doorText)
                        .font(.system(size: 12, weight: .medium))
                        .foregroundColor(doorColor)
                    Spacer()
                }
            }
        }
    }

    /// 门位颜色：没数据灰、有门开着橙、全关绿
    private var doorColor: Color {
        if !e.doorShown { return UI.dim }
        return e.doorAlert ? UI.warn : UI.ok
    }

    private func statItem(_ t: String, _ v: String, _ c: Color) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(t).font(.system(size: 11)).foregroundColor(UI.dim)
            Text(v).font(.system(size: 14, weight: .semibold)).foregroundColor(c)
        }
    }

    // MARK: 操作

    private var actionCard: some View {
        VStack(spacing: 10) {
            HStack(spacing: 10) {
                BigButton(title: "开锁", subtitle: "双通道竞速", color: UI.accent) {
                    e.manual(unlock: true)
                }
                BigButton(title: "锁车", subtitle: "双通道竞速", color: UI.warn) {
                    e.manual(unlock: false)
                }
            }
            HStack(spacing: 10) {
                GhostButton(title: "网络开锁", color: UI.accent) {
                    e.netOnly(unlock: true)
                }
                GhostButton(title: "网络锁车", color: UI.warn) {
                    e.netOnly(unlock: false)
                }
            }
            HStack(spacing: 10) {
                GhostButton(title: "一键启动", color: UI.ok) {
                    engineStart = true
                    showEngine = true
                }
                GhostButton(title: "熄火", color: UI.dim) {
                    engineStart = false
                    showEngine = true
                }
            }
            Text("定位可用时走网络，失败自动转蓝牙；定位不可用时仍是蓝牙优先。"
                + "最后的两个按钮走网络，人在车外也能用。")
                .font(.system(size: 11))
                .foregroundColor(UI.dim)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .alert(isPresented: $showEngine) {
            Alert(
                title: Text(engineStart ? "远程启动发动机？" : "远程熄火？"),
                message: Text(engineStart
                              ? "请确认车停在安全位置、档位在 P 挡、周围没有人。启动后车辆会保持怠速。"
                              : "行驶中熄火会失去助力，请确认车已停稳。"),
                primaryButton: .destructive(Text(engineStart ? "启动" : "熄火")) {
                    if engineStart { e.startEngine() } else { e.stopEngine() }
                },
                secondaryButton: .cancel(Text("取消"))
            )
        }
    }

    // MARK: 定位

    /// 定位设置。放两个开关：总开关（决定「按距离判」还是「按信号判」）、
    /// 后台开关（决定锁屏后还算不算距离）。
    private var locCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("定位判距")
                            .font(.system(size: 15, weight: .semibold))
                            .foregroundColor(UI.text)
                        Text("按车辆定位算真实距离：\(Int(Store.shared.geoNearM)) 米内开锁，超过 \(Int(Store.shared.geoFarM)) 米锁车")
                            .font(.system(size: 11))
                            .foregroundColor(UI.dim)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer()
                    Toggle("", isOn: Binding(
                        get: { e.geoEnabled },
                        set: { e.setGeoEnabled($0) }
                    ))
                    .labelsHidden()
                    .toggleStyle(SwitchToggleStyle(tint: UI.accent))
                }

                Divider().background(UI.line)

                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("后台持续定位")
                            .font(.system(size: 15, weight: .semibold))
                            .foregroundColor(UI.text)
                        Text("锁屏后也能判距并自动开关锁。耗电明显增加，系统状态栏会出现定位箭头。")
                            .font(.system(size: 11))
                            .foregroundColor(UI.dim)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer()
                    Toggle("", isOn: Binding(
                        get: { e.locBackground },
                        set: { e.setLocBackground($0) }
                    ))
                    .labelsHidden()
                    .toggleStyle(SwitchToggleStyle(tint: UI.accent))
                }

                Text(e.distText.isEmpty ? "还没有定位数据" : e.distText)
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(e.geoActive ? UI.ok : UI.dim)

                Text(e.locText)
                    .font(.system(size: 11))
                    .foregroundColor(UI.dim)
            }
        }
    }

    // MARK: 自动模式

    private var autoCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("自动靠近开锁 / 离开落锁")
                            .font(.system(size: 15, weight: .semibold))
                            .foregroundColor(UI.text)
                        Text("定位可用时按真实距离判；不可用时连上车机判开锁、断开即锁")
                            .font(.system(size: 11))
                            .foregroundColor(UI.dim)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer()
                    Toggle("", isOn: Binding(
                        get: { e.running },
                        set: { on in
                            if on { e.start() } else { e.stop() }
                        }
                    ))
                    .labelsHidden()
                    .toggleStyle(SwitchToggleStyle(tint: UI.accent))
                }

                if !e.powerText.isEmpty {
                    Text(e.powerText)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(UI.ok)
                }

                if e.armedKnown && e.rssi > -120 {
                    Text(e.connected
                         ? "已连车机，信号 \(e.rssi)dBm，门限 \(Int(thr))dBm"
                         : "未连接，到达车边会自动重连")
                        .font(.system(size: 11))
                        .foregroundColor(UI.dim)
                }

                Divider().background(UI.line)

                toggleRow("双通道竞速",
                          "开锁 / 锁车时蓝牙与网络同时下发，谁先回执算谁。两条都是幂等指令，不会多锁一次。",
                          isOn: Binding(get: { e.raceEnabled }, set: { e.setRace($0) }))

                toggleRow("离车较远时降低定位精度",
                          "300 米外降到粗略定位，回到车附近自动升到 GPS 高频。精度只在需要时花钱。",
                          isOn: Binding(get: { e.fenceEnabled }, set: { e.setFence($0) }))

                toggleRow("通知与震动",
                          "自动锁车发一条带距离的通知，开锁轻震一下；连续 3 次锁不上会发强提醒。",
                          isOn: Binding(get: { e.notifyEnabled }, set: { e.setNotify($0) }))

                toggleRow("门没关好不锁车",
                          "车机会报门位。有门开着就不下发锁车指令，关好后自动补锁，并弹一条可「仍然锁车」的提醒。",
                          isOn: Binding(get: { e.doorGuardEnabled }, set: { e.setDoorGuard($0) }))
            }
        }
    }

    private func toggleRow(_ title: String, _ hint: String, isOn: Binding<Bool>) -> some View {
        HStack(alignment: .center) {
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.system(size: 14, weight: .medium))
                    .foregroundColor(UI.text)
                Text(hint)
                    .font(.system(size: 10))
                    .foregroundColor(UI.dim)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            Toggle("", isOn: isOn)
                .labelsHidden()
                .toggleStyle(SwitchToggleStyle(tint: UI.accent))
        }
    }

    // MARK: 洗车 / 代客模式

    private var washCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                SectionTitle(text: "洗车 / 代客模式")

                Text("洗车、代客泊车时车辆会反复移动，自动判定就会不停开锁关锁。暂停期间只停自动逻辑，手动按钮照常可用；到点自动恢复。")
                    .font(.system(size: 11))
                    .foregroundColor(UI.dim)
                    .fixedSize(horizontal: false, vertical: true)

                Text(e.washText.isEmpty ? "当前：未开启" : "当前：\(e.washText)")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundColor(e.washText.isEmpty ? UI.dim : UI.ok)

                HStack(spacing: 10) {
                    GhostButton(title: "暂停 30 分钟", color: UI.accent) {
                        e.setWash(minutes: 30)
                    }
                    GhostButton(title: "立即恢复", color: UI.dim) {
                        e.setWash(minutes: 0)
                    }
                }
            }
        }
    }

    // MARK: 开锁表现（罚站率）

    private var statsCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    SectionTitle(text: "开锁表现")
                    Spacer()
                    Button("清空") { e.resetStats() }
                        .font(.system(size: 12))
                        .foregroundColor(UI.dim)
                }

                Text(e.statsText.isEmpty ? Stats.summary() : e.statsText)
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(UI.text)
                    .fixedSize(horizontal: false, vertical: true)

                Text("罚站率 =（超过 3 秒才开 + 没开成）/ 总次数。行业参考：UWB 约 1%，纯蓝牙约 10%。只统计自动开锁。")
                    .font(.system(size: 10))
                    .foregroundColor(UI.dim)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    // MARK: 参数

    private var sliderCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 20) {
                SectionTitle(text: "距离与延时")

                SliderRow(title: "靠近门限",
                          unit: " 米",
                          value: $geoNear,
                          range: 5 ... 30,
                          step: 1,
                          hint: "定位算出的直线距离小于它就算「在车旁」。离开门限自动取它的 2 倍（\(Int(geoNear * 2)) 米），中间这段是死区，专门吃掉 GPS 抖动。")

                SliderRow(title: "开锁信号门限",
                          unit: " dBm",
                          value: $thr,
                          range: -95 ... -45,
                          step: 1,
                          hint: "定位用不了时才看这一项：信号强于此值才算「靠近」。后台拿不到信号时，只要连上车机就按「在附近」处理。")

                VStack(alignment: .leading, spacing: 6) {
                    Text("离开判定：蓝牙一断开就锁车")
                        .font(.system(size: 14, weight: .medium))
                        .foregroundColor(UI.text)
                    Text("iOS 后台没有可靠的定时器，做不了「离开 30 秒再锁」。只在本次到访确实开过锁时才会锁，"
                        + "刚锁完、车辆在行驶、或正在执行别的指令时都会跳过。")
                        .font(.system(size: 11))
                        .foregroundColor(UI.dim)
                        .fixedSize(horizontal: false, vertical: true)
                }

                SliderRow(title: "蓝牙锁车最远信号",
                          unit: " dBm",
                          value: $bleThr,
                          range: -95 ... -70,
                          step: 1,
                          hint: "断开时信号若还强于此值，先尝试蓝牙锁车；否则直接走网络。")

                Button {
                    e.refreshStatus()
                } label: {
                    Text("刷新车辆状态")
                        .font(.system(size: 14, weight: .medium))
                        .foregroundColor(UI.accent)
                }
            }
        }
        .onChange(of: thr) { v in Store.shared.thr = Int(v) }
        .onChange(of: bleThr) { v in Store.shared.bleLockThr = Int(v) }
        .onChange(of: geoNear) { v in
            Store.shared.geoNearM = v
            // 离开门限跟着走，保持「至少 2 倍」，否则死区会被挤没
            Store.shared.geoFarM = max(v * 2, v + 10)
        }
    }

    // MARK: 日志

    private var consoleCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    SectionTitle(text: "运行日志")
                    Spacer()
                    Button("清空") { e.clearLog() }
                        .font(.system(size: 12))
                        .foregroundColor(UI.dim)
                }
                ScrollViewReader { proxy in
                    ScrollView {
                        VStack(alignment: .leading, spacing: 2) {
                            ForEach(Array(e.logs.enumerated()), id: \.offset) { idx, line in
                                Text(line)
                                    .font(.system(size: 11, design: .monospaced))
                                    .foregroundColor(logColor(line))
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .id(idx)
                            }
                        }
                    }
                    .frame(height: 190)
                    .onChange(of: e.logs.count) { _ in
                        if let last = e.logs.indices.last {
                            withAnimation { proxy.scrollTo(last, anchor: .bottom) }
                        }
                    }
                }
            }
        }
    }

    private func logColor(_ s: String) -> Color {
        if s.contains("✗") { return UI.bad }
        if s.contains("✓") { return UI.ok }
        if s.contains("◇") || s.contains("▶") { return UI.accent }
        if s.contains("⚠︎") { return UI.warn }
        return UI.text.opacity(0.82)
    }

    // MARK: 账号

    /// 换账号的入口。刻意放在最底下：日常用车不该被它干扰，但要找的时候一定找得到。
    ///
    /// 这里不提供「同时忘记车机」：iOS 只认系统分配的 identifier，车机又不广播，
    /// 一旦清掉很可能再也扫不回来（Android 还能按 MAC 重连，iOS 没这条路）。
    private var accountCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                SectionTitle(text: "账号")

                HStack(alignment: .center) {
                    Text(e.accountText.isEmpty ? "未登录" : e.accountText)
                        .font(.system(size: 16, weight: .semibold))
                        .foregroundColor(UI.text)
                    Spacer()
                    Button {
                        showLogout = true
                    } label: {
                        Text("退出登录")
                            .font(.system(size: 13, weight: .medium))
                            .foregroundColor(UI.bad)
                            .padding(.horizontal, 14)
                            .padding(.vertical, 7)
                            .background(
                                RoundedRectangle(cornerRadius: 14, style: .continuous)
                                    .stroke(UI.bad.opacity(0.45), lineWidth: 1)
                            )
                    }
                }

                Text("换账号请先退出登录。已记住的车机会保留，不用重新配对。")
                    .font(.system(size: 11))
                    .foregroundColor(UI.dim)

                Text(MainView.versionText)
                    .font(.system(size: 11))
                    .foregroundColor(UI.dim.opacity(0.8))
            }
        }
        .actionSheet(isPresented: $showLogout) {
            ActionSheet(
                title: Text("退出登录"),
                message: Text("当前账号 \(e.accountText)\n\n"
                    + "退出后会关闭自动模式、断开蓝牙并清除登录信息，下次使用要重新输入密码。"),
                buttons: [
                    .destructive(Text("退出登录")) { e.logout() },
                    .cancel(Text("取消"))
                ]
            )
        }
    }
}


// ==========================================================================
//  SXKC/UI/DiagView.swift  ——  诊断页
// ==========================================================================

struct DiagView: View {
    @EnvironmentObject var e: AutoEngine
    @Environment(\.presentationMode) var presentation

    @State private var hexInput = ""
    @State private var calibrating = false
    @State private var calLeft = 0
    @State private var calSamples: [Int] = []
    @State private var calTimer: Timer?

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 14) {
                    scanCard
                    deviceCard
                    linkCard
                    quickCard
                    calibCard
                    diagConsole
                }
                .padding(16)
                .padding(.bottom, 24)
            }
            .background(UI.bg.ignoresSafeArea())
            .navigationTitle("蓝牙诊断")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("关闭") {
                        calTimer?.invalidate()
                        presentation.wrappedValue.dismiss()
                    }
                    .foregroundColor(UI.accent)
                }
            }
        }
        .navigationViewStyle(.stack)
        .onAppear { e.startDiagScan() }
        .onDisappear {
            calTimer?.invalidate()
            e.stopDiagScan()
        }
    }

    // MARK: 扫描

    private var scanCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                SectionTitle(text: "扫描")
                HStack(spacing: 10) {
                    GhostButton(title: e.diagScanning ? "正在扫描…" : "全量扫描",
                                color: UI.accent) {
                        e.startDiagScan()
                    }
                    GhostButton(title: "停止", color: UI.dim) {
                        e.stopDiagScan()
                    }
                }
                Text("iOS 拿不到 MAC 地址，只能看到系统分配的 UUID。带 FFE0 标记的就是本车。")
                    .font(.system(size: 11))
                    .foregroundColor(UI.dim)
                    .lineSpacing(3)
            }
        }
    }

    // MARK: 设备列表

    private var deviceCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    SectionTitle(text: "设备 \(e.diagDevices.count)")
                    Spacer()
                    Text("按信号排序").font(.system(size: 11)).foregroundColor(UI.dim)
                }
                if e.diagDevices.isEmpty {
                    Text("还没有扫到设备")
                        .font(.system(size: 12))
                        .foregroundColor(UI.dim)
                }
                ForEach(e.diagDevices) { d in
                    Button {
                        e.connectDiag(d)
                    } label: {
                        HStack(spacing: 10) {
                            VStack(alignment: .leading, spacing: 3) {
                                HStack(spacing: 6) {
                                    Text(d.name.isEmpty ? "未命名" : d.name)
                                        .font(.system(size: 14, weight: .semibold))
                                        .foregroundColor(UI.text)
                                    if d.hasCarSvc {
                                        Text("FFE0")
                                            .font(.system(size: 10, weight: .bold))
                                            .foregroundColor(.white)
                                            .padding(.horizontal, 5)
                                            .padding(.vertical, 2)
                                            .background(Capsule().fill(UI.ok))
                                    }
                                }
                                Text(d.id.uuidString)
                                    .font(.system(size: 9, design: .monospaced))
                                    .foregroundColor(UI.dim)
                                    .lineLimit(1)
                            }
                            Spacer()
                            Text("\(d.rssi)")
                                .font(.system(size: 13, weight: .semibold, design: .monospaced))
                                .foregroundColor(d.rssi > -75 ? UI.ok : UI.dim)
                        }
                        .padding(.vertical, 8)
                        .contentShape(Rectangle())
                    }
                }
            }
        }
    }

    // MARK: 连接与 GATT

    private var linkCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                SectionTitle(text: "连接")
                HStack(spacing: 14) {
                    badge(e.connected ? "已连接" : "未连接", e.connected ? UI.ok : UI.dim)
                    badge("RSSI \(e.rssi)", e.rssi > -120 ? UI.text : UI.dim)
                    badge(batteryText, UI.dim)
                }
                if e.connected {
                    GhostButton(title: "断开连接", color: UI.bad) {
                        e.ble.disconnect()
                    }
                }
                if !e.diagServices.isEmpty {
                    Divider().background(UI.line)
                    SectionTitle(text: "服务 \(e.diagServices.count)")
                    ForEach(e.diagServices, id: \.self) { s in
                        Text("  \(s)")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(s.uppercased().contains("FFE0") ? UI.ok : UI.dim)
                    }
                }
            }
        }
    }

    private var batteryText: String {
        let b = e.ble.batteryLevel
        return b >= 0 ? "电池 \(b)%" : "电池 --"
    }

    private func badge(_ t: String, _ c: Color) -> some View {
        Text(t)
            .font(.system(size: 12, weight: .semibold))
            .foregroundColor(c)
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(Capsule().fill(UI.cardHi))
    }

    // MARK: 快捷指令

    private var quickCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                SectionTitle(text: "快捷帧")
                Text("握手会在连上后自动完成；下面两个按钮直接下发控制帧（自动派生 btrand）。")
                    .font(.system(size: 11))
                    .foregroundColor(UI.dim)
                    .lineSpacing(3)

                HStack(spacing: 10) {
                    GhostButton(title: "开锁帧", color: UI.accent) { e.diagControl(unlock: true) }
                    GhostButton(title: "锁车帧", color: UI.warn) { e.diagControl(unlock: false) }
                }

                HStack(spacing: 8) {
                    TextField("HEX，如 FF12…", text: $hexInput)
                        .font(.system(size: 12, design: .monospaced))
                        .autocapitalization(.allCharacters)
                        .disableAutocorrection(true)
                        .padding(10)
                        .background(RoundedRectangle(cornerRadius: 8).fill(UI.cardHi))
                        .foregroundColor(UI.text)
                    Button("发送") {
                        e.sendHex(hexInput)
                    }
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundColor(.white)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 10)
                    .background(RoundedRectangle(cornerRadius: 8).fill(UI.accent))
                }
            }
        }
    }

    // MARK: 距离标定

    private var calibCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                SectionTitle(text: "距离标定")
                Text("站在车前 1 米处点开始，保持不动，30 秒后看记录的平均值。用它来定「开锁信号门限」。")
                    .font(.system(size: 11))
                    .foregroundColor(UI.dim)
                    .lineSpacing(3)

                if calibrating {
                    Text("采样中… 剩余 \(calLeft)s　当前 \(e.rssi)dBm　样本 \(calSamples.count)")
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundColor(UI.accent)
                    GhostButton(title: "停止", color: UI.bad) { stopCalib() }
                } else {
                    GhostButton(title: "开始 30 秒标定", color: UI.accent) { startCalib() }
                }

                if !calSamples.isEmpty {
                    Text(summary())
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundColor(UI.text)
                }
            }
        }
    }

    private func startCalib() {
        guard e.connected else {
            e.log("✗ 先连上车机再标定")
            return
        }
        calibrating = true
        calLeft = 30
        calSamples = []
        calTimer?.invalidate()
        calTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { t in
            e.ble.readRssi(force: true)
            calSamples.append(e.rssi)
            calLeft -= 1
            if calLeft <= 0 {
                t.invalidate()
                calibrating = false
                e.log("标定完成：" + summary())
            }
        }
    }

    private func stopCalib() {
        calTimer?.invalidate()
        calibrating = false
        e.log("标定中止：" + summary())
    }

    private func summary() -> String {
        let valid = calSamples.filter { $0 < 0 && $0 > -120 }
        guard !valid.isEmpty else { return "样本无效" }
        let avg = valid.reduce(0, +) / valid.count
        let lo = valid.min() ?? 0
        let hi = valid.max() ?? 0
        return "平均 \(avg)dBm　最低 \(lo)　最高 \(hi)　样本 \(valid.count)"
    }

    // MARK: 日志

    private var diagConsole: some View {
        Card {
            VStack(alignment: .leading, spacing: 8) {
                SectionTitle(text: "日志")
                HStack(spacing: 8) {
                    GhostButton(title: "后台日志", color: UI.accent) {
                        e.readRunLog()
                    }
                    GhostButton(title: "复制", color: UI.dim) {
                        UIPasteboard.general.string = e.logs.joined(separator: "\n")
                        e.log("· 已复制 \(e.logs.count) 行到剪贴板")
                    }
                    GhostButton(title: "清空", color: UI.dim) {
                        e.clearLog()
                    }
                }
                Text("「清空」只清界面；App 被系统回收后，只有落盘那份还能找回。")
                    .font(.system(size: 10))
                    .foregroundColor(UI.dim)
                Button {
                    e.clearRunLog()
                } label: {
                    Text("删除落盘日志文件")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(UI.bad)
                }
                ScrollView {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(Array(e.logs.enumerated()), id: \.offset) { _, line in
                            Text(line)
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundColor(UI.text.opacity(0.8))
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                }
                .frame(height: 200)
            }
        }
    }
}


// ==========================================================================
//  SXKC/UI/LoginView.swift  ——  登录页
// ==========================================================================

struct LoginView: View {
    @EnvironmentObject var e: AutoEngine

    @State private var user: String = Store.shared.str(StoreKey.user)
    @State private var pass: String = ""
    @State private var busy = false
    @State private var err = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("顺心控车")
                        .font(.system(size: 32, weight: .bold))
                        .foregroundColor(UI.text)
                    Text("iOS 版 · 蓝牙直连 + 网络兜底")
                        .font(.system(size: 13))
                        .foregroundColor(UI.dim)
                }
                .padding(.top, 40)

                Card {
                    VStack(alignment: .leading, spacing: 14) {
                        SectionTitle(text: "账号登录")
                        TextField("手机号 / 账号", text: $user)
                            .autocapitalization(.none)
                            .disableAutocorrection(true)
                            .keyboardType(.numberPad)
                            .padding(12)
                            .background(RoundedRectangle(cornerRadius: 10).fill(UI.cardHi))
                            .foregroundColor(UI.text)

                        SecureField("密码", text: $pass)
                            .padding(12)
                            .background(RoundedRectangle(cornerRadius: 10).fill(UI.cardHi))
                            .foregroundColor(UI.text)

                        if !err.isEmpty {
                            Text(err)
                                .font(.system(size: 12))
                                .foregroundColor(UI.bad)
                        }

                        Button {
                            submit()
                        } label: {
                            HStack {
                                if busy { ProgressView().progressViewStyle(CircularProgressViewStyle(tint: .white)) }
                                Text(busy ? "登录中…" : "登录")
                                    .font(.system(size: 16, weight: .semibold))
                            }
                            .foregroundColor(.white)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 14)
                            .background(RoundedRectangle(cornerRadius: 12).fill(UI.accent))
                        }
                        .disabled(busy || user.isEmpty || pass.isEmpty)
                    }
                }

                Card {
                    VStack(alignment: .leading, spacing: 8) {
                        SectionTitle(text: "第一次使用")
                        Text("1. 登录后拿到车机的 btkey（蓝牙密钥）\n2. 进「蓝牙诊断」，全量扫描，连上名字像车机的设备\n3. 连上后能看到 FFE0/FFE1 就是本车，会自动记住\n4. 之后主界面的开锁/锁车就会先走蓝牙")
                            .font(.system(size: 12))
                            .foregroundColor(UI.dim)
                            .lineSpacing(4)
                    }
                }
            }
            .padding(20)
        }
        .background(UI.bg.ignoresSafeArea())
    }

    private func submit() {
        busy = true
        err = ""
        e.login(user: user, password: pass) { ok, msg in
            busy = false
            if !ok { err = msg }
        }
    }
}


// ==========================================================================
//  SXKC/UI/CardOrderView.swift  ——  卡片排序页
// ==========================================================================

/// 卡片顺序与显示。用系统的 `List` + `onMove`，拖动手感就是 iOS 原生的那一套，
/// 不需要自己写手势（自研手势在后台恢复、长按与滚动抢事件这些地方很容易出问题）。
///
/// 拖动把手在右侧、显示开关在左侧：两者刻意分开放，避免手指打架。
/// 改一下立刻写本地并回到主界面生效，不设「保存」按钮 —— 多一次点击没有意义。
struct CardOrderView: View {
    @Environment(\.presentationMode) private var pm

    @State private var list: [CardID] = Cards.order
    @State private var hidden: Set<String> = Cards.hidden

    var body: some View {
        NavigationView {
            List {
                Section(
                    header: Text("按住右侧把手拖动排序"),
                    footer: Text("只有打开的卡片会显示在主界面。左侧开关只管显示，数据和功能都还在。"),
                ) {
                    ForEach(list, id: \.self) { c in
                        row(c)
                    }
                    .onMove(perform: move)
                }

                Section {
                    Button {
                        Cards.reset()
                        list = Cards.order
                        hidden = Cards.hidden
                    } label: {
                        Text("恢复默认顺序，全部显示")
                            .foregroundColor(UI.accent)
                    }
                }
            }
            .listStyle(GroupedListStyle())
            // 常开编辑态：直接就能拖，不用先点「编辑」
            .environment(\.editMode, .constant(.active))
            .navigationTitle("卡片")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("完成") { pm.wrappedValue.dismiss() }
                        .foregroundColor(UI.accent)
                }
            }
        }
        .navigationViewStyle(.stack)
    }

    private func row(_ c: CardID) -> some View {
        HStack(spacing: 12) {
            Toggle("", isOn: Binding(
                get: { !hidden.contains(c.rawValue) },
                set: { on in
                    // 最后一张不给关：关完主界面一片空白，比不给关更糟
                    if !on && list.filter({ !hidden.contains($0.rawValue) }).count <= 1 {
                        return
                    }
                    if on {
                        hidden.remove(c.rawValue)
                    } else {
                        hidden.insert(c.rawValue)
                    }
                    Cards.hidden = hidden
                }
            ))
            .labelsHidden()
            .toggleStyle(SwitchToggleStyle(tint: UI.accent))

            VStack(alignment: .leading, spacing: 2) {
                Text(c.title)
                    .font(.system(size: 15))
                    .foregroundColor(hidden.contains(c.rawValue) ? UI.dim : UI.text)
                Text(c.hint)
                    .font(.system(size: 10))
                    .foregroundColor(UI.dim)
                    .lineLimit(1)
            }

            Spacer(minLength: 0)
        }
        .padding(.vertical, 2)
        .listRowBackground(UI.card)
    }

    private func move(from: IndexSet, to: Int) {
        list.move(fromOffsets: from, toOffset: to)
        Cards.order = list
    }
}


// ==========================================================================
//  SXKC/SXKCApp.swift  ——  App 入口（含小组件按钮的 URL 处理）
// ==========================================================================

@main
struct SXKCApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var engine = AutoEngine.shared
    @Environment(\.scenePhase) private var phase

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(engine)
                .preferredColorScheme(.dark)
                .onOpenURL { url in
                    // 小组件上的「开锁 / 锁车」按钮走这里。
                    //
                    // 小组件是独立进程，没有蓝牙会话，也没法长连车机 —— 所以它
                    // 只能把 App 拉起来，由 App 去下发真正的指令。用户看到的
                    // 效果是「点一下小组件 → App 打开 → 车开了」，多这一跳没法省。
                    guard url.scheme == "sxkc" else { return }
                    switch url.host {
                    case "unlock":
                        engine.manual(unlock: true)
                    case "lock":
                        engine.manual(unlock: false)
                    default:
                        break
                    }
                }
                .onChange(of: phase) { p in
                    // 没有定时器之后，网络兜底就靠这一次「回到前台」。
                    if p == .active {
                        engine.onForeground()
                    } else if p == .background {
                        engine.onBackground()
                    }
                }
        }
    }
}

/// 通知代理。
///
/// 两件事必须在这里做，SwiftUI 的 App 生命周期里没有对应的钩子：
/// 1. **前台也显示**：默认前台收到的本地通知是静默的，自动锁车就白发了；
/// 2. **「手动锁车」按钮**：连续 3 次没锁上时，点通知上的按钮直接在后台再锁一次，
///    不用先解锁手机、找到 App、再翻按钮 —— 那几秒钟可能正好是车门被拉开的几秒。
final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        return true
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                willPresent notification: UNNotification,
                                withCompletionHandler completionHandler:
                                    @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .list, .sound])
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        if response.actionIdentifier == Notify.actionManualLock {
            DispatchQueue.main.async {
                AutoEngine.shared.manualLockNow()
            }
        }
        completionHandler()
    }
}

struct RootView: View {
    @EnvironmentObject var e: AutoEngine

    var body: some View {
        Group {
            if e.signedIn {
                MainView()
            } else {
                LoginView()
            }
        }
        .background(UI.bg.ignoresSafeArea())
    }
}
