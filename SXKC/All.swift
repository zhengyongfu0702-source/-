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
import MapKit


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

    // 1.22 起不再解析尾箱（body[3] bit4）：那个掩码是从原版二进制里抄来的，
    // 但三份实车日志里从没出现过它单独置位。留着它的风险是——万一这个位另有含义，
    // 就会永久拦住锁车（车整夜不锁），比漏判尾箱严重得多。
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
        /// 判「近」要连续保持多久（毫秒）才算数。
        /// 原来用「两拍」，可拍数在 iOS 上是跟着系统定位回调走的（可能 1 秒也可能几分钟），
        /// 换成时间之后语义才稳定。
        var confirmHoldMs: Int64 = 15_000
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
        /// 这一轮「判近」从什么时候开始连续成立；0 = 当前没在近处。
        /// 用它算「持续了多久」，替代原来按拍数确认的做法。
        var nearSince: Int64 = 0
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
            if s.nearSince == 0 { s.nearSince = s.now }
            s.farTicks = 0
            s.farSince = 0
            s.visited = true
            s.lastNearAt = s.now
        } else if far {
            s.farTicks += 1
            s.nearTicks = 0
            s.nearSince = 0
            if s.farSince == 0 { s.farSince = s.now }
        } else {
            // 死区 / 数据勉强：计数清零，谁也别想靠累积蒙过去
            s.nearTicks = 0
            s.nearSince = 0
            s.farTicks = 0
            s.farSince = 0
        }

        // 这次到访算不算结束：看「离开最近一次判近」过了多久，而不是「连续判远」多久。
        // 旧写法要求 farSince 连续累积，而 10~30 米是死区，人在那个区间时 farSince
        // 每拍清零 → 「离开」永远不成立 → unlockedThisVisit 永不重置 →
        // 下次真的走到车边也不开锁，而且全程没有任何报错。
        // 死区只该吃掉抖动，不该把「人已经走了」这个事实一起吃掉。
        if s.lastNearAt > 0 {
            let held = s.now - s.lastNearAt
            let need = s.farTicks > 0 ? c.awayMs : c.awayMs * 2
            if held > need { s.unlockedThisVisit = false }
        }

        if s.busy || !s.armedKnown { return NONE }

        // ① 在车旁且车锁着 → 开锁。判近要「持续」而不是「N 拍」；
        //    蓝牙同时证明「贴着了」就免确认——那条信号比 GPS 精确得多。
        let nearHeld = s.nearSince > 0 && (s.now - s.nearSince) >= c.confirmHoldMs
        if c.autoUnlock && s.armed && !s.moving && near && !s.unlockedThisVisit
            && (s.bleNear || nearHeld)
            && (s.now - s.lastUnlockAt) > c.unlockCooldownMs {
            return UNLOCK
        }

        // ② 确实走远了 → 锁车。必须本次到访真的到过车旁，
        // 否则车停别处会无限下发锁车指令。
        let farHeld = s.farSince > 0 && (s.now - s.farSince) >= c.awayMs
        if c.autoLock && !s.armed && !s.moving && s.visited && !near && far && farHeld
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

    // MARK: 指令通道模式（1.26）

    /// 智能：蓝牙优先，够不着自动转网络，够得着时两条并发。默认值。
    static let MODE_SMART = 0
    /// 仅蓝牙：一条网络指令都不发。省流量、不受云端抖动影响，
    /// 代价是蓝牙连不上时这一笔就放弃（不会偷偷走网络）。
    static let MODE_BLE = 1
    /// 仅网络：指令全走云端。蓝牙仍然连着，只用来读车锁 / 门位状态帧 ——
    /// 不读状态就没有「车现在锁没锁」，整个判定都无从谈起。
    static let MODE_NET = 2

    static func modeName(_ m: Int) -> String {
        if m == MODE_BLE { return "仅蓝牙" }
        if m == MODE_NET { return "仅网络" }
        return "智能"
    }

    /// 按模式挑选下发通道。模式是硬约束，不参与「够不够得着」的判断 ——
    /// 用户选了仅蓝牙，就不该有任何一条指令偷偷走网络。
    static func pickCh(_ mode: Int,
                       unlock: Bool,
                       hasTarget: Bool,
                       connected: Bool,
                       rssiAgeMs: Int64,
                       rssi: Int,
                       _ c: Cfg?) -> Int {
        if mode == MODE_BLE { return CH_BLE }
        if mode == MODE_NET { return CH_NET }
        return unlock
            ? unlockChannel(hasTarget: hasTarget, connected: connected,
                            rssiAgeMs: rssiAgeMs, rssi: rssi, c)
            : lockChannel(hasTarget: hasTarget, connected: connected,
                          rssiAgeMs: rssiAgeMs, rssi: rssi, c)
    }

    /// 这个模式下是否允许并发。仅蓝牙 / 仅网络都是单通道，谈不上竞速。
    static func modeAllowsRace(_ mode: Int) -> Bool {
        return mode == MODE_SMART
    }

    /// 一次决策所需的全部输入
    struct St {
        var connected = true
        var armedKnown = false
        var armed = false
        var moving = false
        var busy = false
        var fresh = false
        /// RSSI 本身是否新鲜（10 秒内读到过）。
        ///
        /// 1.26 起与 `fresh`（状态帧新鲜）分开：状态帧 3 秒一帧，但车机在省电、
        /// 刚回连、或只推了半帧的情况下，`fresh` 会是 false，而此时 RSSI 明明
        /// 强得贴车。原来 `near` 同时要求两者，结果就是「人站在车门上，车不开」。
        var rssiFresh = false
        /// 这一拍的 RSSI。1.28 起引擎填的是**未平滑**的原始读数（拿到读数时），
        /// 只有读不到新值时才退回平滑值 —— 平滑有 17 秒时间常数，判开锁用它
        /// 等于让用户在门口多站半分钟。
        var rssi = -127
        /// 原始读数连续两拍上升（1.28）。配合「差 4dB 也认」把走近的过程提前识别。
        var rssiTrendUp = false
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
        /// 车锁状态最近一次「未锁 → 已锁」翻转的时刻（毫秒）。
        ///
        /// 1.26 新增。这个时间决定「车自己上锁后，人还在车旁多久才允许再开」：
        /// 原来一律要「走开 30 秒再回来」，于是下车关门、车一自锁，人就再也
        /// 拉不开门了 —— 用户说的罚站，很多是这一条。自锁回环只发生在几秒内，
        /// 用 20 秒的持续在旁作确认，既挡住回环又不会把人关在门外。
        var flipAt: Int64 = 0
        /// 连续多少拍判定为「已离开」，用于抗丢包
        var awayTicks = 0
    }

    struct Cfg {
        var autoUnlock = true
        var autoLock = true
        var thr = -72
        var awayMs: Int64 = 30000
        var freshMs: Int64 = 10000
        /// 开锁冷却（1.28 起默认 0，即**没有冷却**）。
        ///
        /// 冷却本来是为了挡住「门在 10 米线上抖 → 开了又锁、锁了又开」。
        /// 但真正挡住这个的是 `unlockedThisVisit`：一次到访只开一次，要等走开
        /// 30 秒或车自锁后 20 秒才重置。冷却叠在上面只剩一个副作用 ——
        /// 刚锁完车转身要拿东西，60 秒内怎么都不给开。所以取消。
        var unlockCooldownMs: Int64 = 0
        var lockCooldownMs: Int64 = 60000
        var awayConfirmTicks = 3
        /// 蓝牙锁车的距离门限（dBm）。离开判定触发时，如果最近一次读到的信号还强于它，
        /// 说明人还没走远、蓝牙大概率连得上，就先走蓝牙；否则直接走网络，别白等连接超时。
        var bleThr = -90
        /// 断开之后多久之内还认为「值得为锁车重连一次」
        var bleReachMs: Int64 = 20000
        /// 信号已弱于 `bleThr` 时的「加速离开」门槛：到这个程度人肯定不在车边了，
        /// 不必再等满 `awayMs`（原来转身走开要等 30 秒才锁，体感很慢）。
        var fastAwayMs: Int64 = 5000
    }

    /// 纯函数式决策；会顺带更新 St 里的 visited / awayTicks / unlockedThisVisit / lastNearAt。
    static func decide(_ s: inout St, _ c: Cfg) -> Int {
        // 先用「上一拍」的近处时刻算是否已经离开，再刷新 lastNearAt。
        // 反过来的话，刚走近的那一拍 lastNearAt 已被刷成 now，awayLong 永远是 false，
        // 「走开很久再回来」就再也不会触发开锁了。
        let nearRef = s.lastNearAt > 0 ? s.lastNearAt : s.lastSeen
        let awayLong = nearRef > 0 && (s.now - nearRef) > c.awayMs

        // 「在车旁」= 连着、信号强于开锁门限，且**状态帧或 RSSI 有一份是新的**。
        //
        // 1.26 改掉「必须状态帧新鲜」：状态帧断了但 RSSI 还在刷，说明车机就在旁边
        // 只是不肯推帧（车机省电、刚回连、地库信号差）。这时人拉门把手，车不开 ——
        // 用户看到的就是「罚站」。RSSI 强于门限本身已经足够证明人在车边。
        // 1.28：差 4dB 但正在走强，也算「到了」。
        //
        // 走近时原始读数会先跳上去，而平滑值要十几秒才跟上来（见 Cfg 注释）。
        // 门槛不必等它稳稳越过：趋势成立时给 4dB 宽限，既提前识别，
        // 又不至于把站在 10 米外的路人算成「贴车」。
        let reach = s.rssi >= c.thr
            || (s.rssiTrendUp && s.rssi >= c.thr - TREND_SLACK_DB)
        let near = s.connected && reach && (s.fresh || s.rssiFresh)
        if near {
            s.visited = true
            s.awayTicks = 0
            s.lastNearAt = s.now
        } else {
            s.awayTicks += 1
        }

        // 加速离开：信号已经弱到「绝不可能贴在车边」时，不必再等满 awayMs。
        // 只缩短确认时间，判据本身没变。
        var awayLongNow = awayLong
        if !near && s.fresh && s.rssi < c.bleThr && nearRef > 0
            && (s.now - nearRef) > c.fastAwayMs {
            awayLongNow = true
        }

        // 离开得足够久 → 下一次靠近算「新的一次到访」，允许再开一次锁
        if awayLongNow {
            s.unlockedThisVisit = false
        }

        // 车刚自锁、人却一直待在车旁 → 解除「本次到访已开过」的抑制。
        //
        // 现场：下车关门，车辆自动上锁（未锁→已锁），人转身想在副驾拿包。
        // 1.25 及以前这里要把「走开 30 秒」当解除条件，于是门怎么拉都不开。
        // 20 秒是权衡：自锁回环在 1~3 秒内就会暴露，20 秒足够挡住；
        // 而真心想上车的人不会在车边干站 20 秒还不碰门。
        if s.armed && s.unlockedThisVisit && near && s.flipAt > 0
            && (s.now - s.flipAt) > 20000 {
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
        // 1.22 起不再要求「连续 N 拍判远」：iOS 是事件驱动的，两次判定可能隔几分钟
        // 也可能隔 80 毫秒，「3 拍」在这里毫无意义。时间条件（awayMs=30 秒）才是确认。
        if c.autoLock && !s.armed && !s.moving && s.visited && !near && awayLongNow
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

    /// 1.22 收紧版：只要「车锁由未锁翻成已锁」就抑制本次到访的自动开锁，不再看是否判近。
    ///
    /// 为什么去掉 near：手机落在车里、蓝牙刚好断过一次，都会让「判近」失败，
    /// 于是抑制失效，下一拍就是「靠近 + 已锁 + 未开过」→ 车自己弹开。
    /// 而「从没锁变成已锁」本身就说明刚才有人在车边动过它，此时立刻解锁几乎总是错的。
    ///
    /// 不会误伤正常开锁：真正走开后 `unlockedThisVisit` 会被重置，下次走近照常开；
    /// 人就在车边想开锁时，手动按钮一直可用。
    static func suppressUnlockOnFlip(wasArmed: Bool, nowArmed: Bool) -> Bool {
        return !wasArmed && nowArmed
    }

    // MARK: iOS 专用的「靠近」判定

    /// 「靠近」在 iOS 上怎么算。三级判据，缺证据就不许说「近」。
    ///
    /// 1. **有新鲜 RSSI**（10 秒内读到过）→ 严格按用户设的门限。这是唯一有物理含义的距离证据。
    /// 2. **没有 RSSI，但最近 15 秒收到过 ≥3 帧状态帧** → 链路干净，判近。
    ///    穿墙时丢包率会明显上升（3 秒一帧变成 6~15 秒一帧），这条正好挡住
    ///    「人在楼上 / 地库另一层、车在下面、蓝牙却连着」的那种误判。
    /// 3. **两个证据都没有** → 返回 false。未知不等于近。
    ///
    /// 为什么不能再用「连着就算近」：iOS 后台 `readRSSI` 会被限流甚至直接不回调，
    /// 旧口径等于「永远判近」。地库里 GPS 失效、蓝牙穿墙连着 → 车直接被解开，
    /// 而人根本不在车边。宁可这一次不开锁（用户掏手机点一下），
    /// 也不能在没有证据的时候把车打开。
    static func nearAssumeByLink(rssi: Int, thr: Int, fresh: Bool, frameCount: Int) -> Bool {
        if fresh { return rssi >= thr }
        return frameCount >= 3
    }

    /// 统计「最近这段时间收到几帧状态帧」用的窗口。车机 3 秒一帧，15 秒正常能收到 4~5 帧。
    static let FRAME_WINDOW_MS: Int64 = 15000

    /// RSSI 多旧就算「没有新鲜值」。车机 3 秒一帧，10 秒已经足够宽裕。
    static let RSSI_FRESH_MS: Int64 = 10000

    // MARK: 蓝牙优先策略（1.25）

    /// 蓝牙信号在「判可用」这件事上的有效期，比 `RSSI_FRESH_MS` 宽得多。
    ///
    /// 为什么不能直接用 10 秒：RSSI 读不到**不等于**信号没了。iOS 在后台会限流
    /// `readRSSI`，安卓那边读数本身也是 15 秒一次。拿「10 秒没读到」当「信号断了」，
    /// 结果是定位反复启停 —— 省下来的电又全花在 GPS 上了。
    ///
    /// 60 秒的旧读数照样能用：这个值只跟 -90 比，而人在 60 秒内不会从车边走到穿墙距离。
    static let BLE_USABLE_HOLD_MS: Int64 = 60000

    /// 走远锁车的距离门槛下限（米）。
    ///
    /// 为什么从 30 提到 100：这一版把锁车改成「蓝牙彻底没信号 **且** 定位确认在
    /// 这个距离之外」，两个条件必须同时成立。30 米时城区 GPS 只能给到 ±50 米，
    /// 「算出来 30 米」可能是 80 米、也可能是 0 米，这个结论根本不能用。
    /// 100 米才允许下「就算误差全错，人也不在车边」的判断。
    ///
    /// 用户可以在界面上把 `geoFarM` 调得更大，但不会被调到它以下 —— 见 `farLockM(_:)`。
    static let FAR_LOCK_M: Double = 100

    /// 实际生效的锁车距离门槛。低于 `FAR_LOCK_M` 的设置一律按 `FAR_LOCK_M` 算。
    static func farLockM(_ userValue: Double) -> Double {
        if !userValue.isFinite || userValue <= 0 { return FAR_LOCK_M }
        return max(FAR_LOCK_M, userValue)
    }

    /// 判「蓝牙还够用、不许锁车」所需的信号余量（dB），加在开锁门限之上。
    ///
    /// 为什么不是「-90 以上都算有信号」：蓝牙穿墙太容易。人在二楼、车在楼下，
    /// 链路还挂着，RSSI 从贴车的 -60 掉到 -80 左右。如果把 -80 也算「人在车边」，
    /// 就是典型的一夜不锁车 —— 定位说 40 米不够 100 米、蓝牙说还连着，
    /// 两边都不动作，而界面一切正常。只有**明显强于门限**才算人真在车边。
    static let BLE_REACH_SLACK_DB = 6

    /// 「信号正在走强」时对开锁门限的宽限（dB）。
    ///
    /// 走近的那几秒里原始读数已经跳到 -72 附近，但用户还想再稳一点才认；
    /// 4dB 大约是「一步之内」的差别，配合趋势判断能把开锁提前 5~15 秒。
    static let TREND_SLACK_DB = 4

    /// 「连上即开」的最低信号底线（dBm）。
    ///
    /// 这条不是判据，是**止损**：连接建立后如果读到的第一个 RSSI 比它更弱，
    /// 说明手机和车之间隔着不止一堵墙（家里、楼上、隔壁车位），这一次不自动开。
    /// 贴在车门边时几乎不可能低于 -85 —— 那是穿两层混凝土的量级。
    static let CONNECT_MIN_RSSI = -85

    /// 蓝牙信号是否「实质可用」：连着、有读数、且明显强于开锁门限。
    ///
    /// - Parameter unlockThr: 用户设的开锁信号门限（默认 -72），这里再留
    ///   `BLE_REACH_SLACK_DB` 的余量，实际门槛是 -78。
    static func bleUsable(connected: Bool, rssiFresh: Bool, rssi: Int, unlockThr: Int) -> Bool {
        guard connected, rssiFresh else { return false }
        return rssi >= unlockThr - BLE_REACH_SLACK_DB
    }

    /// 蓝牙信号是否**足够开锁**：连着、读数新鲜、且达到用户设的开锁门限。
    ///
    /// 1.26 把这件事从 `bleUsable` 里拆出来。原来只有一个「可用」，它同时兼职：
    ///   - 省电：可用就停定位
    ///   - 锁车否决：可用就不锁车
    ///   - 开锁：可用就当人在车边
    ///
    /// 前两件要宽松（-78 也算，避免定位反复启停、避免误锁），第三件必须严格
    /// （到 `thr` 才算，否则门开不了）。混用之后，-78~-72 这一段成了黑洞：
    /// 定位被停掉、开锁又不达标 —— 人站在车门边，App 什么都不做。
    ///
    /// - Parameter rssiFresh: 这里的「新鲜」用 10 秒窗口（`RSSI_FRESH_MS`），
    ///   比 `bleUsable` 的 60 秒严。开锁要的是「此刻信号确实强」，不是「一分钟前强过」。
    static func bleStrong(connected: Bool, rssiFresh: Bool, rssi: Int, unlockThr: Int) -> Bool {
        guard connected, rssiFresh else { return false }
        return rssi >= unlockThr
    }

    /// 走远锁车的最终判据。
    ///
    /// **蓝牙优先的含义就在这里**：只要蓝牙还有可用信号，就绝不锁车 ——
    /// 人在车边、在车上拿东西、在车旁打电话，蓝牙都连着，这些场景一律不锁。
    /// 只有蓝牙没了，才轮到定位说话。
    ///
    /// - Parameters:
    ///   - bleUsable: 蓝牙此刻是否还有可用信号
    ///   - geoUsable: 定位这套数据此刻能不能用（授权、新鲜度、精度都在 `Geo.usable` 里挡）
    ///   - dist: 手机与车的直线距离（米），NaN 表示算不出来
    ///   - farM: 距离门槛，取 `farLockM(_:)`
    ///   - awayLong: 距上次判近是否已超过 `awayMs`。**只给定位用不了的人兜底** ——
    ///     没给定位授权的用户不能永远不锁车，那比误锁危险得多。
    static func farLockReady(bleUsable: Bool, geoUsable: Bool, dist: Double,
                             farM: Double, awayLong: Bool) -> Bool {
        if bleUsable { return false }
        if geoUsable && dist.isFinite { return dist >= farM }
        return awayLong
    }

    /// 1.29：定位判远这条**捷径**能不能真的下发锁车。
    ///
    /// `decideAction` 在蓝牙不可用时用 farLockReady 直接返回 LOCK，不经过 `decide`。
    /// 1.28 就是这样把「锁车成功之后还一直锁车」放出来的：人走远后
    /// 「蓝牙断 / 距离够远 / 离开够久」永远成立，于是每拍都算出 LOCK，
    /// 而 `decide` 里的 armed / visited / 冷却三道闸门全被绕过去了。
    /// 这里把闸门补回来，做成纯函数，两端共用同一组单测向量。
    static func allowFarLock(armedKnown: Bool, armed: Bool, lockedThisVisit: Bool,
                             now: Int64, lastLockAt: Int64, cooldownMs: Int64) -> Bool {
        // 本次到访已经发过锁车：哪怕车机还没回状态帧，也不再自动下发
        if lockedThisVisit { return false }
        // 锁态已知且车已经锁着
        if armedKnown && armed { return false }
        // 刚发过锁车，冷却期内不重复
        if lastLockAt > 0 && (now - lastLockAt) < cooldownMs { return false }
        return true
    }

    // MARK: 车辆电源状态（1.30）

    /// 熄火
    static let VS_OFF = 0
    /// ACC 通电（钥匙拧到 ACC，发动机没转）
    static let VS_ACC = 1
    /// 发动机已启动 / 原地怠速
    static let VS_ENGINE = 2
    /// 行驶中
    static let VS_RUNNING = 3

    /// 车辆当前是「熄火 / ACC 通电 / 已启动 / 行驶中」哪一档。
    ///
    /// 判定顺序不能反：行驶时 ACC 与启动位一定都是 1，
    /// 先看车速才能把「行驶」和「原地怠速」分开。
    /// 与安卓 `Logic.vehicleState` 同语义，供双端共用向量测试。
    static func vehicleState(speedKph: Int, acc: Bool, eng: Bool) -> Int {
        if speedKph > 0 { return VS_RUNNING }
        if eng { return VS_ENGINE }
        if acc { return VS_ACC }
        return VS_OFF
    }

    /// 状态文案。没拿到 vst 时调用方显示「—」，不要用这个函数硬报「熄火」。
    static func vehicleStateText(speedKph: Int, acc: Bool, eng: Bool) -> String {
        switch vehicleState(speedKph: speedKph, acc: acc, eng: eng) {
        case VS_RUNNING: return "行驶中"
        case VS_ENGINE:  return "已启动"
        case VS_ACC:     return "ACC 通电"
        default:         return "熄火"
        }
    }

    /// 双通道并发之后，最多再重发几轮。每轮间隔 `VERIFY_WINDOW_MS`。
    /// 4 轮 ≈ 80 秒，足够覆盖地库、弱网、车机刚唤醒这几种慢响应。
    static let VERIFY_MAX_ROUNDS = 4

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
    /// - 只允许补发 `VERIFY_MAX_ROUNDS - 1` 次，防止状态持续不符时无限补发。
    ///   1.22 是补一次就放弃，实测太急：地库里车机刚唤醒时第一次指令经常丢，
    ///   只补一次等于「开了两次都失败就再也不试」，用户走到车边打不开门。
    ///   现在给到 3 次，配合 20 秒窗口共 80 秒，覆盖慢响应场景，同时仍有硬上限。
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
        if rounds >= VERIFY_MAX_ROUNDS - 1 {
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

    /// 断开状态下重连尝试的最小间隔（熄屏/锁屏）
    static let RECONNECT_MIN_SCREEN_OFF: Int64 = 30000
    /// 断开状态下重连尝试的最小间隔（亮屏/前台，用户可能就在车边）
    static let RECONNECT_MIN_SCREEN_ON: Int64 = 12000
    /// 重连退避上限
    static let RECONNECT_MAX_SCREEN_OFF: Int64 = 90000
    static let RECONNECT_MAX_SCREEN_ON: Int64 = 45000

    /// 重连最小间隔（App 已进后台）。
    ///
    /// 这一档看着比熄屏还慢，但它治的是另一个病：
    /// 开着「后台定位」时 App **不会被挂起**（定位回调一直在给执行时间），
    /// 于是人车分离一整夜，重连逻辑会一整夜真的跑起来 ——
    /// 按前台 12 秒算是一夜 7200 次 connect，按 60 秒算是 1440 次。
    ///
    /// 而且这 60 秒不牺牲可用性：真正能在后台把车机等回来的，是
    /// `CBCentralManager.connect()` 交出去的那次 **pending 连接**（由系统蓝牙栈持有，
    /// App 睡着也在等），我们定时重提只是兜底防止它因蓝牙重启而失效。
    static let RECONNECT_MIN_BACKGROUND: Int64 = 60000
    /// 后台上限。走到这里说明人车确实长期分离，5 分钟重提一次足够兜底。
    static let RECONNECT_MAX_BACKGROUND: Int64 = 300000

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
    ///
    /// 三档优先级：**后台 > 熄屏 > 亮屏**。`background` 一定要由调用方传真实值，
    /// 写死成前台会让「开着后台定位过夜」变成整夜空转。
    static func reconnectDelayMs(fails: Int, screenOn: Bool, background: Bool = false) -> Int64 {
        let base: Int64
        let cap: Int64
        if background {
            base = RECONNECT_MIN_BACKGROUND
            cap = RECONNECT_MAX_BACKGROUND
        } else if screenOn {
            base = RECONNECT_MIN_SCREEN_ON
            cap = RECONNECT_MAX_SCREEN_ON
        } else {
            base = RECONNECT_MIN_SCREEN_OFF
            cap = RECONNECT_MAX_SCREEN_OFF
        }
        var d = base
        var i = 1
        while i < fails && d < cap {
            d *= 2
            i += 1
        }
        return min(d, cap)
    }

    /// 回前台时，隔多久才值得再向服务器要一次状态。
    ///
    /// 原来每次切回前台都发一次请求。用户反复切 App（看一眼、切出去回消息、
    /// 再切回来）时，这等于把网络轮询又加回来了。
    /// 蓝牙有新鲜状态帧的时候根本不缺这一下，只做一个很松的兜底；
    /// 没有蓝牙帧（人在外面）才需要勤一点。
    static func statusMinGapMs(bleFresh: Bool) -> Int64 {
        return bleFresh ? 60000 : 20000
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
    static let connectUnlock = "connect_unlock"
    /// 指令通道模式（1.26）：0 智能 / 1 仅蓝牙 / 2 仅网络
    static let chMode = "ch_mode"
    /// 洗车 / 代客模式截止时刻（毫秒）
    static let washUntil = "wash_until"
    /// 自动动作的通知与震动
    static let notifyOn = "notify_on"
    /// 门没关严不落锁（门位未确认前恒不生效）
    static let doorGuard = "door_guard"
    /// 自动刷新车辆状态（1.30）：前台每 60 秒查一次，进后台自动停
    static let autoRefresh = "auto_refresh"
    /// 1.32：高德 Web 服务 key，只用来把经纬度翻成地名
    static let amapKey = "amap_key"
    /// 1.36：坐标校正（WGS-84 → GCJ-02）。默认开。
    /// 车机给的是 GPS 原始坐标，地图要的是火星坐标，不转就差几百米。
    static let coordFix = "coord_fix"
}

/// 1.33：内置的高德 Web 服务 key。用户不需要填，开箱就能显示地名。
/// 万一以后要换，在设置卡最底下连点版本号两下（长按）会展开输入框，
/// 填了就以填的为准，清空就退回这个默认值。
let kDefaultAmapKey = "f5f737c3a5928dd41f62c81221e04026"

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

    /// 1.33：高德 key 的实际取值。用户填过就用填的，没填过（或清空了）用内置的。
    ///
    /// 统一从这里取，免得 resolvePlace 和设置界面各自判断一遍、结果不一致。
    var amapKey: String {
        let custom = str(StoreKey.amapKey).trimmingCharacters(in: .whitespacesAndNewlines)
        return custom.isEmpty ? kDefaultAmapKey : custom
    }

    /// 是否用了内置 key（设置界面要靠它显示「已内置 / 已自定义」）
    var amapKeyIsBuiltin: Bool {
        return str(StoreKey.amapKey).trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
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

    /// 走远锁车的距离门限（米）。
    ///
    /// 1.25 起默认 100：锁车条件是「蓝牙断联 **且** 定位在这个距离之外」，
    /// 30 米时城区 GPS 的 ±50 米误差会把「在车边」也算成「走远了」。
    /// 真正生效的值还要过一道 `Logic.farLockM()`，低于 100 一律按 100 算。
    var geoFarM: Double {
        get {
            let v = d.object(forKey: StoreKey.geoFarM) as? Double ?? 100
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

    /// 连上即开（1.28）。默认**开**。
    ///
    /// 开着：蓝牙一建立连接就下发开锁，不等 RSSI 收敛、不等车机状态帧。
    /// 这是治「罚站」最有效的一条，代价是蓝牙穿墙 —— 车在楼下、人在楼上，
    /// 只要链路重连过一次，车就会被解开。所以留了「首个读数弱于 -85 就不开」的止损。
    /// 觉得不安全的人可以关掉它，回到 RSSI 判据。
    var connectUnlock: Bool {
        get { return flag(StoreKey.connectUnlock, true) }
        set { putFlag(StoreKey.connectUnlock, newValue) }
    }

    /// 自动刷新车辆状态（1.30）。默认开。
    ///
    /// 只在**前台**跑：iOS 进后台后 Timer 必被挂起，写「后台也刷新」是骗人的。
    /// 蓝牙连着时状态帧 3 秒一帧，本身就在刷新，这条会跳过、不额外发网络请求。
    var autoRefresh: Bool {
        get { return flag(StoreKey.autoRefresh, true) }
        set { putFlag(StoreKey.autoRefresh, newValue) }
    }

    /// 指令通道模式（1.26）。默认智能：蓝牙优先，够不着转网络。
    ///
    /// 用户明确要求能自己选：「纯蓝牙使用」「网络和蓝牙自由选择、也能一起共用」。
    /// 这个值只影响**指令下发**，不影响判定 —— 车锁状态、门位只能从蓝牙状态帧读，
    /// 所以选「仅网络」时蓝牙照样连着，只是不下发开锁 / 锁车指令。
    var chMode: Int {
        get {
            let v = num(StoreKey.chMode, Logic.MODE_SMART)
            return (v == Logic.MODE_BLE || v == Logic.MODE_NET) ? v : Logic.MODE_SMART
        }
        set { putNum(StoreKey.chMode, newValue) }
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
//  SXKC/Core/MapGeo.swift  ——  坐标换算（WGS-84 → GCJ-02）
// ==========================================================================

//
//  MapGeo.swift
//  1.36：坐标系校正（WGS-84 → GCJ-02）
//
//  为什么需要它：车机上报的是 GPS 原始坐标（WGS-84），而中国大陆的苹果地图
//  （MapKit 底层用的就是高德数据）用的是 GCJ-02，也就是俗称的火星坐标。
//  把一个 WGS-84 的点直接丢进 MKMapView，会稳定偏 300~700 米 —— 这就是
//  1.35 地图页车标跟原版对不上的原因。
//
//  原版 iOS 包（顺心控车 1.0.6）的主二进制里能直接找到这套算法的常量：
//  6378245.0、-0.006693421622965943、72.004、137.8347、0.8293、55.8271、
//  -105.0 —— 说明它自己也在 App 内做了一次换算，只是没写在界面上。
//
//  同一个换算还必须用在逆地理上：高德 regeo 接口默认按 GCJ-02 解释传进去的
//  经纬度，灌原始 GPS 坐标等于问了一个偏 500 米的路口，地名会「大致对、细看不对」。
//


enum MapGeo {

    // MARK: 常量（克拉索夫斯基椭球，GCJ-02 算法规定值）

    private static let a = 6378245.0
    private static let ee = 0.00669342162296594323
    private static let pi = 3.1415926535897932384626

    // MARK: 开关

    /// 是否开启校正，默认开。
    ///
    /// 留这个开关只有一个用途：万一某台车机给出的本来就是 GCJ-02（个别平台会
    /// 在入库时先转一次），校正后反而偏，可以在隐藏设置里关掉，不用等我发新版。
    static var fixOn: Bool {
        return Store.shared.flag(StoreKey.coordFix, true)
    }

    // MARK: 对外

    /// 把「车机给的坐标 / 手机定位」换成地图能直接用的坐标。
    /// 开关关掉时原样返回，所有调用点都不用自己判断。
    static func display(lat: Double, lng: Double) -> CLLocationCoordinate2D {
        guard fixOn else { return CLLocationCoordinate2D(latitude: lat, longitude: lng) }
        return wgs2gcj(lat: lat, lng: lng)
    }

    static func display(_ c: CLLocationCoordinate2D) -> CLLocationCoordinate2D {
        return display(lat: c.latitude, lng: c.longitude)
    }

    /// 国内用的「输入经纬度 → 地图点」。境外原样返回（算法只在国境内有意义）。
    static func wgs2gcj(lat: Double, lng: Double) -> CLLocationCoordinate2D {
        guard lat.isFinite, lng.isFinite, inChina(lat: lat, lng: lng) else {
            return CLLocationCoordinate2D(latitude: lat, longitude: lng)
        }
        var dLat = transformLat(lng - 105.0, lat - 35.0)
        var dLng = transformLng(lng - 105.0, lat - 35.0)

        let radLat = lat / 180.0 * pi
        var magic = sin(radLat)
        magic = 1 - ee * magic * magic
        let sqrtMagic = sqrt(magic)

        dLat = (dLat * 180.0) / ((a * (1 - ee)) / (magic * sqrtMagic) * pi)
        dLng = (dLng * 180.0) / (a / sqrtMagic * cos(radLat) * pi)
        return CLLocationCoordinate2D(latitude: lat + dLat, longitude: lng + dLng)
    }

    /// 反向：GCJ-02 → WGS-84。
    ///
    /// 正算没有闭式反函数，用定点迭代逼近。迭代 3 次残差已在 0.1 米以内，
    /// 对「显示」和「判距」都够用。
    static func gcj2wgs(lat: Double, lng: Double) -> CLLocationCoordinate2D {
        guard lat.isFinite, lng.isFinite, inChina(lat: lat, lng: lng) else {
            return CLLocationCoordinate2D(latitude: lat, longitude: lng)
        }
        var wLat = lat
        var wLng = lng
        for _ in 0..<3 {
            let g = wgs2gcj(lat: wLat, lng: wLng)
            wLat += lat - g.latitude
            wLng += lng - g.longitude
        }
        return CLLocationCoordinate2D(latitude: wLat, longitude: wLng)
    }

    /// 粗糙但够用的国境判断：矩形框。框外（日韩、东南亚一部分）不换算。
    static func inChina(lat: Double, lng: Double) -> Bool {
        return lng > 73.66 && lng < 135.05 && lat > 3.86 && lat < 53.55
    }

    // MARK: 算法内部

    private static func transformLat(_ x: Double, _ y: Double) -> Double {
        var ret = -100.0 + 2.0 * x + 3.0 * y + 0.2 * y * y + 0.1 * x * y + 0.2 * sqrt(abs(x))
        ret += (20.0 * sin(6.0 * x * pi) + 20.0 * sin(2.0 * x * pi)) * 2.0 / 3.0
        ret += (20.0 * sin(y * pi) + 40.0 * sin(y / 3.0 * pi)) * 2.0 / 3.0
        ret += (160.0 * sin(y / 12.0 * pi) + 320.0 * sin(y * pi / 30.0)) * 2.0 / 3.0
        return ret
    }

    private static func transformLng(_ x: Double, _ y: Double) -> Double {
        var ret = 300.0 + x + 2.0 * y + 0.1 * x * x + 0.1 * x * y + 0.1 * sqrt(abs(x))
        ret += (20.0 * sin(6.0 * x * pi) + 20.0 * sin(2.0 * x * pi)) * 2.0 / 3.0
        ret += (20.0 * sin(x * pi) + 40.0 * sin(x / 3.0 * pi)) * 2.0 / 3.0
        ret += (150.0 * sin(x / 12.0 * pi) + 300.0 * sin(x / 30.0 * pi)) * 2.0 / 3.0
        return ret
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

    /// 小电池电压偏低（1.32）。
    ///
    /// 不带「点这里做什么」：这不是能远程解决的事，推它是为了让人下次上车前有准备，
    /// 别在停车场才发现打不着火。冷却 6 小时由调用方控制。
    @discardableResult
    func batteryLow(volt: Double) -> Bool {
        let c = UNMutableNotificationContent()
        c.title = "小电池电压偏低"
        c.body = String(format: "当前 %.1fV，低于 10.8V。长时间停放可能打不着火，建议着车充一会儿。", volt)
        c.sound = .default
        post(id: "sxkc.battery.low", content: c)
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
    func doorBlocked() -> Bool {
        // 1.22 起不再区分尾箱：这台车机不区分哪一扇门，任一门开都是低 4 位全 1
        let what = "有车门没关好"
        let c = UNMutableNotificationContent()
        c.title = "\(what)，没有自动锁车"
        c.body = "门开着锁了也等于没锁。关好门会自动补锁；想现在就锁，点「仍然锁车」。"
        c.sound = .default
        c.categoryIdentifier = Notify.catDoorOpen
        post(id: "sxkc.auto.dooropen", content: c)
        return true
    }

    /// 指令发出去了，但 20 秒内车机状态一次都没翻转。
    ///
    /// 1.22 新增。以前这种情况只往日志里写一行「无法确认」，界面继续显示「已锁车」——
    /// 明明没确认，却像个成功。现在必须让人知道「这一笔没算数」。
    func lockUnconfirmed(distText: String) -> Bool {
        let c = UNMutableNotificationContent()
        c.title = "锁车没能确认"
        c.body = distText.isEmpty
            ? "平台已受理，但 20 秒内车机状态没变化，很可能指令还在队列里。请确认一下车锁了没。"
            : "平台已受理，但 20 秒内车机状态没变化（\(distText)）。请确认一下车锁了没。"
        c.sound = .default
        c.categoryIdentifier = Notify.catDoorOpen
        post(id: "sxkc.auto.lockunconfirmed", content: c)
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
    /// 1.32：让车机立刻上报一次。原版「更新状态」，无参数。
    /// 和 203100 的区别：203100 读的是平台缓存，这条是叫醒车机现报。
    static let CODE_REPORT_NOW = "303505"
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
    /// 让车机立刻上报。失败不抛给界面 —— 手动刷新本来就是「尽力而为」。
    func reportNow() throws -> Resp { return try send(CarAPI.CODE_REPORT_NOW) }
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
        c.acc = bitOfVst(c.vst, 0x08)
        c.eng = bitOfVst(c.vst, 0x10)
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
        return bitOfVst(vst, 0x20)
    }

    /// vst 状态字节取某一位。第 3 个字节（索引 2）是状态字节：
    ///
    ///     0x08 ACC 通电   0x10 发动机启动   0x20 已设防（已锁）
    ///
    /// 三个实测样本互相印证：停车未锁 `000001C0`（b[2]=0x01，三位全 0）、
    /// 停车已锁 `000021C0`（b[2]=0x21，只有 0x20）、
    /// 行驶中 `000018A0`（b[2]=0x18，ACC 与启动同时置位）。
    ///
    /// 「ACC 通电但没启动」这一档目前没有实车样本，属按位定义推断 ——
    /// 界面上如实标「ACC 通电」，不硬报「已启动」。
    static func bitOfVst(_ vst: String, _ mask: UInt8) -> Bool {
        let b = Hex.to(vst)
        return b.count > 2 && (b[2] & mask) != 0
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
        /// 1.30：vst 第 3 字节 0x08 位 = ACC 通电
        var acc = false
        /// 1.30：vst 第 3 字节 0x10 位 = 发动机已启动
        var eng = false
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
    /// 快速采样档（1.28）：等开锁的窗口里用 2 秒，其余 5 秒。
    private var pingFast = false
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
        // 采样提速（1.28）：等开锁的窗口里 2 秒读一次，其余时间仍然是 5 秒。
        //
        // 5 秒是保活底线（车机 10 秒没往来就掐链路），不是判定需要的精度。
        // 而判定要的是「人刚走到车边」那一下 —— 2 秒一读能把发现时间从
        // 5~10 秒压到 2~4 秒；配合未平滑值，开锁提前十几秒。
        // 只在「车锁着 + 蓝牙连着」时提速，开车走了或人走远了自动回 5 秒。
        let iv = pingFast ? 2.0 : 5.0
        let t = Timer(timeInterval: iv, repeats: true) { [weak self] _ in
            guard let self = self else { return }
            guard self.connected, let p = self.peripheral, p.state == .connected else { return }
            p.readRSSI()
        }
        RunLoop.main.add(t, forMode: .common)
        pingTimer = t
    }

    /// 快速采样开关。档位没变就不重启定时器 —— 这个方法每次判定都会调。
    func setFastRssi(_ on: Bool) {
        guard keepAlive, ready, pingFast != on else {
            pingFast = on
            return
        }
        pingFast = on
        startPing()
        log("· RSSI 采样切换：\(on ? "2 秒（等开锁）" : "5 秒（保活）")")
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
        let restored = (dict[CBCentralManagerRestoredStatePeripheralsKey] as? [CBPeripheral]) ?? []
        // 恢复列表里可能不止一台（诊断页扫过的设备也会被记着），
        // 必须先挑出我们记住的那台车机，否则会去连别人的设备。
        let hit = restored.first { $0.identifier == savedUuid } ?? restored.first
        if let p = hit {
            peripheral = p
            p.delegate = self
            connected = (p.state == .connected)
            log("后台恢复：拿回车机连接")
            if connected {
                // 进程被杀过再恢复时，特征引用和会话密钥都没了，光"连着"发不出指令。
                // 重新走一遍服务发现 → 订阅 → 握手，链路在就不会再花连接时间。
                // 保活心跳会在 ready 置位时重新挂上（见 ready = true 那一处）。
                ready = false
                chr = nil
                busKey = nil
                p.discoverServices(nil)
            } else {
                // 拿回了外周对象但链路是断的：照样把连接请求交出去，
                // 否则这次唤醒之后又回到「用户不打开 App 就永远连不上」。
                ready = false
                log("后台恢复：外周未连接，重新提交连接")
                ensureConnected()
            }
        } else {
            // 系统为蓝牙事件把 App 捞起来，但恢复状态里一个外周都没有
            // （很常见：车机在我们睡着的时候才广播）。此时如果不主动把连接请求
            // 交出去，这次唤醒就白费了，接下来只能等用户自己打开 App。
            connected = false
            ready = false
            log("后台恢复：没有拿到外周，主动补一次连接请求")
            ensureConnected()
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
    static let buildTag = "b1110f"

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
    /// 连上即开（1.28，界面绑定）
    @Published var connectUnlockEnabled = true
    /// 围栏降耗开关（界面绑定）
    @Published var fenceEnabled = false
    /// 通知与震动开关（界面绑定）
    @Published var notifyEnabled = false
    /// 门没关好就不自动落锁（v1.19）
    @Published var doorGuardEnabled = true
    /// 指令通道模式（1.26，界面绑定）：0 智能 / 1 仅蓝牙 / 2 仅网络
    @Published var chMode = Logic.MODE_SMART
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
    /// 车辆电源状态（1.30）：行驶中 / 已启动 / ACC 通电 / 熄火。
    /// 没拿到过状态时是「—」，不硬报「熄火」——那会在车其实启动着的时候骗人。
    @Published var vehStateText = "—"
    /// 1.32：车辆所在地名（高德逆地理）。没填 key 时一直是空串，界面就不显示这一行。
    @Published var placeText = ""
    private var placeAt: Int64 = 0
    private var placeLat = 0.0
    private var placeLng = 0.0
    /// 1.33：改 key 后的防抖任务，见 `resetPlaceCache()`
    private var placeReloadWork: DispatchWorkItem?
    /// 是否已经拿到过有效状态字（决定文案用灰还是上色）
    @Published var vehStateShown = false
    /// 自动刷新状态开关（1.30，界面绑定）。只在前台跑，进后台自动停。
    @Published var autoRefreshEnabled = true

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
    /// 这一次会话里有没有因为「蓝牙没信号」而提示过开定位。
    /// 不加这个标记的话，每次判定都弹一次授权框，等于把人烦死。
    private var geoAskedThisSession = false
    /// 上次因为定位回调跑完整判定的时刻 / 当时的距离。
    /// 定位一秒能来好几个点，每个点都跑一遍 evaluate 是「卡」的主要来源之一。
    private var lastGeoEvalAt: Int64 = 0
    private var lastGeoEvalDist = -1.0
    private var lastRssiValue = -127
    private var lastRssiAt: Int64 = 0
    private var rssiSmooth = -127
    /// 原始读数连续两拍走强（1.28）。判开锁的辅助信号：
    /// 平滑值还在半分钟前的位置时，趋势已经能说明「人正在靠近」。
    private var rssiTrendUp = false
    private var rssiPrevRaw = -127
    private var rssiPrevDelta = 0
    /// 蓝牙状态帧解出来的电源位（1.30）。车速只有网络才有，所以蓝牙这一路
    /// 先记 acc/eng，文案再和最近一次网络车速合并判断。
    private var bleAcc = false
    private var bleEng = false
    /// 自动刷新定时器。iOS 进后台必被挂起，所以它是「前台才有」的。
    private var autoRefreshTimer: Timer?
    /// 断连后那次「查状态 → 必要时锁车」的去重时刻。
    /// 链路抖动时断开/连上会来回好几次，不去重就会连发好几条查询。
    private var linkLostQueryAt: Int64 = 0
    /// 连上即开的等待令牌：连上后又断开、或已经用别的方式开过，就作废这一次。
    private var connectUnlockToken = 0
    private var reconnectFails = 0
    private var nextReconnectAt: Int64 = 0
    /// 是否在后台。省电退避、轮询节流都要看它 —— 之前这里写死成「前台」，
    /// 结果开着后台定位过夜时按 12 秒一次地重连 Bluetooth（见 Power 的注释）。
    private var isBackground = false
    /// 进后台时申请的那点收尾时间，用完要主动 end，否则会被系统强杀
    private var bgTask: UIBackgroundTaskIdentifier = .invalid
    /// 断线重试令牌：重新排一次就把旧的那次作废，避免每次断开都叠一个定时器
    private var reconnectToken = 0

    /// 自动锁车失败后的重试时刻；0 表示没有待重试的任务
    private var autoLockRetryAt: Int64 = 0
    /// 这一轮自动锁车已经失败几次（最多 3 次就停手，交给用户手动锁）
    private var autoLockFails = 0

    // MARK: 开锁后 10 分钟守夜（1.32）
    //
    // 用户要的边界很明确：开锁后 600 秒没开门，
    //   · 蓝牙还连着 → 不回锁（人可能就在车边，锁了会把人锁在外面）
    //   · 蓝牙已经断了 → 按「断开就锁」的既有规则处理
    // 所以这里只当一个计时器，不自己发明锁车条件。
    private var unlockWatchAt: Int64 = 0
    private var unlockDoorSeen = false
    private var unlockWatchDone = false
    private var unlockWatchTimer: Timer?
    /// 低电压提醒的冷却：6 小时内最多一条，停车时别反复弹
    private var lastBatteryNotifyAt: Int64 = 0
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
    /// 本次「到访」是否已经发过锁车指令。
    /// 一次到访只锁一次，不能因为车机抖动反复下发。
    private var lockedForThisVisit = false
    /// 1.29：闸门挡住重复锁车时只打一条日志，别每拍刷屏
    private var lockSuppressLogged = false
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
    /// 尾箱位（body[3] bit4）。1.22 起不再采信：三份实车日志里从没单独出现过，
    /// 而万一这个位另有含义就会永久拦住锁车。字段留着只为兼容旧接口。
    private var doorTrunk = false
    /// 最近一次拿到门位的时刻（ms）。超过 doorStaleMs 就不采信
    private var doorMs: Int64 = 0
    /// 上一次因为车门没关而拦下锁车的时刻，用来给通知限频
    private var doorBlockAt: Int64 = 0
    /// 锁车前为拿一份「新鲜门位」而主动连蓝牙的截止时刻。0 = 没在等
    private var doorWaitUntil: Int64 = 0
    /// 门位有效期：3 秒一帧，断开 / 省电之后会停在旧值上，过期就不能再拿它拦锁车
    private let doorStaleMs: Int64 = 30000

    // MARK: 网络指令待确认（1.22）
    /// 网络指令已受理、等状态帧确认。0 = 没有待确认的
    private var netPendAt: Int64 = 0
    /// 这条待确认的指令是不是开锁
    private var netPendUnlock = false
    /// 是不是自动决策触发的（决定确认后要不要发通知）
    private var netPendAuto = false
    /// 已经补发过几次
    private var netPendRounds = 0
    /// 最后没能确认：界面必须如实显示，而不是继续挂着「已锁车」
    @Published var netUnconfirmed = false
    /// 最近一次从状态帧拿到锁态的时刻。用来区分「指令之后真翻转」和「本来就等于期望值」
    private var lastArmedFrameAt: Int64 = 0
    /// 最近 15 秒收到的状态帧时刻，用来在拿不到 RSSI 时判断「链路是否干净」
    private var frameTimes: [Int64] = []
    /// 当前为什么不动手，直接显示在状态卡上
    @Published var whyText = ""

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
        connectUnlockEnabled = store.connectUnlock
        doorGuardEnabled = store.flag(StoreKey.doorGuard, true)
        fenceEnabled = store.fenceOn
        notifyEnabled = store.notifyEnabled
        chMode = store.chMode
        locText = loc.statusText
        statsText = Stats.summary()
        Notify.shared.setup()
        log("iOS 版启动")
        log("提示：iOS 拿不到车机 MAC，改用 0xFFE0 指纹 + 已记住的 identifier 连接")

        // 自动模式必须跨启动保留。
        //
        // `store.autoOn` 从 1.19 起就一直在写（start/stop 都写），但**从来没有
        // 任何地方读回来** —— 于是进程一结束 `running` 就回到初值 false，
        // 用户看到的就是「退出软件再打开，自动靠近开锁自己变成关闭」。
        // 安卓那边是在 MainActivity onCreate 里读 K_AUTO 重新拉起服务的，
        // iOS 缺的正是这一步。
        if signedIn && store.autoOn {
            beginAuto(restoring: true)
        } else if signedIn {
            whyText = "自动模式已关闭"
        }
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

    func start() { beginAuto(restoring: false) }

    /// 真正的开启动作。`restoring` 只影响第一条日志文案。
    ///
    /// 拆出来的原因：冷启动时要把上次开着的自动模式接回来，而「接回来」必须和
    /// 手动点开**完全一样**。只写 `running = true` 是不够的 —— 那样界面显示
    /// 「已开启」，但保活心跳、定位、重连一个都没挂上，等于假装开着：
    /// 用户以为靠近会开锁，走到车边却毫无反应，比明确显示"关闭"更糟。
    private func beginAuto(restoring: Bool) {
        guard !running else { return }
        running = true
        store.autoOn = true
        ble.clearDiagMode()
        ble.setKeepAlive(true)
        if restoring {
            log("↻ 自动模式按上次的状态恢复开启（离开 App 前是开着的）")
        } else {
            log("▶ 自动模式开启（蓝牙优先：连着就判、不取 GPS；断了才用定位兜底）")
        }
        log("· 构建 \(AutoEngine.buildTag) · 门位解析已启用")
        ensureSession { ok in
            if !ok { self.log("⚠︎ 没有有效会话，网络通道不可用（蓝牙仍可用）") }
        }
        // 开启自动模式 = 用户现在就要用，退避计数从头算
        reconnectFails = 0
        nextReconnectAt = 0
        // 注意：这里**不再**预启动定位。1.25 起定位只在「蓝牙没信号」时才拉起，
        // 由 decideAction 按需启停。启动时先连蓝牙，连上就一分钱定位电都不花。
        ble.ensureConnected()
        startAutoRefresh()
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
        st.flipAt = 0
        st.awayTicks = 0
        st.lastNearAt = 0
        geoSt = Geo.St()
        lockedForThisVisit = false
        lockSuppressLogged = false
        reconnectToken += 1          // 作废挂着的那次断线重试
        reconnectFails = 0
        nextReconnectAt = 0
        autoLockRetryAt = 0
        autoLockFails = 0
        // 1.32：关掉自动模式，开锁守夜也一并收掉，否则 10 分钟后还会去查一次
        stopUnlockWatch()
        loc.stop()
        stopAutoRefresh()
        geoActive = false
        distText = ""
        log("■ 自动模式关闭")
        powerText = ""
        // 不清的话，状态卡会一直挂着关掉之前那句「在车旁 · 车是锁着的状态」，
        // 看着像还在工作。
        whyText = "自动模式已关闭"
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
        frameTimes.removeAll()
        lastUnlockAt = 0
        lastLockAt = 0
        lastPollAt = 0
        lastNetAt = 0
        netRetried = false
        netPendAt = 0
        netUnconfirmed = false
        doorWaitUntil = 0
        whyText = ""
        lastResult = ""
        car = nil
        lockedForThisVisit = false
        lockSuppressLogged = false
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
    /// 判定本身全在 `decideAction` 里（1.25 起）：蓝牙有信号就只看蓝牙、定位停着；
    /// 只有蓝牙没了才拉起定位判距离。
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
        // `st.rssi` 由 decideAction 按「有没有新鲜 RSSI」折算后再用，这里不重复算。

        // 断线后按退避重连（人车分离时不要 4 秒一次地空转）
        if running && !ble.isConnected && !ble.busy && now >= nextReconnectAt {
            let d = Power.reconnectDelayMs(fails: max(1, reconnectFails),
                                           screenOn: screenOn, background: isBackground)
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

        // 等开锁的窗口里把采样提到 2 秒。开完锁（或车本来就是开的）立刻回 5 秒 ——
        // 不能在车边整天 2 秒一次地读，那点电全花在这上面了。
        ble.setFastRssi(running && ble.isConnected && armed && !st.unlockedThisVisit)

        // 判定全在 decideAction 里（1.25）：蓝牙优先，接不上才转定位。
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
            var doorFresh = doorKnown && (nowMs - doorMs) < doorStaleMs

            // ── 先补一份新鲜门位（1.22）──
            // 走网络锁车时蓝牙通常已经断开，门位必然过期，门闸就被整个跳过 ——
            // 而「人走远了、门没关严」恰恰是最需要门闸的场景。
            // 所以先主动连一次蓝牙，最多等 8 秒；拿到状态帧就按真实门位判，
            // 等不到才放行，并如实记一条日志。
            var holdForDoor = false
            if store.flag(StoreKey.doorGuard, true), !doorFresh, ble.hasSavedTarget {
                if doorWaitUntil == 0 {
                    doorWaitUntil = nowMs + 8000
                    log("锁车前门位未知 → 先连蓝牙拿一次门位（最多等 8 秒）")
                    ble.ensureConnected()
                    whyText = "正在确认车门状态，最多等 8 秒…"
                    holdForDoor = true
                } else if nowMs < doorWaitUntil {
                    holdForDoor = true
                } else {
                    doorWaitUntil = 0
                    log("⚠ 8 秒内没拿到门位 → 按门位未知处理，照常锁车")
                }
            }

            if holdForDoor {
                // 这一拍本来要锁，现在先等门位：不写 lastLockAt、不进冷却
            } else {
                doorFresh = doorKnown && (CarAPI.nowMs() - doorMs) < doorStaleMs
                if store.flag(StoreKey.doorGuard, true),
                   Logic.doorBlocksLock(doorKnown: doorFresh, doorOpen: doorOpen) {
                    whyText = "有车门开着，暂停锁车（关好会自动补锁）"
                    log("⚠ 检测到车门没关好，本轮不落锁（关好后会自动补锁）")
                    if store.notifyEnabled, nowMs - doorBlockAt > 60000 {
                        doorBlockAt = nowMs
                        Notify.shared.doorBlocked()
                    }
                } else {
                    log("◇ 判定（\(reason) · \(src)）：确认离开 → 锁车")
                    requestAction(unlock: false, auto: true)
                }
            }
        }

        // 到点的锁车重试。只在 App 还活着时有效：后台被挂起时这里不会执行，
        // 所以重试失败不影响「断开后由定位判距离」那条主路。
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
        refreshWhy(now)
        checkVerify(now: now)
    }

    /// 算出「现在为什么不动手」，直接显示在状态卡上。
    ///
    /// 1.22 新增。以前这些理由只写在日志里，用户想知道「刚才走到车边为什么没开锁」
    /// 只能去诊断页逐条翻 —— 而这恰恰是最常被问的问题。
    private func refreshWhy(_ now: Int64) {
        if !running { whyText = "自动模式已关闭"; return }
        if store.washUntil > now { whyText = "洗车 / 代客模式：自动判定已暂停（手动照常）"; return }
        if netPendAt > 0 { whyText = "指令已发出，等车机确认…"; return }
        if doorWaitUntil > 0 { whyText = "正在确认车门状态，最多等 8 秒…"; return }
        if store.chMode == Logic.MODE_BLE && !ble.isConnected {
            whyText = "仅蓝牙模式 · 正在重连车机（连不上这一笔就放弃）"
            return
        }
        if !armedKnown { whyText = "还没收到车锁状态"; return }

        let farM = Int(Logic.farLockM(store.geoFarM))

        // ── 蓝牙有信号：主路径，正常状态不必解释 ──
        if ble.isConnected {
            if st.unlockedThisVisit && armed {
                whyText = "车辆刚自己上锁 · 在车旁持续 20 秒或走开再回来才会自动开"
                return
            }
            if isNearNow() {
                if !armed {
                    whyText = "在车旁 · 车是开着的"
                } else if st.unlockedThisVisit {
                    whyText = "本次到访已开过锁；走开再回来才会自动开"
                } else {
                    whyText = "在车旁 · 开锁冷却中"
                }
            } else {
                // 1.26：把「差多少」直接写出来。用户在门口罚站时，最想知道的
                // 就是「-75 差 3dB 到不了 -72」，而不是一句「蓝牙已连接」。
                let r = rssiSmooth
                if r > -120 && r < store.cfg.thr {
                    whyText = "信号 \(r)dBm 未达门限 \(store.cfg.thr)dBm · 再靠近一点，或等重连即开"
                } else {
                    whyText = "蓝牙已连接 · 走远到 \(farM) 米外才会自动锁"
                }
            }
            return
        }

        // ── 蓝牙没信号：看定位怎么说 ──
        if geoActive, !geoSt.dist.isNaN {
            let d = geoSt.dist
            whyText = d >= Logic.farLockM(store.geoFarM)
                ? "距车 \(Int(d.rounded())) 米 · 正在锁车…"
                : "距车 \(Int(d.rounded())) 米 · 还没到 \(farM) 米，不锁"
            return
        }
        if !store.geoOn {
            whyText = "蓝牙已断 · 定位兜底已关，断联 \(store.cfg.awayMs / 1000) 秒后锁"
            return
        }
        if !armed && !st.visited { whyText = "没靠近过这辆车，不会自动锁"; return }
        if doorKnown && (now - doorMs) < doorStaleMs && doorOpen {
            whyText = "有车门开着，暂停锁车"
            return
        }
        whyText = ""
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

    /// 蓝牙优先、定位兜底（1.25 重写）。
    ///
    /// 上一版是「定位可用就按距离判」，代价是定位常开：fine 档每秒要 GPS 点，
    /// 每来一个点就触发一次完整 evaluate（建 geo、算距离、推小组件、跑核实），
    /// 人走一步就是一轮。实测一天下来又热又卡。而它换来的精度其实没必要 ——
    /// 蓝牙 RSSI 判「在不在车旁」比 10 米 GPS 准得多。
    ///
    /// 现在的三条规则（1.28）：
    /// 1. **蓝牙一连上** → 立刻下发开锁（「连上即开」，见 `unlockOnConnect`）。
    /// 2. **蓝牙有可用信号**（连着、帧新鲜、RSSI ≥ 门限-6）→ 只按蓝牙判，
    ///    用**未平滑**读数 + 上升趋势；并且**把定位整个停掉**。省电主要来源。
    /// 3. **蓝牙没信号** → 才拉起定位，而且定位只干一件事：粗档判距离，
    ///    超过 100 米才锁车。1.28 起定位不再参与开锁。
    private func decideAction(now: Int64, cfg: Logic.Cfg) -> Int {
        let gcfg = store.geoCfg

        let rssiFresh = lastRssiAt > 0 && (now - lastRssiAt) < Logic.RSSI_FRESH_MS
        st.rssiFresh = rssiFresh
        // ── 1.28：判开锁用**未平滑**的原始读数 ──
        //
        // 平滑公式是 (3×旧 + 新)/4，样本 5 秒一个，时间常数 17 秒。从 -80 爬到 -72
        // 需要 6 个样本 = 30 秒。也就是说人已经贴在车门上，判定还在用半分钟前的
        // 信号值 —— 这是「每天都罚站」最直接的一条。
        // 判锁车仍然用平滑值（见下面 bu / farLock）：那边要的是稳，不是快。
        let rawUsable = rssiFresh && lastRssiValue > -120
        st.rssi = rawUsable ? lastRssiValue : rssiSmooth
        st.rssiTrendUp = rssiTrendUp

        // 完全读不到读数时退回「状态帧判近」：车机省电、刚回连时状态帧还在推，
        // 人就在车边，只是没过 RSSI。
        if !rssiFresh, Logic.nearAssumeByLink(rssi: st.rssi, thr: cfg.thr,
                                              fresh: false, frameCount: recentFrameCount(now)) {
            st.rssi = cfg.thr
        }

        // 共享状态（visited / unlockedThisVisit / lastNearAt）必须一直维护，
        // 否则「走开再回来」的语义会丢。动作由下面的策略决定，不由它决定。
        let bleAct = Logic.decide(&st, cfg)
        // 1.29：这一拍判近 = 人回到车边 = 新的一次到访，解除「本次已锁过」的抑制。
        // 锁车成功那一拍 lastNearAt 还是上一次判近的旧值，不会把闸门误清掉。
        if st.lastNearAt == now {
            lockedForThisVisit = false
            lockSuppressLogged = false
        }

        // ── 仅蓝牙模式：定位完全不参与 ──
        // 用户选「纯蓝牙」要的就是：不取 GPS、不发网络。判定全交给 RSSI 与状态帧，
        // 锁车退回「断开够久」。这里必须提前返回，否则下面会照样拉起定位。
        if store.chMode == Logic.MODE_BLE {
            stopGeoForBle()
            return bleAct
        }

        // ── 刚连上、还没读到第一个 RSSI：这一拍什么都不判 ──
        // 否则会掉进「蓝牙不可用 → 拉定位 → 判是否该锁车」，在下发「连上即开」
        // 之前先发一条锁车指令（acting 被占住，开锁反而被跳过）。
        if ble.isConnected && lastRssiAt == 0 {
            stopGeoForBle()
            return bleAct == Logic.UNLOCK ? Logic.UNLOCK : Logic.NONE
        }

        // 判「蓝牙可用」用的是宽松得多的窗口（60 秒），不是 RSSI 新鲜窗口（10 秒）。
        // 读不到读数不等于信号没了：iOS 后台会限流 readRSSI，拿 10 秒当断线
        // 会让定位反复启停，省下的电又全花回 GPS。
        let heldFresh = lastRssiAt > 0 && (now - lastRssiAt) < Logic.BLE_USABLE_HOLD_MS
        let bu = Logic.bleUsable(connected: ble.isConnected, rssiFresh: heldFresh,
                                 rssi: rssiSmooth, unlockThr: cfg.thr)

        if bu {
            // ── 蓝牙够用（≥ 门限 - 6dB）：一个 GPS 点都不取 ──
            //
            // 1.28 删掉了「定位兜底开锁」，所以弱连接不再需要精细定位 ——
            // 开锁与否全交给上面的 bleAct（未平滑值 + 上升趋势）。
            // 地库里 GPS 本来也给不出 ±30 米的精度，那段兜底从来没真正生效过。
            stopGeoForBle()
            // 蓝牙可用时绝不锁车：人可能就在车边，只是信号被口袋挡住。
            // 之前这里直接 return bleAct，弱信号站久了会被判「离开 30 秒」而落锁。
            return bleAct == Logic.UNLOCK ? Logic.UNLOCK : Logic.NONE
        }

        // ── 蓝牙不可用：定位只剩一件工作 —— 判「是否走远到该锁车」 ──
        startGeoForFar()
        let g = buildGeo(now, cfg, gcfg)
        let ok = Geo.usable(g, gcfg)
        if geoActive != ok { geoActive = ok }
        updateDistText(g)
        tuneGeoMode(g)

        let farM = Logic.farLockM(store.geoFarM)
        // 距上次判近过了多久。只给「定位用不了」的人兜底用：
        // 没给定位授权的用户不能永远不锁车，那比误锁危险得多。
        let awayLong = st.lastNearAt > 0 && (now - st.lastNearAt) > cfg.awayMs

        geoSt = g

        if Logic.farLockReady(bleUsable: false, geoUsable: ok, dist: g.dist,
                              farM: farM, awayLong: awayLong) {
            // 1.29：这条捷径不经过 decide，必须自己把闸门补齐。否则锁车成功后
            // 条件依旧成立，每一拍都会再下发一条锁车（本次到访已锁过 / 车已锁 /
            // 冷却期内，三种情况都不该再发）。
            guard Logic.allowFarLock(armedKnown: armedKnown, armed: armed,
                                     lockedThisVisit: lockedForThisVisit,
                                     now: now, lastLockAt: lastLockAt,
                                     cooldownMs: cfg.lockCooldownMs) else {
                if !lockSuppressLogged {
                    lockSuppressLogged = true
                    log("· 本次到访已锁过（或车已锁 / 冷却中）→ 不再重复下发锁车")
                }
                return Logic.NONE
            }
            lockSuppressLogged = false
            return Logic.LOCK
        }

        return Logic.NONE
    }

    /// 蓝牙有信号时把定位停掉。**这是这一版省电的主要来源**：
    /// 原先定位一路常开，人在车旁一天几百次采点；现在只有在车机连不上时才有 GPS。
    private func stopGeoForBle() {
        // 界面状态先清：即使定位本来就没跑（仅蓝牙模式），也要把「距车 xx 米」
        // 这类上一轮的残留清掉，否则用户会拿一个不再更新的数当实时值。
        if geoActive || !distText.isEmpty {
            geoActive = false
            // 距离必须跟着一起清掉：定位停了之后这个数不会再更新，
            // 留着「距车 320 米」比留一个空格更糟。
            distText = ""
            lastDistM = -1
            pushWidget(force: true)
        }
        guard loc.running else { return }
        loc.stop()
        log("· 停掉定位（不再取 GPS 点）")
    }

    /// 门限的简写，只给日志用
    private var cfgThr: Int { return store.cfg.thr }

    /// 蓝牙没信号时才拉起定位，默认粗档。
    /// 判 100 米用不着 10 米精度，粗档（百米精度 + 100 米位移）耗电约细档的十分之一。
    private func startGeoForFar() {
        guard running, store.geoOn else { return }
        if loc.running { return }
        guard loc.authorized else {
            // 没授权就只记一次，别每次判定都弹提示
            if !geoAskedThisSession {
                geoAskedThisSession = true
                loc.askPermission()
                log("⚠︎ 蓝牙没信号、定位没授权 → 只能靠「断联 30 秒」判锁车")
            }
            locText = loc.statusText
            return
        }
        loc.setBackground(store.locBg)
        loc.setMode(.coarse)
        loc.start()
        locText = loc.statusText
        log("▶ 蓝牙没信号 → 拉起粗档定位判距离（门槛 \(Int(Logic.farLockM(store.geoFarM))) 米）")
    }

    /// 定位档位自适应：远处粗档、回到车附近升细档。
    /// 只有「人就在车边、要判 10 米」这一次才值得花细档的电。
    private func tuneGeoMode(_ g: Geo.St) {
        guard store.geoOn, loc.running else { return }
        let farM = Logic.farLockM(store.geoFarM)
        let target: Loc.Mode = (store.fenceOn
            && Logic.canGoCoarse(dist: g.dist, acc: g.phoneAcc, fenceM: farM))
            ? .coarse : .fine
        loc.setMode(target)
        // 车的位置已知就挂一个系统级围栏：App 被挂起也能在「回到车附近」时被叫醒
        if g.carValid, !loc.fenceMatches(lat: g.carLat, lng: g.carLng) {
            loc.startFence(lat: g.carLat, lng: g.carLng, radius: min(farM, fenceRadiusM))
        }
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
    ///
    /// 1.25 起加了节流：定位一秒能来好几个点，而完整的 `evaluate` 要建 geo、算距离、
    /// 推小组件、跑一遍核实。每个点都跑等于拿几十次重复计算换一个不会变的结论 ——
    /// 卡顿和发热有一半来自这里。现在只在「距离明显变了（20 米）」或者
    /// 「过了 20 秒」时才真的判一次。
    private func onLocUpdate() {
        let now = CarAPI.nowMs()
        let g = buildGeo(now, store.cfg, store.geoCfg)
        updateDistText(g)
        guard running else { return }
        let moved = lastGeoEvalDist < 0 || abs(g.dist - lastGeoEvalDist) >= 20
        if moved || now - lastGeoEvalAt >= 20000 {
            lastGeoEvalAt = now
            lastGeoEvalDist = g.dist
            evaluate("定位更新")
        }
    }

    /// 只给「用户手动要求」用的一处：切前后台模式时要让新参数立刻生效。
    /// 自动判定路径已经改走 `startGeoForFar()`，不再调这个。
    private func startLoc() {
        loc.setBackground(store.locBg)
        loc.askPermission()
        loc.start()
        locText = loc.statusText
        log("▶ 定位已启动（\(loc.statusText)，门槛 \(Int(store.geoNearM)) / \(Int(Logic.farLockM(store.geoFarM))) 米）")
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
        // 不再无条件拉起来：定位是不是在跑由「蓝牙有没有信号」决定
        if running { evaluate("定位模式切换") }
    }

    /// 界面开关「走远锁车（用定位确认距离）」。
    ///
    /// 1.25 起语义变了：不再是「用定位判距为主」，而是
    /// **「蓝牙没信号时，允许用定位确认 100 米再锁车」**。
    /// 打开只是允许，真正启动要等蓝牙断开 —— 蓝牙连着时定位一直是停着的。
    func setGeoEnabled(_ on: Bool) {
        store.geoOn = on
        geoEnabled = on
        if on {
            log("▶ 走远锁车：开（蓝牙没信号时才用定位确认 \(Int(Logic.farLockM(store.geoFarM))) 米）")
            if running { evaluate("开启定位兜底") }
        } else {
            log("▶ 走远锁车：关（只按「蓝牙断联 30 秒」判锁车）")
            loc.stop()
            geoActive = false
            distText = ""
        }
        locText = loc.statusText
    }

    // MARK: 一键启动 / 熄火

    func startEngine() { engine(start: true) }
    func stopEngine() { engine(start: false) }

    /// 走网络，不需要蓝牙在附近。实车抓包：303120 启动、303125 熄火。
    private func engine(start: Bool) {
        // 启动 / 熄火只有网络这一条路。仅蓝牙模式下拒绝，
        // 而不是「偷偷发一条」—— 那正是用户选纯蓝牙时要避开的东西。
        if store.chMode == Logic.MODE_BLE {
            log("· 仅蓝牙模式：\(start ? "一键启动" : "熄火")只能走网络，已禁用")
            lastResult = "仅蓝牙模式不支持\(start ? "启动" : "熄火")"
            return
        }
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
    /// 蓝牙断开的那一刻。
    ///
    /// 1.25 起这里**不再直接锁车**。用户要的判据是「蓝牙断联 **且** 定位 100 米外」，
    /// 而刚断开时人往往就在车边：下车、开后备箱、走进旁边的便利店、进地库电梯口。
    /// 这几种情况下"断开即锁"，等于把车锁在车主手里，比不锁更烦。
    ///
    /// 现在它只做一件事：把判定往前推一拍，让 `decideAction` 去拉起定位。
    /// 门闸、冷却、行驶中这些检查都还在真正的 LOCK 分支里，一条没少。
    /// 连上即开（1.28）。
    ///
    /// 为什么要有它：原来的判定要同时满足「链路建立 → 读到读数 → 读数过门限 →
    /// 平滑值收敛」，每一步都吃掉几秒到几十秒，人站在车门前的体感就是 App 死了。
    /// 这一条把等待全部省掉：**不等读数、不等状态帧、不等平滑**。
    ///
    /// 代价得说清楚：蓝牙能穿墙。人在家里、车在楼下，只要链路挂着，一次重连就会
    /// 把车解开。所以留了 0.8 秒的止损 —— 连上后读到的第一个 RSSI 若弱于 -85
    /// （穿两层墙的量级），这一次不开。贴车门时几乎不可能低于 -85。
    private func unlockOnConnect() {
        guard running, store.autoUnlock, store.connectUnlock,
              store.chMode != Logic.MODE_NET else { return }
        guard CarAPI.nowMs() >= store.washUntil else { return }
        guard !acting, !ble.busy, !st.moving, !(car?.moving ?? false) else { return }
        guard !st.unlockedThisVisit else { return }
        // 已经知道车是开着的，就不要再发一条（幂等，但没必要）
        if armedKnown, !armed { return }

        connectUnlockToken += 1
        let tk = connectUnlockToken
        let t0 = CarAPI.nowMs()
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) { [weak self] in
            guard let self = self, self.connectUnlockToken == tk, self.ble.isConnected else { return }
            guard self.running, self.store.autoUnlock, self.store.connectUnlock else { return }
            guard !self.acting, !self.st.unlockedThisVisit else { return }
            let gotReading = self.lastRssiAt >= t0
            if gotReading, self.lastRssiValue < Logic.CONNECT_MIN_RSSI {
                self.log("· 连上即开：首个读数 \(self.lastRssiValue)dBm 弱于 \(Logic.CONNECT_MIN_RSSI) → 这次不开")
                return
            }
            // 先占住「本次到访已开过」，防止链路抖动时反复下发
            self.st.unlockedThisVisit = true
            self.geoSt.unlockedThisVisit = true
            self.log("▶ 连上即开：\(gotReading ? "\(self.lastRssiValue)dBm" : "还没读到 RSSI")，直接下发开锁")
            self.requestAction(unlock: true, auto: true)
        }
    }

    /// 开锁没成功 → 解除「本次到访已开过」。
    ///
    /// 1.28 起这个标记在「连上即开」时是**先占后发**的：占住是为了防抖动重发，
    /// 但如果这一笔根本没成功，人就被永久关在门外了（车锁着、判定还说「开过了」）。
    /// 所以失败要还回去，下一拍或下次连上还能再试。
    private func clearVisitOnUnlockFail() {
        st.unlockedThisVisit = false
        geoSt.unlockedThisVisit = false
        log("· 开锁未成功 → 解除本次到访限制，下次靠近或重连会再试")
    }

    private func handleLinkLost() {
        guard running else { return }
        log("· 蓝牙断开 → 转定位判距（\(Int(Logic.farLockM(store.geoFarM))) 米外才锁）")
        evaluate("蓝牙断开")
        queryAfterLinkLost()
    }

    /// 蓝牙断开后：查一次真实状态，没锁就补一条锁车，锁完由 9 秒回查确认。
    ///
    /// 「双指令」在这里只能是「网络一条 + 重连后蓝牙状态帧补一条」——
    /// 连接已经断了，蓝牙指令没有物理通道可发，写「已经发了两条」是骗人的。
    /// 所以日志如实分开写：先发网络，蓝牙那一路等重连后的状态帧。
    ///
    /// 已锁就一个字都不发：`allowFarLock` 里的 `armedKnown && armed` 就是这道闸。
    private func queryAfterLinkLost() {
        let now = CarAPI.nowMs()
        // 链路抖动时断开/连上会来回好几次，15 秒内只跑一次
        if linkLostQueryAt > 0 && now - linkLostQueryAt < 15000 { return }
        linkLostQueryAt = now
        if store.chMode == Logic.MODE_BLE {
            log("· 仅蓝牙模式：断连后不查网络")
            return
        }
        log("▶ 蓝牙断开：发网络状态查询（蓝牙这一路等重连后由状态帧补）")
        refreshStatus { [weak self] c in
            guard let self = self else { return }
            guard let c = c, c.reportedAt > 0 else {
                self.log("⚠ 断连后状态查询失败，本轮不判断锁车")
                return
            }
            if c.armed {
                self.log("· 断连查询：车已锁着，不重复下发锁车")
                return
            }
            let t = CarAPI.nowMs()
            guard Logic.allowFarLock(armedKnown: self.armedKnown, armed: self.armed,
                                     lockedThisVisit: self.lockedForThisVisit,
                                     now: t, lastLockAt: self.lastLockAt,
                                     cooldownMs: self.store.cfg.lockCooldownMs) else {
                self.log("· 断连查询：车未锁，但闸门拦住（本次已锁过 / 冷却中）→ 不重复")
                return
            }
            guard !self.acting else {
                self.log("· 断连查询：车未锁，但有一条指令还在飞 → 交给它")
                return
            }
            self.log("▶ 断连查询：车未锁 → 自动补一条锁车")
            self.requestAction(unlock: false, auto: true)
        }
    }

    /// 状态卡上那行「现在走的是哪条路」。
    ///
    /// 这一版省电有没有真生效，用户看一眼这里就有答案，不用去猜：
    /// 显示「蓝牙优先」时定位一定是停的，显示「定位兜底」时才有 GPS。
    private func updatePowerText() {
        let text: String
        if !running {
            text = ""
        } else if loc.running {
            text = "定位判距 · 蓝牙没信号，\(Int(Logic.farLockM(store.geoFarM))) 米外自动锁"
        } else {
            text = "蓝牙优先 · 已连车机，不取 GPS"
        }
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
        // 仅蓝牙模式：这是 UI 之外的第二道闸。按钮已经置灰，这里再挡一次，
        // 免得将来改界面时又把「一条网络指令都不发」破了。
        if store.chMode == Logic.MODE_BLE {
            log("· 仅蓝牙模式：网络指令已禁用（要发请先切到「智能」或「仅网络」）")
            lastResult = "仅蓝牙模式已禁用网络"
            return
        }
        log("▶ 网络\(unlock ? "开锁" : "锁车")")
        pendingUnlock = unlock
        pendingChannel = Logic.CH_NET
        pendingManual = true
        acting = true
        actionT0 = CarAPI.nowMs()
        netPendAt = 0
        netPendRounds = 0
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
        // 新的一条指令 = 新的确认周期：把上一笔的待确认和轮次一起清掉。
        // 不清的话，上一笔用剩的重发配额会被这一笔继承（甚至直接为负），
        // 结果就是「第一笔用完 4 轮之后，后面每一笔都不重发了」。
        netPendAt = 0
        netPendRounds = 0

        // 两条通道都够得着时并发下发 —— 这是「点了就开」和「点完站十秒」的区别
        if tryRace(unlock: unlock, auto: auto, manual: manual) {
            return
        }

        let cfg = store.cfg
        let rssiAge: Int64 = lastRssiAt > 0 ? CarAPI.nowMs() - lastRssiAt : -1
        // 1.26：通道由「指令通道模式」说了算。
        // 仅蓝牙 → 绝不偷偷走网络；仅网络 → 蓝牙只读状态，不下发。
        // 智能模式仍是老规矩：蓝牙够得着就走蓝牙，本地 0.2 秒完成。
        let mode = store.chMode
        let ch: Int = Logic.pickCh(mode,
                                   unlock: unlock,
                                   hasTarget: ble.hasSavedTarget,
                                   connected: ble.isConnected,
                                   rssiAgeMs: rssiAge,
                                   rssi: lastRssiValue,
                                   cfg)

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
        log("通道选择：\(Logic.channelName(ch)) · \(Logic.modeName(mode))模式（\(sigText)）")
        if ch == Logic.CH_NET && !signedIn {
            log("⚠︎ 当前未登录网络，网络通道可能被拒")
        }
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
        // 仅蓝牙 / 仅网络是明确的单通道选择，不参与竞速 —— 由 requestAction
        // 的单通道路径下发。否则「仅蓝牙」点一下，网络那条还是会偷偷发出去。
        guard Logic.modeAllowsRace(store.chMode) else { return false }
        // 自动触发一律走双通道：用户明确要求「靠近就蓝牙和网络一起发，谁先回算谁」。
        // 手动按钮仍尊重界面上的「双通道竞速」开关 —— 有人就是想省点流量。
        guard auto || store.raceOn, !raceActive, !ble.busy else { return false }
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
            beginUnlockWatch(now)
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
        // 9 秒后回查一次，确认车机真的锁上了。
        // 1.27：仅蓝牙模式跳过 —— 这一步是最容易被忽略的「偷偷联网」，
        // 锁车本身走本地蓝牙，用户以为一条请求都没发，其实这里补了一条。
        DispatchQueue.main.asyncAfter(deadline: .now() + 9) { [weak self] in
            guard let self = self else { return }
            guard self.store.chMode != Logic.MODE_BLE else {
                self.log("· 仅蓝牙模式：跳过锁车后的状态回查")
                return
            }
            self.refreshStatus()
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

    /// 连上即开（1.28）。关掉之后回到「RSSI 过门限才开」的老口径。
    func setConnectUnlock(_ on: Bool) {
        store.connectUnlock = on
        connectUnlockEnabled = on
        log(on
            ? "连上即开：已开启（蓝牙一建立连接就下发开锁，不再等信号）"
            : "连上即开：已关闭（回到 RSSI 门限判定，信号达标才开）")
    }

    /// 切换指令通道模式（1.26）。
    ///
    /// 改完立刻重判一次：用户在车边发现「纯蓝牙更稳」时切过去，应该下一秒就生效，
    /// 而不是等他走开再回来。切到「仅蓝牙」时顺便把正在跑的定位停掉 ——
    /// 定位的用途只有「网络兜底 / 走远锁车」，纯蓝牙模式下它只会白耗电。
    func setChMode(_ m: Int) {
        let v = (m == Logic.MODE_BLE || m == Logic.MODE_NET) ? m : Logic.MODE_SMART
        store.chMode = v
        chMode = v
        switch v {
        case Logic.MODE_BLE:
            log("指令通道：仅蓝牙（不再发送任何网络指令）")
            stopGeoForBle()
        case Logic.MODE_NET:
            log("指令通道：仅网络（蓝牙只读车锁与门位状态）")
        default:
            log("指令通道：智能（蓝牙优先，够不着转网络）")
        }
        if running { evaluate("通道模式切换") }
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
            beginUnlockWatch(now)
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
                // 只有蓝牙回执能当作"这次锁车在推进中"，网络那条要等状态帧，
                // 所以重试计数只在蓝牙路径上清
                autoLockFails = 0
                autoLockRetryAt = 0
            }
            Stats.lockResult(ok: true)
            Notify.shared.clearLockFailed()
            // 网络"已受理"不能拿来当"已锁车"报喜，通知要等状态帧确认后再发（见 checkVerify）
            if channel == Logic.CH_BLE, wasAutoLock, store.notifyEnabled {
                let d = notifyDistText()
                Notify.shared.autoLocked(distText: d)
                log("· 已发通知：已自动锁车" + (d.isEmpty ? "" : " · \(d)"))
            }
        }
        statsText = Stats.summary()
        // ── 网络通道不再「受理即成功」（1.22）──
        // 平台回 ok 只说明云平台收下了指令：车机离线、指令排队、门没关严被拒绝，
        // 都会走这条路，而状态帧纹丝不动。以前这里直接把 armed 改掉，
        // 界面就报「已锁车」，自动锁车也不再重判、重试链被清空 ——
        // 假锁车一直挂到下次连上蓝牙为止。现在只登记待确认，锁态由状态帧说了算。
        if channel == Logic.CH_NET {
            netPendAt = now
            netPendUnlock = unlock
            netPendAuto = wasAutoLock
            // `netPendRounds` 刻意不在这里清零：重发一条指令也会走到这里，
            // 清零的话轮次永远回到 0，"重发上限"就不存在了，会一直刷服务端。
            // 新指令的清零在 `requestAction` 开头。
            netUnconfirmed = false
            lastResult = "已发出，等车机确认"
            whyText = "已发出指令，等车机确认…"
            log("网络\(unlock ? "开锁" : "锁车")已受理 → 等状态帧确认（不预先改写锁态）")
            // 走网络时蓝牙通常已经断了，收不到状态帧，只能靠主动查。
            // 这里排一次"到点再看一眼"，否则没有任何事件会驱动 evaluate，
            // 重发那一轮根本不会被触发。
            DispatchQueue.main.asyncAfter(deadline: .now() + 21) { [weak self] in
                guard let self = self, self.netPendAt > 0 else { return }
                self.evaluate("等待车机确认")
            }
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

        // 网络通道的"受理"核实。必须是一次**在指令之后**到达的锁态，
        // 不能用"本来就等于期望值"蒙过去（比如对着一辆已锁的车再点一次锁车）。
        if netPendAt > 0 {
            let age = now - netPendAt
            let framed = lastArmedFrameAt > netPendAt
            if framed && armed == !netPendUnlock {
                let wasUnlock = netPendUnlock
                let wasAuto = netPendAuto
                netPendAt = 0
                netUnconfirmed = false
                log("✓ 车机已确认：\(wasUnlock ? "已解锁" : "已锁车")（状态帧翻转，耗时 \(age) ms）")
                if !wasUnlock {
                    autoLockFails = 0
                    autoLockRetryAt = 0
                    if wasAuto && store.notifyEnabled {
                        let d = notifyDistText()
                        Notify.shared.autoLocked(distText: d)
                        log("· 已发通知：已自动锁车" + (d.isEmpty ? "" : " · \(d)"))
                    }
                    whyText = "已锁车（车机已确认）"
                } else {
                    whyText = "已解锁（车机已确认）"
                }
            } else if age > Logic.VERIFY_WINDOW_MS {
                let wasUnlock = netPendUnlock
                // ── 还没翻转：继续重发，直到车机确认或到轮次上限（1.25）──
                //
                // 1.22 是「20 秒没等到 → 报未确认 → 45 秒后再试一次，最多 3 次」。
                // 实测这套节奏太急：地库里车机刚唤醒时第一条指令经常直接丢掉，
                // 「试两次就放弃」的结果是人走到车边打不开门，还以为是蓝牙坏了。
                // 现在改成每 20 秒一轮、最多 4 轮，一确认就停。
                if netPendRounds < Logic.VERIFY_MAX_ROUNDS {
                    netPendRounds += 1
                    netPendAt = now
                    log("↻ 车机还没确认\(wasUnlock ? "开锁" : "锁车") → 第 \(netPendRounds)/\(Logic.VERIFY_MAX_ROUNDS) 轮重发")
                    whyText = "重发\(wasUnlock ? "开锁" : "锁车")（第 \(netPendRounds) 轮）…"
                    if !dispatchFallback(unlock: wasUnlock) {
                        log("· 上一条指令还没结束，下一拍再重发")
                    }
                } else {
                    netPendAt = 0
                    netUnconfirmed = true
                    log("⚠ 已重发 \(Logic.VERIFY_MAX_ROUNDS) 轮，车机仍未确认\(wasUnlock ? "开锁" : "锁车")")
                    if !wasUnlock {
                        // 1.29：不再叠加「45 秒后再锁 3 次」。本次到访的锁车指令
                        // 已经发过 4 轮，车要么已经锁上（只是状态帧没回来），要么
                        // 链路确实不通 —— 再发既锁不上车，又刷通知、耗流量。
                        // 如实报「未确认」并通知用户手动核对，比闷头重发安全。
                        autoLockFails = 0
                        autoLockRetryAt = 0
                        if store.notifyEnabled {
                            // 返回值是「是否真的发出去」，这里不用，加 _ = 消掉编译警告
                            _ = Notify.shared.lockUnconfirmed(distText: notifyDistText())
                        }
                        whyText = "⚠ 锁车没能确认，请手动核对车锁"
                    } else {
                        whyText = "⚠ 开锁没能确认，车可能还锁着"
                    }
                }
            }
        }

        // 网络指令等确认期间，蓝牙通常已经断了，一帧状态都收不到 —— 只能主动查。
        // 8 秒一次：车机 3 秒一帧，云端查询来回 1~2 秒，再密就是白烧流量。
        // 用 lastPollAt 兜住，refreshStatus 内部再调回 checkVerify 也不会成环。
        //
        // 仅蓝牙模式跳过：核实要靠车机状态帧，用户要的就是一条网络请求都不发。
        if store.chMode != Logic.MODE_BLE, netPendAt > 0, now - lastPollAt > 8000 {
            lastPollAt = now
            refreshStatus()
        }
    }

    /// 核实失败时补一次网络指令。补发前把通道标记改成网络，
    /// 否则网络成功后 markDone 会以为还是蓝牙，又留下一个待核实标记。
    ///
    /// - Returns: 是否真的发出去了。false 表示此刻正有别的指令在跑，
    ///   调用方不要清掉待核实标记，下一拍再试。
    @discardableResult
    private func dispatchFallback(unlock: Bool) -> Bool {
        // 仅蓝牙模式：蓝牙失败就是失败，不许偷偷转网络。
        // 用户选这个模式要的就是「一条网络指令都不发」。
        if store.chMode == Logic.MODE_BLE {
            log("· 仅蓝牙模式：不转网络，这一笔放弃")
            return false
        }
        guard !acting else { return false }
        pendingUnlock = unlock
        pendingChannel = Logic.CH_NET
        lastActionUnlock = unlock
        acting = true
        netPerform(unlock: unlock)
        return true
    }

    // MARK: 开锁后 10 分钟守夜（1.32）

    /// 开锁成功时调一次。四个成功分支都要调，漏一个就会出现"开锁了但没人守"。
    private func beginUnlockWatch(_ now: Int64) {
        unlockWatchAt = now
        unlockDoorSeen = false
        unlockWatchDone = false
        guard unlockWatchTimer == nil else { return }
        let t = Timer.scheduledTimer(withTimeInterval: 20, repeats: true) { [weak self] _ in
            self?.unlockWatchTick()
        }
        t.tolerance = 5
        unlockWatchTimer = t
    }

    private func stopUnlockWatch() {
        unlockWatchTimer?.invalidate()
        unlockWatchTimer = nil
        unlockWatchAt = 0
        unlockWatchDone = false
        unlockDoorSeen = false
    }

    /// 门位一变就记一笔：开过门 = 人上车了，这次不用再守。
    private func noteDoorForUnlockWatch(_ open: Bool) {
        if open && unlockWatchAt > 0 { unlockDoorSeen = true }
    }

    private func unlockWatchTick() {
        guard unlockWatchAt > 0, !unlockWatchDone else { return }
        let now = CarAPI.nowMs()
        if unlockDoorSeen {
            unlockWatchDone = true
            stopUnlockWatch()
            return
        }
        guard now - unlockWatchAt >= 600_000 else { return }
        unlockWatchDone = true
        unlockWatchTimer?.invalidate()
        unlockWatchTimer = nil
        if ble.isConnected {
            // 用户明确要的边界：蓝牙还在 = 人可能就在车边，不回锁。
            log("· 开锁 10 分钟未开门，蓝牙还连着 → 不回锁")
            return
        }
        log("▶ 开锁 10 分钟未开门，蓝牙已断 → 按断开即锁规则处理")
        queryAfterLinkLost()
    }

    // MARK: 小电池电压（1.32）

    /// 低于 10.8V 推一条。只采信真实读数：空串 / 0 一律当没数据，不误报。
    private func checkBatteryLow(_ voltText: String) {
        guard store.notifyEnabled else { return }
        let v = Double(voltText.trimmingCharacters(in: .whitespaces)) ?? 0
        guard v > 1, v < 10.8 else { return }
        let now = CarAPI.nowMs()
        // 6 小时一条就够：停车时电压本来就低，反复弹只会让人关掉通知
        guard lastBatteryNotifyAt == 0 || now - lastBatteryNotifyAt > 6 * 3_600_000 else { return }
        lastBatteryNotifyAt = now
        log("⚠ 小电池电压 \(String(format: "%.1f", v))V 偏低，已发通知")
        Notify.shared.batteryLow(volt: v)
    }

    // MARK: 手动刷新 / 地点名称（1.32）

    /// 手动刷新。先叫车机现在报一次（303505），2.5 秒后再读 203100。
    ///
    /// 只读 203100 拿到的是平台缓存，可能停在几分钟前 —— 用户点了刷新却看到旧数据，
    /// 会以为车没动。所以先点名、后读值。303505 失败也不影响，照读缓存。
    func manualRefresh() {
        log("▶ 手动刷新车辆状态（先叫车机上报）")
        ensureSession { ok in
            guard ok else {
                self.log("⚠ 无有效会话，只读缓存")
                self.refreshStatus()
                return
            }
            DispatchQueue.global(qos: .userInitiated).async {
                _ = try? self.api.reportNow()
                DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) {
                    self.refreshStatus()
                }
            }
        }
    }

    /// 经纬度 → 地名（高德逆地理编码）。
    ///
    /// 三条约束：没有 key 不请求；同一点位 5 分钟内不重复请求；失败保持上一次的名字，
    /// 不要把界面清空 —— 用户看到"定位中"闪来闪去比看到一个稍旧的地名更烦。
    private func resolvePlace(_ c: CarAPI.Car) {
        // 1.33：key 从 Store 统一取 —— 用户没填过时返回内置 key，所以默认就能显示地名。
        let key = store.amapKey
        guard !key.isEmpty else { return }
        guard let lat = Double(c.lat), let lng = Double(c.lng), lat != 0, lng != 0 else { return }
        let now = CarAPI.nowMs()
        let moved = abs(lat - placeLat) > 0.005 || abs(lng - placeLng) > 0.005
        if placeAt > 0, now - placeAt < 300_000, !moved { return }
        placeAt = now
        placeLat = lat
        placeLng = lng
        // 1.36：车机给的是 GPS 原始坐标（WGS-84），高德 regeo 默认按 GCJ-02 理解
        // 传进去的东西。不换一次，问到的就是 500 米外那个路口的地名。
        // 上面 placeLat/placeLng 存的仍是原始值 —— 判「车有没有挪」要跟 c.lat 比。
        let p = MapGeo.display(lat: lat, lng: lng)
        let url = "https://restapi.amap.com/v3/geocode/regeo?key=\(key)"
            + "&location=\(String(format: "%.6f,%.6f", p.longitude, p.latitude))"
            + "&extensions=base&radius=200&output=json"
        guard let u = URL(string: url) else { return }
        URLSession.shared.dataTask(with: u) { [weak self] data, _, _ in
            // 注意 `try? x as? T` 会被解析成 `try? (x as? T)`，得到双层可选，
            // 必须先解 JSONSerialization 的结果再转字典，否则 obj 还是个可选、下标编译不过。
            guard let self = self, let data = data,
                  let any = try? JSONSerialization.jsonObject(with: data),
                  let obj = any as? [String: Any],
                  let re = obj["regeocode"] as? [String: Any] else { return }
            let addr = (re["formatted_address"] as? String) ?? ""
            guard !addr.isEmpty else { return }
            DispatchQueue.main.async {
                // 高德对无结果会给空数组，这里已经用 String 判过，不会再踩
                self.placeText = addr
            }
        }.resume()
    }

    /// 1.33：改了高德 key 之后清掉「同一点位 5 分钟内不重复请求」的缓存。
    ///
    /// 输入框是逐字符回调的，这里必须防抖 —— 直接每次刷新会变成敲 32 下打 32 条请求。
    /// 停手 1.5 秒才真正查一次，结果跟手，又不会把免费配额刷掉。
    func resetPlaceCache() {
        placeAt = 0
        placeLat = 0
        placeLng = 0
        placeReloadWork?.cancel()
        let w = DispatchWorkItem { [weak self] in
            self?.refreshStatus()
        }
        placeReloadWork = w
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5, execute: w)
    }

    // MARK: 状态刷新

    /// 带回调版（1.30）。断连后「查完再决定要不要锁车」必须拿到结果。
    ///
    /// 失败也回调 `nil` —— 不回调的话调用方会一直等，等于把补锁这件事静默吞掉。
    /// 不要另外写一个无参重载：带默认值的同名函数会让 `refreshStatus()` 产生歧义。
    func refreshStatus(_ done: ((CarAPI.Car?) -> Void)? = nil) {
        let epoch = sessionEpoch
        ensureSession { ok in
            guard ok, epoch == self.sessionEpoch else { done?(nil); return }
            DispatchQueue.global(qos: .userInitiated).async {
                let c = self.api.status()
                DispatchQueue.main.async {
                    guard epoch == self.sessionEpoch, let c = c else { done?(nil); return }
                    self.car = c
                    // 1.35：顺手落一个轨迹点。放这里而不是地图页里，是因为轨迹要在
                    // 「后台也是一直在查状态」的情况下才连贯 —— 地图页关掉也得记。
                    // 15 米内的重复点 TrackStore 自己会丢。
                    // 1.38：带上速度 —— 原版回放时每个点都显示 KM/H，
                    // 没有速度这一列，回放页那行数字就是空的。
                    TrackStore.shared.append(lat: Double(c.lat) ?? 0,
                                             lng: Double(c.lng) ?? 0,
                                             at: c.reportedAt > 0 ? c.reportedAt : c.fetchedAt,
                                             kph: Double(c.speedKph))
                    self.updateVehState(acc: c.acc, eng: c.eng, speedKph: c.speedKph)
                    self.checkBatteryLow(c.volt)
                    self.resolvePlace(c)
                    if c.reportedAt > 0 {
                        // 1.15 的修复搬过来：这里以前是直接 `armed = c.armed`，
                        // 绕过了「车辆自锁抑制」。蓝牙断着、只能靠网络查状态时，
                        // 熄火关门车自己上锁，人还在旁边，下一拍就会把车又解开。
                        self.applyArmed(c.armed)
                        // 网络状态是权威的，可直接用来核实蓝牙回执
                        self.checkVerify(now: CarAPI.nowMs())
                    }
                    done?(c)
                }
            }
        }
    }

    // MARK: 自动刷新（1.30）

    /// 打开自动刷新。只在前台有效 —— iOS 进后台后 Timer 必被挂起，
    /// 之前的版本用「回前台补一次」就是这个原因。
    private func startAutoRefresh() {
        autoRefreshEnabled = store.autoRefresh
        guard store.autoRefresh, autoRefreshTimer == nil else { return }
        let t = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
            self?.autoRefreshTick()
        }
        // 容差让系统把这次唤醒和别的活儿合并，别每 60 秒硬醒一次
        t.tolerance = 8
        autoRefreshTimer = t
    }

    private func stopAutoRefresh() {
        autoRefreshTimer?.invalidate()
        autoRefreshTimer = nil
    }

    /// 界面上的开关。
    func setAutoRefresh(_ on: Bool) {
        store.autoRefresh = on
        autoRefreshEnabled = on
        if on {
            startAutoRefresh()
            log("· 自动刷新已开启（蓝牙断着时每 5 分钟查一次；开了走远锁车则为 55 秒）")
            autoRefreshTick()
        } else {
            stopAutoRefresh()
            log("· 自动刷新已关闭")
        }
    }

    /// 定时器 60 秒一拍，但真正发不发由这里的闸门决定。
    ///
    /// 1.31 起频率分两档（用户主诉是省电，手动按钮兜底）：
    /// - 没开「走远锁车」→ 5 分钟一条，够看个大概，剩下的交给手动刷新；
    /// - 开了「走远锁车」→ 仍按 55 秒，因为 farLock 要靠**新鲜的车锁状态**
    ///   才敢判「该不该锁」；锁态一旧，实际没锁却记着已锁，车就敞在那儿了。
    ///
    /// 三条硬跳过缺一条，就会变成「偷偷联网、偷偷耗电」：
    /// 仅蓝牙模式、蓝牙正连着、正在执行指令。
    private func autoRefreshTick() {
        guard running, !isBackground else { return }
        if store.chMode == Logic.MODE_BLE { return }
        // 蓝牙连着就一次都不联网 —— 状态帧 + 回执已经够用
        if ble.isConnected { return }
        if acting { return }
        let now = CarAPI.nowMs()
        let gap: Int64 = store.geoOn ? 55_000 : 270_000
        if lastPollAt > 0 && now - lastPollAt < gap { return }
        lastPollAt = now
        log("· 自动刷新车辆状态")
        refreshStatus()
    }

    /// 把状态字折成「行驶中 / 已启动 / ACC 通电 / 熄火」。
    ///
    /// 蓝牙帧只带 acc/eng，车速只有网络才有，所以两边各贡献一半。
    private func updateVehState(acc: Bool, eng: Bool, speedKph: Int) {
        let txt = Logic.vehicleStateText(speedKph: speedKph, acc: acc, eng: eng)
        if txt != vehStateText { vehStateText = txt }
        if !vehStateShown { vehStateShown = true }
    }

    /// 当前是否真的在屏幕上。省电退避按它分档，不能写死。
    private var screenOn: Bool {
        return UIApplication.shared.applicationState == .active
    }

    /// App 回到前台。原来靠定时器轮询网络，现在没有定时器了，
    /// 改成「一进前台就补一次真实状态」——这也正是用户最需要看到最新状态的时候。
    func onForeground() {
        guard signedIn else { return }
        isBackground = false
        endBgTask()
        log("· 回到前台")
        // 人就在眼前，退避从头算：这一下很可能就能连上，没必要还压着 5 分钟
        reconnectFails = 0
        nextReconnectAt = 0
        // 每次回前台先刷一次小组件：用户很可能是在桌面上看了一眼小组件、
        // 觉得不对才点开 App 的，这时候界面上的数必须和桌面上的对齐。
        pushWidget(force: true)

        // 回前台不再无条件发请求。用户反复切进切出（看一眼、回条消息、再切回来）
        // 时，原来那版等于把网络轮询又加了回来 —— 见 Power.statusMinGapMs。
        let now = CarAPI.nowMs()
        let bleFresh = ble.lastSeenMs > 0 && (now - ble.lastSeenMs) < store.cfg.freshMs
        let gap = Power.statusMinGapMs(bleFresh: bleFresh)
        if store.chMode == Logic.MODE_BLE {
            log("· 仅蓝牙模式：跳过网络状态查询")
        } else if lastPollAt == 0 || now - lastPollAt >= gap {
            lastPollAt = now
            refreshStatus()
        } else {
            log("· 距上次查询 \(max(0, now - lastPollAt) / 1000)s（<\(gap / 1000)s），这次不查网络")
        }
        refreshStats()
        startAutoRefresh()
        if running {
            // 定位不再在这里拉起：1.25 起它完全由 decideAction 按「蓝牙有没有信号」决定，
            // 回前台先催一次连接 —— 连上了就一分钱定位电都不花。
            ble.ensureConnected()
            evaluate("回到前台")
        }
    }

    /// 进后台。只有「仅前台定位」这一档才真的停；
    /// 开了后台定位就必须让它继续跑，否则锁屏后判不了距离。
    func onBackground() {
        isBackground = true
        // Timer 进后台必被系统挂起，留着只会让人以为还在刷新
        stopAutoRefresh()

        // 后台第一件事：把这次连接请求交给系统。
        //
        // App 一旦被挂起，我们自己排的 asyncAfter / Timer 全都不跑 —— 只有已经交给
        // CoreBluetooth 的 **pending 连接** 会在后台替我们等车机重新广播。
        // 所以进后台时如果还没连上，必须补提交一次，否则断开之后就再也没人捞得回来。
        if running && !ble.isConnected {
            ble.ensureConnected()
            log("进后台：已提交一次后台连接请求")
        }

        // 争取几秒收尾时间：让上面那次 connect、日志落盘、小组件快照都真正写下去。
        // 少这一步，App 可能在被挂起前就把这次 connect 丢了。
        beginBgTask()

        if !store.locBg {
            loc.stop()
            geoActive = false
        }
    }

    /// 申请一小段后台执行时间做收尾，最多 5 秒主动归还。
    /// 不归还的话系统会一直记着这笔配额，反复进出后台容易被降权甚至直接杀掉。
    private func beginBgTask() {
        endBgTask()
        bgTask = UIApplication.shared.beginBackgroundTask(withName: "sxkc.bg.finish") { [weak self] in
            // 系统说「时间到了」，必须立刻还，否则会被强杀
            self?.endBgTask()
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(5)) { [weak self] in
            self?.endBgTask()
        }
    }

    private func endBgTask() {
        guard bgTask != .invalid else { return }
        UIApplication.shared.endBackgroundTask(bgTask)
        bgTask = .invalid
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
            rssiPrevRaw = -127
            rssiPrevDelta = 0
            rssiTrendUp = false
            ble.readRssi(force: true)
            evaluate("蓝牙已连接")
            // 1.28：连上就开，不等 RSSI、不等状态帧。
            unlockOnConnect()
        } else {
            rssi = -127
            rssiSmooth = -127
            rssiPrevRaw = -127
            rssiPrevDelta = 0
            rssiTrendUp = false
            // 断开了，还在等的那次「连上即开」作废
            connectUnlockToken += 1
            // 断连之后门位就没有来源了，界面如实退回「未知」，
            // 不让上一次的「全关」一直挂在那里骗人
            doorShown = false
            doorAlert = false
            doorText = "车门：状态未知"
            handleLinkLost()
            if running {
                let d = Power.reconnectDelayMs(fails: max(1, reconnectFails),
                                               screenOn: screenOn, background: isBackground)
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
        // 趋势用**原始值**判：两拍累计涨 2dB 以上才算走强（单拍 +1dB 是噪声）。
        // 平滑值在这里帮不上忙 —— 它正是那个慢 30 秒的东西。
        let delta = rssiPrevRaw > -120 ? r - rssiPrevRaw : 0
        rssiTrendUp = rssiPrevRaw > -120 && delta > 0 && (delta >= 2 || rssiPrevDelta > 0)
        rssiPrevDelta = delta
        rssiPrevRaw = r
        if rssiSmooth == -127 {
            rssiSmooth = r
        } else {
            rssiSmooth = (rssiSmooth * 3 + r) / 4
        }
        // 1.28：门槛判**原始值**，且把「差 4dB 但正在走强」也算进来。
        //
        // 原来卡平滑值 >= 门限，等于要求人在门口站半分钟等滤波收敛。
        // 现在只要这一拍读数到位、或趋势说明正在靠近，就立刻跑一次判定。
        guard running else { return }
        let thr = store.cfg.thr
        if armed, !st.unlockedThisVisit,
           r >= thr || (rssiTrendUp && r >= thr - Logic.TREND_SLACK_DB) {
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
        // 尾箱位（bit4）1.22 起不再采信，见 Frame.anyDoorOpen 的注释
        let trunk = false
        let now = CarAPI.nowMs()
        // 记一帧心跳：拿不到 RSSI 时，「15 秒内收到几帧」是唯一能反映距离的物理量
        frameTimes.append(now)
        if frameTimes.count > 40 { frameTimes.removeFirst(frameTimes.count - 40) }
        let wasFresh = doorKnown && (now - doorMs) < doorStaleMs
        let changed = !wasFresh || open != doorOpen || trunk != doorTrunk

        doorKnown = true
        doorOpen = open
        doorTrunk = trunk
        doorMs = now
        // 1.32：开过门就说明人上车了，开锁守夜可以收工
        noteDoorForUnlockWatch(open)
        // 拿到门位了，"锁车前等门位"这件事就不用再等
        doorWaitUntil = 0

        // 1.30：同一个状态字节里还有电源位（0x08 ACC / 0x10 启动）。
        // 两位全 0 时不采信 —— 那可能是固件没填，此时硬报「熄火」比不报更误导。
        if body.count > 5 && (body[5] & 0x18) != 0 {
            bleAcc = (body[5] & 0x08) != 0
            bleEng = (body[5] & 0x10) != 0
            updateVehState(acc: bleAcc, eng: bleEng, speedKph: car?.speedKph ?? 0)
        }

        guard changed else { return }
        doorText = "车门：" + (open ? "有门开着" : "全关")
        doorShown = true
        doorAlert = open
        log("· 门位 \(Hex.of(body)) → \(open ? "有车门开着" : "四门全关")")
        if !open {
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

    /// 此刻是否判定为「在车旁」。
    ///
    /// 1.25 起判据顺序反过来：**蓝牙优先**。这不是口味问题 —— 蓝牙连着的时候
    /// 定位是停掉的，`geoSt` 停在几小时前的旧值上，拿它判「近」会得出完全错误的结论。
    private func isNearNow() -> Bool {
        let now = CarAPI.nowMs()
        if ble.isConnected {
            let rssiFresh = lastRssiAt > 0 && (now - lastRssiAt) < Logic.RSSI_FRESH_MS
            return Logic.nearAssumeByLink(rssi: rssiSmooth, thr: store.cfg.thr,
                                          fresh: rssiFresh, frameCount: recentFrameCount(now))
        }
        let g = buildGeo(now, store.cfg, store.geoCfg)
        guard Geo.usable(g, store.geoCfg) else { return false }
        return !g.dist.isNaN && g.dist <= store.geoNearM && g.phoneAcc <= store.geoCfg.accNearM
    }

    /// 最近 15 秒收到几帧状态帧。
    ///
    /// 拿不到 RSSI 时（iOS 后台被限流），「连着」本身不能证明离得近——蓝牙穿墙也连着。
    /// 但丢包率能：在车边 3 秒一帧，15 秒该有 4~5 帧；隔一层楼板通常只剩 1~2 帧。
    private func recentFrameCount(_ now: Int64) -> Int {
        frameTimes.removeAll { now - $0 > Logic.FRAME_WINDOW_MS }
        return frameTimes.count
    }

    /// 改「车锁状态」的唯一入口。状态帧和网络查询都必须走这里，
    /// 否则两条路各改各的，自锁抑制就只在一半路径上生效——人站车旁车会被自己弹开。
    private func applyArmed(_ a: Bool) {
        let wasKnown = armedKnown
        let wasArmed = armed
        let prev = armedKnown ? armed : a
        armed = a
        armedKnown = true
        lastArmedFrameAt = CarAPI.nowMs()
        if Logic.suppressUnlockOnFlip(wasArmed: prev, nowArmed: a) {
            // 熄火下车关门，车辆自己上锁 → 绝不能下一拍又把它解开。
            // 1.22 起不再要求「此刻判近」：手机落在车里、蓝牙刚断过，都会让判近失败，
            // 而「车从没锁变已锁」本身就说明刚才有人在车边动过它。
            //
            // 1.26：记下翻转时刻。若人持续在车旁 20 秒（`Logic.decide` 里判），
            // 就解除抑制 —— 否则下车拿个东西就再也拉不开门，这是最常见的罚站现场。
            st.unlockedThisVisit = true
            st.flipAt = CarAPI.nowMs()
            geoSt.unlockedThisVisit = true
            log("车辆刚上锁（人还在车旁或手机落在车里）→ 20 秒内不自动开；持续在车旁会自动解除")
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
                if store.chMode == Logic.MODE_BLE {
                    log("✗ 蓝牙失败（\(msg)）· 仅蓝牙模式：不转网络，这一笔放弃")
                    lastResult = msg
                    if pendingUnlock { clearVisitOnUnlockFail() } else { noteLockFailed(msg) }
                } else if fallbackRound < 1 {
                    fallbackRound += 1
                    log("蓝牙失败（\(msg)），自动转网络")
                    pendingChannel = Logic.CH_NET
                    acting = true
                    netPerform(unlock: pendingUnlock)
                } else {
                    log("✗ 蓝牙失败（\(msg)），两条通道都试过了")
                    lastResult = msg
                    if pendingUnlock { clearVisitOnUnlockFail() } else { noteLockFailed(msg) }
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
    /// false 时置灰不可点。1.27：仅蓝牙模式下必须把网络按钮一起关掉，
    /// 否则「一条网络指令都不发」和底部这两个按钮自相矛盾。
    var enabled: Bool = true
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(title)
                .font(.system(size: 14, weight: .semibold))
                .foregroundColor(enabled ? color : UI.dim.opacity(0.45))
                .frame(maxWidth: .infinity)
                .padding(.vertical, 12)
                .background(
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .stroke(enabled ? color.opacity(0.55) : UI.line, lineWidth: 1.2)
                )
        }
        .disabled(!enabled)
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
//  SXKC/UI/AppLogo.swift  ——  内嵌的车辆 LOGO
// ==========================================================================

/// App 界面里的车辆 LOGO（导航栏、登录页、页脚都用它）。
///
/// 为什么内嵌 base64，而不是放进 Assets.xcassets：
/// App 图标（AppIcon）必须走 asset catalog，这是系统硬要求；但界面里这个
/// 小徽章不必。走内嵌可以少建一个 imageset 目录、少传 4 个文件，
/// 代价只有 16KB —— UIImage 是懒解码的，不绘制就不占内存。
///
/// 用多行字面量而不是 `"a" + "b" + ...`：两百多段相加会超过 Swift 类型检查的
/// 表达式复杂度上限，直接报 "expression was too complex"。
/// 换行交给 `ignoreUnknownCharacters` 去忽略。
///
/// 图案由 `资源/icon_gen.py` 从实拍车图生成（深色渐变圆角底 + 车模），
/// 想换车图就改那个脚本重新跑一遍。
enum AppLogo {

    /// 192×192 PNG（base64）
    private static let b64 = """
    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
    """

    static let image: UIImage? = {
        guard let d = Data(base64Encoded: b64, options: .ignoreUnknownCharacters) else {
            return nil
        }
        return UIImage(data: d)
    }()

    /// 圆角徽章。解码失败时画一个空位，不给用户一个「消失的图标」。
    @ViewBuilder
    static func view(_ size: CGFloat, radius: CGFloat? = nil) -> some View {
        if let img = image {
            Image(uiImage: img)
                .resizable()
                .frame(width: size, height: size)
                .clipShape(RoundedRectangle(cornerRadius: radius ?? size * 0.24,
                                            style: .continuous))
        } else {
            RoundedRectangle(cornerRadius: radius ?? size * 0.24, style: .continuous)
                .fill(Color.white.opacity(0.08))
                .frame(width: size, height: size)
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
    /// 1.33：高德 key 的隐藏入口。长按设置卡最底下的版本号才展开。
    @State private var showAmapKey = false
    /// 1.35：全屏地图页（照原版那个地图页做的，不再是卡片里的小图）
    @State private var showMapPage = false

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
        return "五菱控车  v\(v) (\(b)) · \(AutoEngine.buildTag)"
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

                    // 作者信息放最底下：不挡操作，但一眼能找到。
                    // 微信写成可点的，长按复制比手打十一位数字靠谱。
                    VStack(spacing: 4) {
                        HStack(spacing: 6) {
                            AppLogo.view(14, radius: 4)
                                .opacity(0.78)
                            Text("作者：胖胖胖")
                                .font(.system(size: 11))
                                .foregroundColor(UI.dim)
                        }
                        Text("微信：zhengyongfu")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(UI.dim.opacity(0.85))
                    }
                    .padding(.top, 2)
                }
                .padding(16)
                .padding(.bottom, 24)
            }
            .background(UI.bg.ignoresSafeArea())
            .navigationTitle("五菱控车")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                // 标题栏放 LOGO + 名称，和桌面图标对得上，用户不会怀疑装错 App
                ToolbarItem(placement: .principal) {
                    HStack(spacing: 7) {
                        AppLogo.view(22, radius: 6)
                        Text("五菱控车")
                            .font(.system(size: 17, weight: .semibold))
                            .foregroundColor(UI.text)
                    }
                }
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
        // 1.35：全屏地图页。用 fullScreenCover 不用 push —— 原版那个地图页是盖满
        // 整屏的，没有导航栏，上滑才是信息卡。
        .fullScreenCover(isPresented: $showMapPage) {
            MapPage(isPresented: $showMapPage)
                .environmentObject(e)
        }
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

    /// 1.33：手里有没有可用的车辆坐标。
    private var hasCoord: Bool {
        return carCoord != nil
    }

    /// 1.34：把坐标解出来一次，供地图与跳转共用
    private var carCoord: (lat: Double, lng: Double)? {
        guard let c = e.car, let lat = Double(c.lat), let lng = Double(c.lng),
              lat != 0, lng != 0 else { return nil }
        return (lat, lng)
    }

    /// 1.34：点地名展开内置地图。
    /// 1.35：改成打开**全屏地图页** —— 对照原版 App 的地图页，卡片里那块 200 高的小图
    /// 看车在哪个区还行，看周边路网就太小了。全屏页里才有围栏、轨迹、导航。
    private func toggleMap() {
        guard hasCoord else {
            e.log("⚠ 还没有车辆坐标，先点一次刷新")
            return
        }
        showMapPage = true
        e.log("▶ 打开地图页")
    }

    private var statusCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 14) {
                HStack(alignment: .firstTextBaseline) {
                    Text(armedText)
                        .font(.system(size: 26, weight: .bold))
                        .foregroundColor(armedColor)
                    Spacer()
                    // 1.30：把「车门」和「车辆状态」放到「已锁车」右边的空位上。
                    // 以前门位单独占一行，标题右侧一大片空白，扫一眼只能看到锁没锁。
                    HStack(spacing: 6) {
                        if e.vehStateShown {
                            stateBadge(e.vehStateText, color: vehStateColor)
                        }
                        stateBadge(doorBadgeText, color: doorColor)
                        if e.acting {
                            ProgressView()
                                .progressViewStyle(CircularProgressViewStyle(tint: UI.accent))
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

                // 1.32：车辆所在地名。没填高德 key、或还没解析出来时，整行不显示。
                // 1.33：整行可点 —— 直接跳到地图看车在哪。右侧给个小箭头，免得看不出来能点。
                // 1.34：不再跳外部 App，改成在下面展开 App 内置的地图。
                // 地名还没解析出来（没网 / 配额用完）时退成「查看车辆位置」，
                // 只要拿到过坐标就仍然能展开地图，不让这个入口依赖高德。
                if !e.placeText.isEmpty || hasCoord {
                    Button(action: { toggleMap() }) {
                        HStack(spacing: 6) {
                            Image(systemName: "mappin.and.ellipse")
                                .font(.system(size: 11))
                                .foregroundColor(e.placeText.isEmpty ? UI.dim : UI.accent)
                            Text(e.placeText.isEmpty ? "查看车辆位置" : e.placeText)
                                .font(.system(size: 12))
                                .foregroundColor(UI.dim)
                                .lineLimit(1)
                            Spacer(minLength: 0)
                            Image(systemName: "arrow.up.left.and.arrow.down.right")
                                .font(.system(size: 10, weight: .semibold))
                                .foregroundColor(UI.dim.opacity(0.7))
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(PlainButtonStyle())
                }

                // 1.35：这里原来挂的是 200 高的小地图，现在点地名直接进全屏地图页，
                // 小图不再在这里展开（CarMapView 留着，别处还能用）。

                // 门位已并到标题行右侧的徽标里（1.30），这里不再单独占一行

                // 「为什么现在不动手」。1.22 新增：以前这个理由只写进日志，
                // 用户想知道「刚才走近了为什么没开锁」必须去诊断页翻。
                if !e.whyText.isEmpty {
                    HStack(spacing: 7) {
                        // 与色点对齐，但不画点，避免和门位那一行抢注意力
                        Color.clear.frame(width: 7, height: 1)
                        Text(e.whyText)
                            .font(.system(size: 11))
                            .foregroundColor(e.whyText.hasPrefix("⚠") ? UI.warn : UI.dim)
                            .fixedSize(horizontal: false, vertical: true)
                        Spacer(minLength: 0)
                    }
                }

                // 1.31：手动刷新不再置灰。自动刷新已经降到 5 分钟，这个按钮就是
                // 用户想看最新状态时的唯一手段 —— 灰着不让人点，等于把兜底也拿走了。
                GhostButton(title: "刷新车辆状态",
                            color: UI.accent,
                            enabled: true) {
                    // 1.32：先叫车机上报（303505），2.5 秒后再读，不然看到的是缓存
                    e.manualRefresh()
                }
            }
        }
    }

    /// 门位颜色：没数据灰、有门开着橙、全关绿
    private var doorColor: Color {
        if !e.doorShown { return UI.dim }
        return e.doorAlert ? UI.warn : UI.ok
    }

    /// 标题行右侧的车门徽标。写成「车门 全关」而不是整句，是为了和车辆状态并排不折行。
    private var doorBadgeText: String {
        if !e.doorShown { return "车门 —" }
        return e.doorAlert ? "车门 开着" : "车门 全关"
    }

    /// 车辆状态徽标颜色：熄火灰、ACC 橙、启动与行驶绿
    private var vehStateColor: Color {
        guard e.vehStateShown else { return UI.dim }
        switch e.vehStateText {
        case "行驶中", "已启动": return UI.ok
        case "ACC 通电":        return UI.warn
        default:                return UI.dim
        }
    }

    private func stateBadge(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.system(size: 11, weight: .medium))
            .foregroundColor(color)
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .overlay(
                RoundedRectangle(cornerRadius: 6)
                    .stroke(color.opacity(0.45), lineWidth: 0.8)
            )
            .fixedSize()
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
                BigButton(title: "开锁", subtitle: Logic.modeName(e.chMode), color: UI.accent) {
                    e.manual(unlock: true)
                }
                BigButton(title: "锁车", subtitle: Logic.modeName(e.chMode), color: UI.warn) {
                    e.manual(unlock: false)
                }
            }
            // 1.27：仅蓝牙模式下这四个按钮一起置灰。
            // 它们全是纯网络指令，留着可点就等于「纯蓝牙」名不副实。
            HStack(spacing: 10) {
                GhostButton(title: "网络开锁", color: UI.accent,
                            enabled: e.chMode != Logic.MODE_BLE) {
                    e.netOnly(unlock: true)
                }
                GhostButton(title: "网络锁车", color: UI.warn,
                            enabled: e.chMode != Logic.MODE_BLE) {
                    e.netOnly(unlock: false)
                }
            }
            HStack(spacing: 10) {
                GhostButton(title: "一键启动", color: UI.ok,
                            enabled: e.chMode != Logic.MODE_BLE) {
                    engineStart = true
                    showEngine = true
                }
                GhostButton(title: "熄火", color: UI.dim,
                            enabled: e.chMode != Logic.MODE_BLE) {
                    engineStart = false
                    showEngine = true
                }
            }
            Text("通道按上面「指令通道」的设置走：智能＝蓝牙优先、够不着转网络；"
                + "仅蓝牙＝不发任何网络指令（这四个网络按钮会变灰）；仅网络＝全走云端。")
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
                        Text("走远自动锁车")
                            .font(.system(size: 15, weight: .semibold))
                            .foregroundColor(UI.text)
                        Text("定位只用来判「该不该锁车」：蓝牙没信号、且距离超过 \(Int(Logic.farLockM(Store.shared.geoFarM))) 米才锁。1.28 起定位不再参与开锁 —— 开锁全交给蓝牙。")
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
                        Text("蓝牙优先：连上车机就判开锁、不取 GPS；断开后离车 \(Int(Logic.farLockM(Store.shared.geoFarM))) 米以上才锁车")
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

                toggleRow("自动刷新车辆状态",
                          "蓝牙断着时每 5 分钟查一次；蓝牙连着靠状态帧刷新，一次都不联网",
                          isOn: Binding(get: { e.autoRefreshEnabled },
                                        set: { e.setAutoRefresh($0) }))

                // 1.33：高德 key 改成内置 + 隐藏入口。
                // 内置 key 已经能显示地名，日常不需要看见这一行；长按最底下的版本号才展开。
                // 展开后填了就以填的为准，清空就退回内置值。
                if showAmapKey {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 8) {
                            Text("高德 Key")
                                .font(.system(size: 14, weight: .medium))
                                .foregroundColor(UI.text)
                            Spacer(minLength: 8)
                            Text(Store.shared.amapKeyIsBuiltin ? "内置" : "已自定义")
                                .font(.system(size: 11))
                                .foregroundColor(Store.shared.amapKeyIsBuiltin ? UI.dim : UI.ok)
                        }
                        TextField("留空使用内置 key", text: Binding(
                            get: { Store.shared.str(StoreKey.amapKey) },
                            set: {
                                Store.shared.put(StoreKey.amapKey, $0)
                                e.resetPlaceCache()
                            }))
                            .font(.system(size: 12))
                            .multilineTextAlignment(.trailing)
                            .foregroundColor(UI.dim)
                            // iOS 14 兼容：不能用 textInputAutocapitalization（15+）
                            .autocapitalization(.none)
                            .disableAutocorrection(true)
                        Text("只用于「经纬度 → 地名」，不上传任何车辆信息。清空这一栏就恢复内置 key。")
                            .font(.system(size: 11))
                            .foregroundColor(UI.dim)
                            .fixedSize(horizontal: false, vertical: true)

                        Divider()
                            .background(UI.line)
                            .padding(.vertical, 2)

                        // 1.36：万一某台车机给的本来就不是 WGS-84，校正后反而偏，
                        // 这里能立刻关掉，不用等新版。默认开。
                        Toggle(isOn: Binding(
                            get: { Store.shared.flag(StoreKey.coordFix, true) },
                            set: {
                                Store.shared.putFlag(StoreKey.coordFix, $0)
                                e.resetPlaceCache()
                                e.log($0 ? "▶ 坐标校正：开（WGS-84 → GCJ-02）"
                                         : "· 坐标校正：关（按原样显示）")
                            })) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("坐标校正")
                                    .font(.system(size: 14, weight: .medium))
                                    .foregroundColor(UI.text)
                                Text("车机给的是 GPS 原始坐标，地图要火星坐标。正常情况保持开启。")
                                    .font(.system(size: 11))
                                    .foregroundColor(UI.dim)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                        .toggleStyle(SwitchToggleStyle(tint: UI.ok))
                    }
                }

                // 指令通道（1.26）：用户要的「纯蓝牙 / 自由选择 / 一起共用」。
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("指令通道")
                            .font(.system(size: 14, weight: .medium))
                            .foregroundColor(UI.text)
                        Spacer()
                        Text(Logic.modeName(e.chMode))
                            .font(.system(size: 11))
                            .foregroundColor(UI.accent)
                    }

                    Picker("", selection: Binding(
                        get: { e.chMode },
                        set: { e.setChMode($0) }
                    )) {
                        Text("智能").tag(Logic.MODE_SMART)
                        Text("仅蓝牙").tag(Logic.MODE_BLE)
                        Text("仅网络").tag(Logic.MODE_NET)
                    }
                    .pickerStyle(SegmentedPickerStyle())

                    Text(modeHint(e.chMode))
                        .font(.system(size: 10))
                        .foregroundColor(UI.dim)
                        .fixedSize(horizontal: false, vertical: true)
                }

                toggleRow("连上即开",
                          "蓝牙一连上车机就下发开锁，不等信号强度、不等车机状态帧。治罚站最有效，"
                          + "代价是蓝牙能穿墙：车在楼下、人在楼上，链路重连过一次也会开。"
                          + "另有止损：连上后第一个读数弱于 -85dBm 就不开。",
                          isOn: Binding(get: { e.connectUnlockEnabled }, set: { e.setConnectUnlock($0) }))

                if e.chMode == Logic.MODE_SMART {
                    toggleRow("双通道竞速",
                              "开锁 / 锁车时蓝牙与网络同时下发，谁先回执算谁。两条都是幂等指令，不会多锁一次。",
                              isOn: Binding(get: { e.raceEnabled }, set: { e.setRace($0) }))
                }

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

    /// 通道模式的说明。三句话分别回答：为什么这样选、代价是什么。
    private func modeHint(_ m: Int) -> String {
        switch m {
        case Logic.MODE_BLE:
            return "一条网络指令都不发：最省流量，也不受云端抖动影响。代价是蓝牙连不上时这一笔就放弃，"
                + "走远锁车退回「断开够久」。"
        case Logic.MODE_NET:
            return "指令全走云端，人在车外也能用，但通常要 3~10 秒。蓝牙仍然连着 —— "
                + "车锁和门位只能从车机状态帧读，断了就没有判定依据。"
        default:
            return "蓝牙优先：够得着就本地下发（0.2 秒），够不着自动转网络；两条都够时并发，谁先回算谁。"
        }
    }

    private func toggleRow(_ title: String, _ hint: String, isOn: Binding<Bool>) -> some View {        HStack(alignment: .center) {
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

                SliderRow(title: "靠近门限（当前不参与开锁）",
                          unit: " 米",
                          value: $geoNear,
                          range: 5 ... 30,
                          step: 1,
                          hint: "1.28 起定位不再参与开锁判定，这一项留着只是给旧逻辑备用。现在开锁只看蓝牙：要么「连上即开」，要么信号到门限。")

                SliderRow(title: "开锁信号门限",
                          unit: " dBm",
                          value: $thr,
                          range: -95 ... -45,
                          step: 1,
                          hint: "主要判据。连着车机、信号强于此值就算「在车旁」，直接开锁。这个值比定位准得多：贴车约 -55~-70，隔一堵墙就掉到 -85 以下。")

                VStack(alignment: .leading, spacing: 6) {
                    Text("离开判定：蓝牙断联 + 定位 \(Int(Logic.farLockM(Store.shared.geoFarM))) 米外")
                        .font(.system(size: 14, weight: .medium))
                        .foregroundColor(UI.text)
                    Text("两个条件同时成立才锁车。刚断开时人往往就在车边（下车、开后备箱、进便利店），"
                        + "这时锁上等于把车锁在车主手里。只有真的走出这个距离才落锁。"
                        + "没给定位授权的话，退回「断联 30 秒」兜底。")
                        .font(.system(size: 11))
                        .foregroundColor(UI.dim)
                        .fixedSize(horizontal: false, vertical: true)
                }

                SliderRow(title: "蓝牙锁车最远信号",
                          unit: " dBm",
                          value: $bleThr,
                          range: -95 ... -70,
                          step: 1,
                          hint: "信号弱于此值就算「蓝牙已经没了」，转由定位判距离。低于 -90 基本等于穿墙后的残留链路，不能当成人在车边。")

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
                    // 1.33：隐藏入口。长按 1.2 秒展开 / 收起「高德 Key」。
                    // 平时不显示，避免设置页被一串 32 位字符占着。
                    .onLongPressGesture(minimumDuration: 1.2) {
                        withAnimation { showAmapKey.toggle() }
                        if !showAmapKey { UIApplication.shared.sendAction(
                            #selector(UIResponder.resignFirstResponder),
                            to: nil, from: nil, for: nil) }
                    }
                    .contentShape(Rectangle())
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

// MARK: - 内置地图（1.34）

/// App 内嵌的地图，用系统的 MapKit —— 不跳任何外部 App，也不需要额外 key。
///
/// 为什么不上高德 SDK：那要另申请「iOS 平台 Key」并绑定 bundle id，还要把
/// 几十兆的 framework 塞进无签名构建。系统地图在中国大陆用的本来就是高德
/// 数据，但坐标系是 GCJ-02，而车机给的是 GPS 原始坐标（WGS-84）——
/// **必须先用 MapGeo 换算一次**，否则图钉会偏五六百米（1.36 才修的就是这个）。
struct CarMapView: UIViewRepresentable {

    let lat: Double
    let lng: Double
    let title: String

    final class Coord {
        var lastLat = 0.0
        var lastLng = 0.0
    }

    func makeCoordinator() -> Coord {
        return Coord()
    }

    func makeUIView(context: Context) -> MKMapView {
        let mv = MKMapView()
        mv.isZoomEnabled = true
        mv.isScrollEnabled = true
        mv.isRotateEnabled = false
        mv.isPitchEnabled = false
        mv.showsCompass = false
        mv.showsUserLocation = false
        // 只留路网与地名，去掉商铺图标：这块只有 200 高，信息越少越好认
        mv.pointOfInterestFilter = .excludingAll
        return mv
    }

    func updateUIView(_ mv: MKMapView, context: Context) {
        let moved = abs(lat - context.coordinator.lastLat) > 0.0001
            || abs(lng - context.coordinator.lastLng) > 0.0001
        // 车没动就不碰视野：用户刚把地图拖开看周边，下一次状态刷新不能把他拽回原点
        guard moved || mv.annotations.isEmpty else { return }
        context.coordinator.lastLat = lat
        context.coordinator.lastLng = lng
        // 传进来的是车机原始坐标（WGS-84），落地图前换一次，见 MapGeo.swift
        let p = MapGeo.display(lat: lat, lng: lng)
        let c = CLLocationCoordinate2D(latitude: p.latitude, longitude: p.longitude)
        if let a = mv.annotations.first as? MKPointAnnotation {
            a.coordinate = c
            a.title = title
        } else {
            let a = MKPointAnnotation()
            a.coordinate = c
            a.title = title
            mv.addAnnotation(a)
        }
        if moved || mv.region.span.latitudeDelta == 0 {
            mv.setRegion(MKCoordinateRegion(center: c,
                                            latitudinalMeters: 500,
                                            longitudinalMeters: 500),
                         animated: false)
        }
    }
}


// ==========================================================================
//  SXKC/UI/MapPage.swift  ——  全屏地图页（实时追踪/围栏/轨迹/导航入口）
// ==========================================================================

//
//  MapPage.swift
//  1.39：地图页五个功能按原版重做（三个整屏页在 MapPanels.swift）
//
//  —— 以下是拆包得到的原版实现，不是猜的 ——
//
//  · 实时追踪 = TrackFlowController（iOS 二进制里同样有 TrackFlowController /
//    TrackFlowControllerFactory / showTrackFlow）。做法是**定时器循环**：
//    安卓版每轮 60 秒（const-wide/32 #0xEA60），先发 303598 叫车机定位，
//    等 1.9 秒（const-wide/16 #0x76C）再发 203100 读状态；地图跟着车走，
//    同时用手机 GPS 算「我离车多远」，字段名 lloc.pcdis。
//  · 电子围栏 = GeoFenceController + GeoFenceCellItem。**是一个列表**：
//    多个围栏，各有名字 / 圆心 / 半径；半径用 slider 调（默认 500，上限 5000，
//    步长由配置 101321 下发）；圆心可以放在车上或手机上（oncar / onphone）；
//    字段 geo.geoname / geo.radius / geo.circle.lat / geo.circle.lng /
//    geo.gis_id / geo.path / geo.type；显示开关 101323。
//    1.39 按原版截图补了编辑页的两个报警开关：入围栏报警 / 出围栏报警。
//  · 历史轨迹 = HistoryListView（按天列表）+ HistoryController（回放）：
//    先列出**每一天**一条（日期、里程 miles、平均速度 avgspd、最高速度 maxspd、
//    起止时间），点某天进回放页：进度条 slider + 前进 forward / 后退 backward +
//    播放 his.start / 停止 his.stop，每个点显示速度（KM/H），还能切卫星图和路况。
//  · 导航到车 = ActionMapNavi：探测装了哪个地图——高德 com.autonavi.minimap、
//    百度 com.baidu.BaiduMap、腾讯 com.tencent.map，用 URI 直接唤起并进驾车路线；
//    一个都没装就开网页版。目的地取 lloc.lat / lloc.lng。
//  · 车辆设置 = GPS 功能设置页（原版截图就三行）：GPS 开关 / 电子围栏 /
//    隐私模式 + 查询 / 保存。有三个字段能对上：config.devcfg.privacy、
//    parseVstStatus 里读的 gps_opn / gps_cls / gps_loc。**但写入走哪条指令码
//    没有实证**（iOS 主二进制是 FairPlay 加密的，字符串读不出来），所以这一版
//    开关只记在本机，保存时会如实告诉用户，不硬发一条可能改坏车机参数的指令。
//
//  坐标：车机给 WGS-84，大陆 MapKit 要 GCJ-02，画之前统一过 MapGeo.display()。
//  原版二进制里带着同一套转换常量（6378245.0 / -0.006693421622965943），
//  说明它也是这么处理的。
//


// MARK: - 轨迹仓库

/// 本机轨迹。原版的轨迹是车机上报到服务器、App 再按天拉回来的
/// （HistoryListView 的 dayqry / tripqry，page_size 31）；我们这边拿不到
/// 那条接口的明文参数，先用本机记录顶上 —— 结构照原版：按天存、按天汇总。
final class TrackStore {

    /// 一个轨迹点。原版每个点带速度（回放时显示 KM/H）和时间（hisfmt）。
    struct Pt {
        var lat: Double
        var lng: Double
        var ts: Int64      // 毫秒
        var kph: Double
    }

    /// 一天的小结。对应原版列表里的一行：日期 / 里程 / 平均速度 / 最高速度。
    struct Day {
        var key: String        // yyyyMMdd
        var date: Date
        var count: Int
        var km: Double
        var avgKph: Double
        var maxKph: Double
        var startAt: Int64
        var endAt: Int64
    }

    static let shared = TrackStore()

    private let dir: URL
    private let dayFmt: DateFormatter

    private init() {
        let base = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        dir = base.appendingPathComponent("tracks", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir,
                                                 withIntermediateDirectories: true,
                                                 attributes: nil)
        dayFmt = DateFormatter()
        dayFmt.dateFormat = "yyyyMMdd"
        dayFmt.locale = Locale(identifier: "en_US_POSIX")
        dayFmt.timeZone = TimeZone.current
    }

    private func fileURL(_ day: String) -> URL {
        return dir.appendingPathComponent("t_" + day + ".json")
    }

    private func dayOf(_ ms: Int64) -> String {
        let sec = ms > 100_000_000_000 ? ms / 1000 : ms
        return dayFmt.string(from: Date(timeIntervalSince1970: TimeInterval(sec)))
    }

    /// 读一天的点。兼容老格式（只有 [lat,lng] 两列）。
    private func loadPts(_ url: URL) -> [Pt] {
        guard let data = try? Data(contentsOf: url),
              let any = try? JSONSerialization.jsonObject(with: data, options: []),
              let arr = any as? [[Any]] else {
            return []
        }
        var out: [Pt] = []
        for r in arr {
            guard r.count >= 2,
                  let a = r[0] as? Double, let b = r[1] as? Double else { continue }
            var t: Int64 = 0
            var v: Double = 0
            if r.count >= 3, let x = r[2] as? Double { t = Int64(x) }
            if r.count >= 4, let x = r[3] as? Double { v = x }
            out.append(Pt(lat: a, lng: b, ts: t, kph: v))
        }
        return out
    }

    private func savePts(_ pts: [Pt], to url: URL) {
        var rows: [[Double]] = []
        rows.reserveCapacity(pts.count)
        for p in pts {
            rows.append([p.lat, p.lng, Double(p.ts), p.kph])
        }
        if let data = try? JSONSerialization.data(withJSONObject: rows, options: []) {
            try? data.write(to: url, options: .atomic)
        }
    }

    /// 记一个点。15 米内、且不到 30 秒，直接丢掉 —— 停车时点不会无限涨。
    func append(lat: Double, lng: Double, at ms: Int64, kph: Double) {
        guard lat.isFinite, lng.isFinite, lat != 0, lng != 0 else { return }
        let t = ms > 100_000_000_000 ? ms : ms * 1000
        let url = fileURL(dayOf(t))
        var pts = loadPts(url)
        if let last = pts.last {
            let d = CLLocation(latitude: last.lat, longitude: last.lng)
                .distance(from: CLLocation(latitude: lat, longitude: lng))
            if d < 15 || t - last.ts < 30_000 { return }
        }
        pts.append(Pt(lat: lat, lng: lng, ts: t, kph: max(0, kph)))
        savePts(pts, to: url)
    }

    /// 一天的原始点（WGS-84，未换算）。
    func points(day key: String) -> [Pt] {
        return loadPts(fileURL(key))
    }

    /// 最近几天的点，按时间正序（昨天 → 今天），已换成地图坐标。
    func points(daysBack: Int = 1,
                now: Int64 = Int64(Date().timeIntervalSince1970)) -> [CLLocationCoordinate2D] {
        var out: [CLLocationCoordinate2D] = []
        let span = max(0, daysBack)
        for i in stride(from: span, through: 0, by: -1) {
            let d = Date(timeIntervalSince1970: TimeInterval(now - Int64(i) * 86400))
            let day = dayFmt.string(from: d)
            for p in loadPts(fileURL(day)) {
                out.append(MapGeo.display(lat: p.lat, lng: p.lng))
            }
        }
        if out.count > 2000 { return Array(out.suffix(2000)) }
        return out
    }

    /// 按天汇总，日期新的在前。原版列表一次给 31 天。
    func days() -> [Day] {
        let fm = FileManager.default
        guard let list = try? fm.contentsOfDirectory(at: dir,
                                                     includingPropertiesForKeys: nil) else {
            return []
        }
        var out: [Day] = []
        for u in list {
            guard u.lastPathComponent.hasPrefix("t_"), u.pathExtension == "json" else { continue }
            let key = u.deletingPathExtension().lastPathComponent
                .replacingOccurrences(of: "t_", with: "")
            let pts = loadPts(u)
            if pts.isEmpty { continue }

            var km = 0.0
            var maxV = 0.0
            var sumV = 0.0
            var nV = 0
            if pts.count >= 2 {
                for i in 1..<pts.count {
                    let a = CLLocation(latitude: pts[i - 1].lat, longitude: pts[i - 1].lng)
                    let b = CLLocation(latitude: pts[i].lat, longitude: pts[i].lng)
                    km += a.distance(from: b)
                }
            }
            for p in pts {
                if p.kph > maxV { maxV = p.kph }
                if p.kph > 0 { sumV += p.kph; nV += 1 }
            }
            km = km / 1000.0

            let s = pts.first?.ts ?? 0
            let e = pts.last?.ts ?? 0
            var avg = 0.0
            if e > s {
                avg = km / (Double(e - s) / 3_600_000.0)
            } else if nV > 0 {
                avg = sumV / Double(nV)
            }

            out.append(Day(key: key,
                           date: dayFmt.date(from: key) ?? Date(),
                           count: pts.count,
                           km: km,
                           avgKph: avg,
                           maxKph: maxV,
                           startAt: s,
                           endAt: e))
        }
        out.sort { $0.key > $1.key }
        if out.count > 31 { return Array(out.prefix(31)) }
        return out
    }

    /// 清空本机轨迹（只删手机里的 JSON，车机与服务端不受影响）。
    func clear() {
        let fm = FileManager.default
        if let list = try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil) {
            for u in list where u.pathExtension == "json" {
                try? fm.removeItem(at: u)
            }
        }
    }

    func countToday(now: Int64 = Int64(Date().timeIntervalSince1970)) -> Int {
        return loadPts(fileURL(dayFmt.string(from: Date(timeIntervalSince1970: TimeInterval(now))))).count
    }
}

// MARK: - 围栏仓库

/// 电子围栏。原版存服务端（geo.gis_id / geo.path / geo.type，增 geo.301502、
/// 删 geo.301503，条目里 gis_uuid 是唯一号）；这里没有那条写入接口，
/// 先存本机，结构照原版：多个、有名字、有半径、有显示开关。
final class FenceStore {

    struct Fence: Codable, Identifiable {
        var id: String
        var name: String
        var lat: Double        // WGS-84 原始坐标，画的时候再换算
        var lng: Double
        var radius: Double     // 米
        var on: Bool           // 是否参与越界判定
        var inAlert: Bool      // 入围栏报警（原版编辑页第一个开关，默认关）
        var outAlert: Bool     // 出围栏报警（原版编辑页第二个开关，默认开）

        init(id: String, name: String, lat: Double, lng: Double,
             radius: Double, on: Bool,
             inAlert: Bool = false, outAlert: Bool = true) {
            self.id = id
            self.name = name
            self.lat = lat
            self.lng = lng
            self.radius = radius
            self.on = on
            self.inAlert = inAlert
            self.outAlert = outAlert
        }

        enum CodingKeys: String, CodingKey {
            case id, name, lat, lng, radius, on, inAlert, outAlert
        }

        /// 1.39 才加 inAlert / outAlert。1.38 存下来的 fences.json 里没有这两个键，
        /// 直接合成解码会整条失败、老围栏全丢，所以这里逐键 decodeIfPresent。
        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            id = (try? c.decode(String.self, forKey: .id)) ?? UUID().uuidString
            name = (try? c.decode(String.self, forKey: .name)) ?? "围栏"
            lat = (try? c.decode(Double.self, forKey: .lat)) ?? 0
            lng = (try? c.decode(Double.self, forKey: .lng)) ?? 0
            radius = (try? c.decode(Double.self, forKey: .radius)) ?? 500
            on = (try? c.decode(Bool.self, forKey: .on)) ?? true
            inAlert = (try? c.decode(Bool.self, forKey: .inAlert)) ?? false
            outAlert = (try? c.decode(Bool.self, forKey: .outAlert)) ?? true
        }
    }

    static let shared = FenceStore()

    private let url: URL
    private(set) var list: [Fence] = []

    private init() {
        let base = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        url = base.appendingPathComponent("fences.json")
        reload()
    }

    func reload() {
        guard let data = try? Data(contentsOf: url),
              let arr = try? JSONDecoder().decode([Fence].self, from: data) else {
            list = []
            return
        }
        list = arr
    }

    private func flush() {
        if let data = try? JSONEncoder().encode(list) {
            try? data.write(to: url, options: .atomic)
        }
    }

    /// 新增或更新。id 相同就替换。
    func save(_ f: Fence) {
        if let i = list.firstIndex(where: { $0.id == f.id }) {
            list[i] = f
        } else {
            list.append(f)
        }
        flush()
    }

    func remove(id: String) {
        list.removeAll { $0.id == id }
        flush()
    }

    func setOn(id: String, _ v: Bool) {
        if let i = list.firstIndex(where: { $0.id == id }) {
            list[i].on = v
            flush()
        }
    }

    /// 自动起名，对应原版 lang.map.geofence.gen_name（"围栏 N"）。
    func nextName() -> String {
        var n = list.count + 1
        var name = "围栏 " + String(n)
        while list.contains(where: { $0.name == name }) {
            n += 1
            name = "围栏 " + String(n)
        }
        return name
    }

    func makeNew(at lat: Double, lng: Double) -> Fence {
        return Fence(id: UUID().uuidString,
                     name: nextName(),
                     lat: lat, lng: lng,
                     radius: 500,
                     on: true)
    }
}

// MARK: - 车标

/// 地图上的车标。coordinate 必须 @objc dynamic，MKAnnotationView 才会跟着 KVO 移动。
final class CarPoint: NSObject, MKAnnotation {
    @objc dynamic var coordinate: CLLocationCoordinate2D
    var title: String?

    init(_ c: CLLocationCoordinate2D, _ t: String) {
        coordinate = c
        title = t
        super.init()
    }
}

/// 绿色圆角方块 + 白色车图标，下面挂一条半透明名字标签 —— 和原版那个样式一致。
final class CarPinView: MKAnnotationView {

    override init(annotation: MKAnnotation?, reuseIdentifier: String?) {
        super.init(annotation: annotation, reuseIdentifier: reuseIdentifier)
        isEnabled = false
        canShowCallout = false
        backgroundColor = .clear
        centerOffset = CGPoint(x: 0, y: 14)
        if let p = annotation as? CarPoint {
            image = CarPinView.makeImage(p.title ?? "")
        }
    }

    required init?(coder aDecoder: NSCoder) {
        // 形参名是 aDecoder，不能写 a —— 写成 a 编译器会报 "cannot find 'a' in scope"
        super.init(coder: aDecoder)
        isEnabled = false
        backgroundColor = .clear
        centerOffset = CGPoint(x: 0, y: 14)
    }

    func setName(_ s: String) {
        image = CarPinView.makeImage(s)
    }

    static func makeImage(_ name: String) -> UIImage {
        let w: CGFloat = 180
        let h: CGFloat = 64
        let renderer = UIGraphicsImageRenderer(size: CGSize(width: w, height: h))
        return renderer.image { _ in
            let green = UIColor(red: 0.10, green: 0.66, blue: 0.34, alpha: 1.0)

            let box = CGRect(x: w / 2 - 17, y: 2, width: 34, height: 34)
            let path = UIBezierPath(roundedRect: box, cornerRadius: 10)
            green.setFill()
            path.fill()
            UIColor.white.setStroke()
            path.lineWidth = 2
            path.stroke()

            if let icon = UIImage(systemName: "car.fill")?
                .withTintColor(.white, renderingMode: .alwaysOriginal) {
                icon.draw(in: CGRect(x: w / 2 - 11, y: 8, width: 22, height: 22))
            }

            let para = NSMutableParagraphStyle()
            para.alignment = .center
            let attrs: [NSAttributedString.Key: Any] = [
                .font: UIFont.systemFont(ofSize: 12, weight: .semibold),
                .foregroundColor: UIColor.white,
                .paragraphStyle: para
            ]
            let text = (name.isEmpty ? "我的车" : name) as NSString
            let tw = text.size(withAttributes: attrs).width
            let bw = min(w - 10, max(58, tw + 18))
            let bx = (w - bw) / 2

            UIColor(white: 0.05, alpha: 0.62).setFill()
            UIBezierPath(roundedRect: CGRect(x: bx, y: 41, width: bw, height: 19),
                         cornerRadius: 6).fill()
            text.draw(in: CGRect(x: 0, y: 42, width: w, height: 17), withAttributes: attrs)
        }
    }
}

// MARK: - 地图画布

/// 一个要画的围栏圆（已经换算成地图坐标）。
struct FenceRing {
    var key: String
    var center: CLLocationCoordinate2D
    var radius: Double
    var on: Bool
}

struct MapCanvas: UIViewRepresentable {

    var center: CLLocationCoordinate2D?
    var name: String
    var follow: Bool
    var recenter: Int
    var rings: [FenceRing]
    var track: [CLLocationCoordinate2D]
    var route: [CLLocationCoordinate2D]
    var mine: CLLocationCoordinate2D?
    var focusMine: Int
    var replayDot: CLLocationCoordinate2D?
    var satellite: Bool
    var traffic: Bool
    /// 1.39：把这一组点全部框进屏幕。历史轨迹页「切换」到地图时用它 ——
    /// 只靠 center 传一个点，跑了几十公里的一天会被裁掉大半条线。
    var fit: [CLLocationCoordinate2D] = []

    func makeCoordinator() -> Coord {
        return Coord()
    }

    private func same(_ a: CLLocationCoordinate2D?, _ b: CLLocationCoordinate2D?) -> Bool {
        guard let a = a, let b = b else { return false }
        return abs(a.latitude - b.latitude) < 0.0000001
            && abs(a.longitude - b.longitude) < 0.0000001
    }

    func makeUIView(context: Context) -> MKMapView {
        let mv = MKMapView()
        mv.delegate = context.coordinator
        mv.isZoomEnabled = true
        mv.isScrollEnabled = true
        mv.isRotateEnabled = false
        mv.isPitchEnabled = false
        mv.showsCompass = false
        mv.showsScale = false
        mv.showsBuildings = true
        mv.mapType = .standard
        mv.pointOfInterestFilter = .includingAll
        context.coordinator.lastRecenter = -99
        context.coordinator.lastFocusMine = 0
        return mv
    }

    func updateUIView(_ mv: MKMapView, context: Context) {
        let c = context.coordinator

        // 0. 图层：原版有 btnsatellite / btntraffic 两个开关
        let want: MKMapType = satellite ? .satellite : .standard
        if mv.mapType != want { mv.mapType = want }
        if mv.showsTraffic != traffic { mv.showsTraffic = traffic }

        // 1. 车标
        var pin: CarPoint?
        for a in mv.annotations {
            if let p = a as? CarPoint { pin = p; break }
        }
        if let p = center {
            if let a = pin {
                if a.title != name { a.title = name; (mv.view(for: a) as? CarPinView)?.setName(name) }
                if !same(a.coordinate, p) { a.coordinate = p }
            } else {
                mv.addAnnotation(CarPoint(p, name))
            }
        }

        // 2. 视野。只有「跟车」开着、或用户点了回正，才动镜头，
        //    否则用户自己拖开的视野会被下一次刷新拽回去。
        if let p = center {
            let forced = c.lastRecenter != recenter
            let moved = !same(c.lastCenter, p)
            if forced || (follow && moved) || c.lastRecenter == -99 {
                c.lastCenter = p
                c.lastRecenter = recenter
                mv.setRegion(MKCoordinateRegion(center: p,
                                                latitudinalMeters: 900,
                                                longitudinalMeters: 900),
                             animated: forced)
            }
        }

        // 3. 手机定位
        if focusMine > 0, c.lastFocusMine != focusMine, let m = mine {
            c.lastFocusMine = focusMine
            mv.setRegion(MKCoordinateRegion(center: m,
                                            latitudinalMeters: 900,
                                            longitudinalMeters: 900),
                         animated: true)
        }

        // 4. 围栏圆（可能是多个）。整组内容变了才重画。
        var ringKey = ""
        for r in rings { ringKey += r.key + "|" }
        if ringKey != c.lastRingKey {
            c.lastRingKey = ringKey
            for o in mv.overlays {
                if let ci = o as? MKCircle, ci.title == "fence" { mv.removeOverlay(ci) }
            }
            for r in rings {
                if !r.on { continue }
                let ci = MKCircle(center: r.center, radius: r.radius)
                ci.title = "fence"
                mv.addOverlay(ci)
            }
        }

        // 5. 轨迹线
        if track.count != c.lastTrackCount {
            c.lastTrackCount = track.count
            for o in mv.overlays {
                if let l = o as? MKPolyline, l.title == "track" { mv.removeOverlay(o) }
            }
            if track.count >= 2 {
                let line = MKPolyline(coordinates: track, count: track.count)
                line.title = "track"
                mv.addOverlay(line)
            }
        }

        // 6. 导航线
        if route.count != c.lastRouteCount {
            c.lastRouteCount = route.count
            for o in mv.overlays {
                if let l = o as? MKPolyline, l.title == "route" { mv.removeOverlay(o) }
            }
            if route.count >= 2 {
                let line = MKPolyline(coordinates: route, count: route.count)
                line.title = "route"
                mv.addOverlay(line)
            }
        }

        // 7. 回放点（一个小圆，跟着进度走）
        var dotKey = "off"
        if let d = replayDot {
            dotKey = String(format: "%.6f,%.6f", d.latitude, d.longitude)
        }
        if dotKey != c.lastDotKey {
            c.lastDotKey = dotKey
            for o in mv.overlays {
                if let ci = o as? MKCircle, ci.title == "replay" { mv.removeOverlay(ci) }
            }
            if let d = replayDot {
                let ci = MKCircle(center: d, radius: 16)
                ci.title = "replay"
                mv.addOverlay(ci)
            }
        }

        // 8. 视野自适应（历史轨迹页用）。整天的线要一次框进来，
        //    否则镜头停在起点，后面几十公里的轨迹全在屏幕外面。
        if fit.count != c.lastFitCount, fit.count >= 2 {
            c.lastFitCount = fit.count
            var rect = MKMapRect.null
            for p in fit {
                let pt = MKMapPoint(p)
                rect = rect.union(MKMapRect(x: pt.x, y: pt.y, width: 0, height: 0))
            }
            if !rect.isNull {
                mv.setVisibleMapRect(rect,
                                     edgePadding: UIEdgeInsets(top: 40, left: 40,
                                                               bottom: 40, right: 40),
                                     animated: false)
            }
        }
    }

    final class Coord: NSObject, MKMapViewDelegate {
        var lastCenter: CLLocationCoordinate2D?
        var lastRecenter = -99
        var lastFocusMine = 0
        var lastRingKey = ""
        var lastTrackCount = -1
        var lastRouteCount = -1
        var lastDotKey = ""
        var lastFitCount = -1

        func mapView(_ mapView: MKMapView, viewFor annotation: MKAnnotation) -> MKAnnotationView? {
            guard let p = annotation as? CarPoint else { return nil }
            let id = "carPin"
            if let v = mapView.dequeueReusableAnnotationView(withIdentifier: id) as? CarPinView {
                v.annotation = p
                v.setName(p.title ?? "")
                return v
            }
            return CarPinView(annotation: p, reuseIdentifier: id)
        }

        func mapView(_ mapView: MKMapView, rendererFor overlay: MKOverlay) -> MKOverlayRenderer {
            if let c = overlay as? MKCircle {
                let r = MKCircleRenderer(circle: c)
                if c.title == "replay" {
                    // 回放点：橘黄色实心小圆
                    r.strokeColor = UIColor(red: 0.98, green: 0.62, blue: 0.04, alpha: 1.0)
                    r.fillColor = UIColor(red: 0.98, green: 0.62, blue: 0.04, alpha: 0.85)
                    r.lineWidth = 2
                    return r
                }
                // 围栏：原版颜色是 00FF00 描边 + 淡填充
                r.strokeColor = UIColor(red: 0.13, green: 0.77, blue: 0.37, alpha: 0.95)
                r.fillColor = UIColor(red: 0.13, green: 0.77, blue: 0.37, alpha: 0.12)
                r.lineWidth = 2
                return r
            }
            if let l = overlay as? MKPolyline {
                let r = MKPolylineRenderer(polyline: l)
                if l.title == "route" {
                    r.strokeColor = UIColor(red: 0.23, green: 0.51, blue: 0.97, alpha: 1.0)
                    r.lineWidth = 5
                } else {
                    r.strokeColor = UIColor(red: 0.98, green: 0.62, blue: 0.04, alpha: 1.0)
                    r.lineWidth = 4
                }
                r.lineCap = .round
                r.lineJoin = .round
                return r
            }
            return MKOverlayRenderer(overlay: overlay)
        }
    }
}

// MARK: - 地图页

/// 地图页弹出的面板。同一个视图只挂**一个** .sheet —— 挂多个的话
/// iOS 14 上只有最后一个生效。
/// 地图页上只还剩一个 .sheet —— 导航到车。围栏、轨迹、GPS 设置三个都改成
/// 整屏页面了（见 MapPanels.swift），因为它们都需要整屏高度。
private enum MapSheet: String, Identifiable {
    case navi
    var id: String { rawValue }
}

struct MapPage: View {

    @EnvironmentObject var e: AutoEngine
    @Binding var isPresented: Bool

    // 地图状态
    @State private var follow = true
    @State private var recenter = 0
    @State private var focusMine = 0
    @State private var satellite = false
    @State private var traffic = false
    @State private var track: [CLLocationCoordinate2D] = []
    @State private var route: [CLLocationCoordinate2D] = []
    @State private var replayDot: CLLocationCoordinate2D? = nil

    // 必须显式 = nil：有默认值才会被排除在 memberwise init 之外，
    // 否则 MapPage(isPresented:) 这个调用会变成缺参数。
    @State private var sheet: MapSheet? = nil
    @State private var hint = ""

    // 实时追踪
    @State private var tracking = false
    @State private var trackTimer: Timer? = nil
    @State private var distText = ""

    // 围栏
    @State private var fences: [FenceStore.Fence] = []
    @State private var inFence: [String: Bool] = [:]

    // 1.39：三个整屏页面（电子围栏列表 / 围栏编辑 / 历史轨迹 / GPS 功能设置）。
    // 用 ZStack 直接盖，不走 .sheet —— 这两个页面都需要整屏地图，sheet 只有
    // 半屏高度，而且同一个视图上再挂 presentation 在 iOS 14 上会互相顶掉。
    @State private var showFenceList = false
    @State private var showFenceEdit = false
    @State private var editFence: FenceStore.Fence? = nil
    @State private var showHistory = false
    @State private var showGpsSet = false

    // MARK: 数据

    private var carLatLng: (Double, Double)? {
        guard let c = e.car,
              let lat = Double(c.lat), let lng = Double(c.lng),
              lat != 0, lng != 0 else { return nil }
        return (lat, lng)
    }

    private var carCoord: CLLocationCoordinate2D? {
        guard let p = carLatLng else { return nil }
        // 车机给的是 WGS-84，地图要 GCJ-02，差 300~700 米
        return MapGeo.display(lat: p.0, lng: p.1)
    }

    private var mineCoord: CLLocationCoordinate2D? {
        let lat = e.loc.lat, lng = e.loc.lng
        guard lat != 0, lng != 0 else { return nil }
        return MapGeo.display(lat: lat, lng: lng)
    }

    /// 手机定位的原始坐标（WGS-84）。围栏要存原始值 —— 存换算后的 GCJ 再换算一次，
    /// 来回一折腾就漂出去几十米了。
    private var mineLatLng: (Double, Double)? {
        let lat = e.loc.lat, lng = e.loc.lng
        guard lat != 0, lng != 0 else { return nil }
        return (lat, lng)
    }

    /// 手机到车的直线距离。原版这个数叫 lloc.pcdis，显示在车辆卡上。
    private var phoneCarKm: Double? {
        guard let p = carLatLng else { return nil }
        let lat = e.loc.lat, lng = e.loc.lng
        guard lat != 0, lng != 0 else { return nil }
        let d = CLLocation(latitude: lat, longitude: lng)
            .distance(from: CLLocation(latitude: p.0, longitude: p.1))
        return d / 1000.0
    }

    private var rings: [FenceRing] {
        var out: [FenceRing] = []
        for f in fences {
            let c = MapGeo.display(lat: f.lat, lng: f.lng)
            let key = f.id + "," + String(format: "%.6f", c.latitude)
                + "," + String(format: "%.6f", c.longitude)
                + "," + String(Int(f.radius)) + "," + (f.on ? "1" : "0")
            out.append(FenceRing(key: key, center: c, radius: f.radius, on: f.on))
        }
        return out
    }

    private var carName: String {
        return e.devName.isEmpty ? "我的车" : e.devName
    }

    private var tid: String {
        return Store.shared.str(StoreKey.tid)
    }

    private var moving: Bool {
        return e.car?.moving ?? false
    }

    private func stamp(_ ms: Int64) -> String {
        if ms <= 0 { return "--" }
        let sec = ms > 100_000_000_000 ? ms / 1000 : ms
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        f.locale = Locale(identifier: "en_US_POSIX")
        return f.string(from: Date(timeIntervalSince1970: TimeInterval(sec)))
    }

    private func hm(_ ms: Int64) -> String {
        if ms <= 0 { return "--:--" }
        let sec = ms > 100_000_000_000 ? ms / 1000 : ms
        let f = DateFormatter()
        f.dateFormat = "HH:mm"
        f.locale = Locale(identifier: "en_US_POSIX")
        return f.string(from: Date(timeIntervalSince1970: TimeInterval(sec)))
    }

    private var voltText: String {
        guard let v = e.car?.volt, !v.isEmpty else { return "--" }
        if v.lowercased().contains("v") { return v }
        return v + "V"
    }

    private var tempText: String {
        guard let t = e.car?.temp, !t.isEmpty else { return "--" }
        return t + "°"
    }

    /// 四个整屏页面里有没有开着的。开着就要把状态栏那片也压成深色。
    private var pageOpen: Bool {
        return showFenceList || showFenceEdit || showHistory || showGpsSet
    }

    // MARK: 界面

    /// 布局：**地图在上，操作区在地图下方，两者不重叠**。
    ///
    /// 为什么不按原版那样把按钮浮在地图上：UIKit 的命中测试只认 UIView，
    /// SwiftUI 画出来的按钮不是 UIView。当一张全屏 MKMapView 在下面时，
    /// 点在这些"浮"按钮上的触摸会先被地图的手势识别器接走，表现就是
    /// 「点了没反应」。把操作区挪到地图外面，就不存在抢触摸的问题了。
    var body: some View {
        ZStack {
            VStack(spacing: 0) {
                mapZone
                panel
            }

            // 页面打开时先垫一层，把状态栏和 Home 指示条那两条也压成深色，
            // 否则整屏页只从安全区开始，上下会漏出地图页的边。
            if pageOpen {
                UI.bg.ignoresSafeArea()
            }

            if showFenceList {
                FenceListPage(onBack: {
                                  // 列表里可能删掉或关掉了围栏，退出去要把地图上的圈同步掉。
                                  showFenceList = false
                                  fences = FenceStore.shared.list
                              },
                              onAdd: { openFenceEdit(nil) },
                              onEdit: { f in openFenceEdit(f) })
            }

            if showFenceEdit {
                FenceEditPage(fence: editFence,
                              carLatLng: carLatLng,
                              mineLatLng: mineLatLng,
                              carTitle: carName,
                              onBack: {
                                  // 原版这个按钮就叫「返回列表」，所以退出去先看到列表，
                                  // 不是直接弹回地图页。
                                  showFenceEdit = false
                                  fences = FenceStore.shared.list
                                  showFenceList = true
                              },
                              onSaved: {
                                  showFenceEdit = false
                                  fences = FenceStore.shared.list
                                  showFenceList = true
                                  hint = "围栏已保存"
                              })
                    // 从「新建」切到「改另一个」时，SwiftUI 认为还是同一个视图、
                    // @State 不会重新初始化，会把上一个围栏的名字带过来。用 id 强制重建。
                    .id(editFence?.id ?? "new-fence")
            }

            if showHistory {
                HistoryPage(carCoord: carCoord,
                            carTitle: carName,
                            onBack: { showHistory = false })
            }

            if showGpsSet {
                GpsSetPage(onBack: { showGpsSet = false })
            }
        }
        .background(UI.bg)
        .sheet(item: $sheet) { _ in
            naviSheet
        }
        .onAppear {
            e.log("▶ 打开地图页")
            fences = FenceStore.shared.list
            if e.car == nil {
                e.refreshStatus()
            }
            updateDistance()
            checkFences()
        }
        .onDisappear {
            stopTracking()
        }
    }

    private var mapZone: some View {
        MapCanvas(center: carCoord,
                  name: carName,
                  follow: follow,
                  recenter: recenter,
                  rings: rings,
                  track: track,
                  route: route,
                  mine: mineCoord,
                  focusMine: focusMine,
                  replayDot: replayDot,
                  satellite: satellite,
                  traffic: traffic)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .clipped()
    }

    private var panel: some View {
        VStack(spacing: 9) {
            HStack(spacing: 6) {
                panelLink("chevron.left", "返回") { isPresented = false }
                panelLink("location.fill", "我的位置") { jumpToMe() }
                panelLink("arrow.clockwise", "刷新") {
                    hint = "已叫车机上报，几秒后回来看看"
                    e.manualRefresh()
                    updateDistance()
                }
                panelLink("map.fill", satellite ? "卫星" : "标准") {
                    satellite = !satellite
                    hint = satellite ? "已切成卫星图" : "已切回标准图"
                }
                panelLink("speedometer", traffic ? "路况开" : "路况") {
                    traffic = !traffic
                    hint = traffic ? "已打开实时路况" : "已关闭实时路况"
                }
                Spacer(minLength: 0)
            }

            if !hint.isEmpty {
                Text(hint)
                    .font(.system(size: 11))
                    .foregroundColor(UI.text)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 7)
                    .background(UI.card.opacity(0.96))
                    .cornerRadius(9)
            }

            infoCard
            actionRow
        }
        .padding(.horizontal, 12)
        .padding(.top, 4)
        .padding(.bottom, 10)
        .background(UI.bg)
    }

    /// 面板顶部的小文字按钮。整段（图标+字+内边距）都能点。
    private func panelLink(_ icon: String, _ text: String,
                           _ action: @escaping () -> Void) -> some View {
        Button {
            tapFeedback()
            action()
        } label: {
            HStack(spacing: 3) {
                Image(systemName: icon)
                    .font(.system(size: 10, weight: .bold))
                Text(text)
                    .font(.system(size: 11))
            }
            .foregroundColor(tracking && text == "实时追踪" ? UI.ok : UI.dim)
            .padding(.vertical, 8)
            .padding(.horizontal, 7)
            .contentShape(Rectangle())
        }
        .buttonStyle(PlainButtonStyle())
    }

    private var infoCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(carName)
                    .font(.system(size: 16, weight: .bold))
                    .foregroundColor(UI.text)
                    .lineLimit(1)
                Spacer(minLength: 6)
                Text(moving ? "行驶" : "静止")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(.white)
                    .padding(.horizontal, 9)
                    .padding(.vertical, 2)
                    .background(moving ? UI.accent : UI.ok)
                    .cornerRadius(4)
                if !tid.isEmpty {
                    Text(tid)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(UI.dim)
                }
            }

            Divider().background(UI.line)

            HStack(spacing: 14) {
                infoItem("更新时间", stamp(e.car?.fetchedAt ?? 0))
            }
            HStack(spacing: 14) {
                infoItem("定位时间", stamp(e.car?.reportedAt ?? 0))
                if !distText.isEmpty {
                    Text(distText)
                        .font(.system(size: 11))
                        .foregroundColor(UI.accent)
                }
            }

            HStack(spacing: 14) {
                infoItem("电压", voltText)
                infoItem("温度", tempText)
                infoItem("速度", String(e.car?.speedKph ?? 0) + " km/h")
            }

            if !e.placeText.isEmpty {
                HStack(alignment: .top, spacing: 6) {
                    Text("地址")
                        .font(.system(size: 10))
                        .foregroundColor(UI.dim)
                        .frame(width: 34, alignment: .leading)
                    Text(e.placeText)
                        .font(.system(size: 11))
                        .foregroundColor(UI.text)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 0)
                }
            }
        }
        .padding(12)
        .background(UI.card.opacity(0.96))
        .cornerRadius(14)
    }

    private var actionRow: some View {
        HStack(spacing: 0) {
            actionBtn("location.north.line.fill", "实时追踪", tracking) { toggleTracking() }
            actionBtn("circle.dashed", "电子围栏", !fences.isEmpty) { openFence() }
            actionBtn("play.circle.fill", "历史轨迹", showHistory) { openHistory() }
            actionBtn("arrow.triangle.turn.up.right.diamond.fill", "导航到车",
                      !route.isEmpty) { openNavi() }
            actionBtn("car.fill", "车辆设置", showGpsSet) { showGpsSet = true }
        }
        .padding(.vertical, 6)
        .background(UI.card.opacity(0.96))
        .cornerRadius(14)
    }

    // MARK: 零件

    private func actionBtn(_ icon: String, _ text: String, _ on: Bool,
                           _ action: @escaping () -> Void) -> some View {
        Button {
            tapFeedback()
            action()
        } label: {
            VStack(spacing: 4) {
                ZStack {
                    Circle()
                        .stroke(on ? UI.ok : UI.accent, lineWidth: 2)
                        .frame(width: 42, height: 42)
                    Image(systemName: icon)
                        .font(.system(size: 17, weight: .semibold))
                        .foregroundColor(on ? UI.ok : UI.accent)
                }
                Text(text)
                    .font(.system(size: 10))
                    .foregroundColor(on ? UI.ok : UI.text)
                    .lineLimit(1)
            }
            // 五等分整格都能点。少了这句，只有那 42 点的圆和几个字能点中。
            .frame(maxWidth: .infinity)
            .padding(.vertical, 4)
            .contentShape(Rectangle())
        }
        .buttonStyle(PlainButtonStyle())
    }

    private func infoItem(_ k: String, _ v: String) -> some View {
        HStack(spacing: 5) {
            Text(k)
                .font(.system(size: 10))
                .foregroundColor(UI.dim)
            Text(v)
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(UI.text)
            Spacer(minLength: 0)
        }
    }

    /// 每按一下就轻轻震一下。有震动说明点击确实收到了。
    private func tapFeedback() {
        let g = UIImpactFeedbackGenerator(style: .light)
        g.prepare()
        g.impactOccurred()
    }

    // MARK: 实时追踪（照原版 TrackFlowController）

    /// 原版是定时器循环：安卓每 60 秒一轮（0xEA60），先叫车机定位、
    /// 等 1.9 秒再读状态；地图跟着车走，同时算手机到车的距离。
    ///
    /// iOS 包的主二进制里没有 303598 这个码（那条是安卓侧的），所以这里
    /// 用 203100 读状态这一半，不额外发指令 —— 宁可少发，不要乱发。
    private func toggleTracking() {
        if tracking {
            stopTracking()
            hint = "已停止实时追踪"
            e.log("▶ 停止实时追踪")
            return
        }
        tracking = true
        follow = true
        recenter += 1
        hint = "实时追踪已开 · 每 60 秒自动刷新一次车辆位置"
        e.log("▶ 开始实时追踪（60 秒一轮）")
        e.refreshStatus()
        trackTimer = Timer.scheduledTimer(withTimeInterval: 60.0, repeats: true) { _ in
            // 闭包里一律显式写 self：SXKC 是 struct，Swift 在 escaping 闭包中
            // 不允许裸引用成员。
            DispatchQueue.main.async {
                self.e.refreshStatus()
                self.updateDistance()
                self.checkFences()
            }
        }
    }

    private func stopTracking() {
        tracking = false
        if let t = trackTimer {
            t.invalidate()
            trackTimer = nil
        }
    }

    private func updateDistance() {
        guard let km = phoneCarKm else {
            distText = ""
            return
        }
        if km < 1 {
            distText = String(format: "我离车 %d 米", Int(km * 1000))
        } else {
            distText = String(format: "我离车 %.1f 公里", km)
        }
    }

    // MARK: 电子围栏（照原版 GeoFenceController）

    /// 原版从地图页点「电子围栏」：一个围栏都没有时直接进编辑页新建；
    /// 已经有了就先出列表（列表右上角加号同样能新建）。
    private func openFence() {
        fences = FenceStore.shared.list
        if fences.isEmpty {
            openFenceEdit(nil)
        } else {
            showFenceList = true
        }
    }

    private func openFenceEdit(_ f: FenceStore.Fence?) {
        if f == nil, carLatLng == nil, mineLatLng == nil {
            hint = "还没有车辆坐标，先点「刷新」再建围栏"
            return
        }
        editFence = f
        showFenceEdit = true
    }

    /// 越界判定。原版由服务端判、推 ActionMapWarn；这里本地判，
    /// App 没开的时候就断（如实说明）。
    ///
    /// 1.39：按每个围栏自己的两个开关分别判 —— 入圈报警 / 出圈报警，
    /// 跟原版编辑页那两行 Toggle 一一对应。第一次见到这个围栏只记方向、
    /// 不报警，否则一打开地图页就会因为"本来就在圈外"炸一条通知出来。
    private func checkFences() {
        guard let p = carLatLng else { return }
        let car = CLLocation(latitude: p.0, longitude: p.1)
        for f in fences {
            if !f.on { continue }
            let d = car.distance(from: CLLocation(latitude: f.lat, longitude: f.lng))
            let inside = d <= f.radius
            let was = inFence[f.id]
            inFence[f.id] = inside
            if was == nil { continue }
            if was == true, !inside, f.outAlert {
                alert("车辆离开围栏",
                      "「" + f.name + "」已出圈，直线距离 " + String(Int(d)) + " 米")
            }
            if was == false, inside, f.inAlert {
                alert("车辆进入围栏",
                      "「" + f.name + "」已进圈，直线距离 " + String(Int(d)) + " 米")
            }
        }
    }

    private func alert(_ title: String, _ body: String) {
        let c = UNMutableNotificationContent()
        c.title = title
        c.body = body
        c.sound = .default
        let r = UNNotificationRequest(identifier: "fence-" + UUID().uuidString,
                                      content: c, trigger: nil)
        UNUserNotificationCenter.current().add(r, withCompletionHandler: nil)
        hint = title + "：" + body
        e.log("⚠ " + title + " " + body)
    }

    // MARK: 历史轨迹（照原版 HistoryListView）

    /// 整屏的轨迹页在 MapPanels.swift 的 HistoryPage 里（日期页签 + 四项小结 +
    /// 起止地点 + 地图回放）。这里只负责把当天已经画在地图上的线清掉再进去，
    /// 否则用户从轨迹页退回来，地图上还挂着上一次那条线。
    private func openHistory() {
        track = []
        replayDot = nil
        showHistory = true
    }

    // MARK: 导航到车（照原版 ActionMapNavi）

    private func openNavi() {
        if carCoord == nil {
            hint = "还没有车辆坐标，先点「刷新」"
            return
        }
        sheet = .navi
    }

    private var naviSheet: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("导航到车")
                    .font(.system(size: 18, weight: .bold))
                    .foregroundColor(UI.text)
                Spacer()
                Button("关闭") { sheet = nil }
                    .foregroundColor(UI.accent)
            }

            Text("原版是唤起手机里装的地图 App（高德 / 百度 / 腾讯），直接进「到车」的驾车路线。")
                .font(.system(size: 11))
                .foregroundColor(UI.dim)
                .fixedSize(horizontal: false, vertical: true)

            naviRow("map.fill", "在 App 内算路线", "苹果算路，不跳出去") {
                sheet = nil
                calcRouteInApp()
            }
            naviRow("location.circle.fill", "用苹果地图打开", "系统地图，可导航可限速提醒") {
                sheet = nil
                openAppleMap()
            }
            naviRow("car.circle.fill", "用高德地图打开", "装了高德才会成功") {
                sheet = nil
                openThirdMap("iosamap://path?sourceApplication=SXKC&dlat=",
                             "dname=", "高德")
            }
            naviRow("mappin.circle.fill", "用百度地图打开", "装了百度才会成功") {
                sheet = nil
                openThirdMap("baidumap://map/direction?mode=driving&destination=latlng:",
                             "|name=", "百度")
            }
            naviRow("mappin.and.ellipse", "用腾讯地图打开", "装了腾讯才会成功") {
                sheet = nil
                openThirdMap("qqmap://map/routeplan?type=drive&to=",
                             "", "腾讯")
            }

            Spacer(minLength: 0)
        }
        .padding(18)
        .background(UI.bg.ignoresSafeArea())
    }

    private func naviRow(_ icon: String, _ title: String, _ sub: String,
                         _ action: @escaping () -> Void) -> some View {
        Button {
            tapFeedback()
            action()
        } label: {
            HStack(spacing: 10) {
                Image(systemName: icon)
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundColor(UI.accent)
                    .frame(width: 24)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.system(size: 14))
                        .foregroundColor(UI.text)
                    Text(sub)
                        .font(.system(size: 11))
                        .foregroundColor(UI.dim)
                }
                Spacer(minLength: 0)
                Image(systemName: "chevron.right")
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(UI.dim.opacity(0.6))
            }
            .padding(.vertical, 12)
            .padding(.horizontal, 14)
            .background(UI.card)
            .cornerRadius(10)
            .contentShape(Rectangle())
        }
        .buttonStyle(PlainButtonStyle())
    }

    /// 苹果地图：直接交给系统，不用拼 scheme。
    private func openAppleMap() {
        guard let p = carLatLng else { return }
        let g = MapGeo.display(lat: p.0, lng: p.1)
        let item = MKMapItem(placemark: MKPlacemark(coordinate: g))
        item.name = carName
        item.openInMaps(launchOptions: [
            MKLaunchOptionsDirectionsModeKey: MKLaunchOptionsDirectionsModeDriving
        ])
        e.log("▶ 用苹果地图导航到车")
    }

    /// 第三方地图。手机没装时 open 会失败，所以用 completion 判。
    /// 坐标给 GCJ-02：这几个地图 App 在中国大陆都按 GCJ 理解传入值。
    private func openThirdMap(_ head: String, _ tail: String, _ label: String) {
        guard let p = carLatLng else { return }
        let g = MapGeo.display(lat: p.0, lng: p.1)
        let lat = String(format: "%.6f", g.latitude)
        let lng = String(format: "%.6f", g.longitude)

        // 车名一般是中文，直接塞进 URL 会让 URL(string:) 返回 nil
        // （iOS 9 起严格校验），所以名字先单独做百分号编码。
        let qName = carName.addingPercentEncoding(
            withAllowedCharacters: .urlQueryAllowed) ?? "car"

        var s = ""
        if label == "高德" {
            s = head + lat + "&dlon=" + lng + "&" + tail + qName + "&dev=0&t=0"
        } else if label == "百度" {
            s = head + lat + "," + lng + tail + qName
                + "&coord_type=gcj02&src=ios.sxkc"
        } else {
            s = head + qName + "&tocoord=" + lat + "," + lng + "&referer=sxkc"
        }

        guard let url = URL(string: s) else {
            hint = label + "的地图链接拼错了"
            return
        }
        UIApplication.shared.open(url, options: [:]) { ok in
            if !ok {
                self.hint = "没打开" + label + "地图 —— 手机里可能没装这个 App"
            } else {
                self.hint = "已用" + label + "地图打开"
            }
        }
        e.log("▶ 唤起" + label + "地图：" + s)
    }

    private func calcRouteInApp() {
        guard let dst = carCoord else {
            hint = "还没有车辆坐标，先点「刷新」"
            return
        }
        guard let src = mineCoord else {
            hint = "还没拿到手机定位：回主界面把「定位」卡片的开关打开"
            return
        }
        hint = "正在算路…"

        let req = MKDirections.Request()
        req.source = MKMapItem(placemark: MKPlacemark(coordinate: src))
        req.destination = MKMapItem(placemark: MKPlacemark(coordinate: dst))
        req.transportType = .automobile
        req.requestsAlternateRoutes = false

        MKDirections(request: req).calculate { resp, err in
            DispatchQueue.main.async {
                guard let r = resp?.routes.first else {
                    self.hint = "没算出路：" + (err?.localizedDescription ?? "附近没有可用道路")
                    return
                }
                var coords = [CLLocationCoordinate2D](repeating: kCLLocationCoordinate2DInvalid,
                                                      count: r.polyline.pointCount)
                r.polyline.getCoordinates(&coords,
                                          range: NSRange(location: 0, length: r.polyline.pointCount))
                self.route = coords
                self.follow = false
                let km = r.distance / 1000.0
                let mins = Int(r.expectedTravelTime / 60.0)
                self.hint = String(format: "到车 %.1f 公里 · 约 %d 分钟", km, max(1, mins))
                self.e.log("▶ 导航到车 " + self.hint)
            }
        }
    }

    // MARK: 动作

    private func jumpToMe() {
        guard mineCoord != nil else {
            hint = "还没拿到手机定位：回主界面把「定位」卡片的开关打开"
            return
        }
        focusMine += 1
        follow = false
        hint = "镜头已跳到我的位置"
    }
}


// ==========================================================================
//  SXKC/UI/MapPanels.swift  ——  整屏页面：电子围栏、历史轨迹、GPS 功能设置
// ==========================================================================

//
//  MapPanels.swift
//  1.39：三个整屏页面 —— 电子围栏、历史轨迹、GPS 功能设置
//
//  这三个页面是照着原版 iOS（顺心控车 1.0.6）的截图 1:1 复刻的：
//
//   1. 电子围栏（fence）
//      整屏地图 + 底部面板：返回列表 / 保存 / 半径滑杆（0.5KM）/ 围栏名称 /
//      入围栏报警 / 出围栏报警。字段和安卓包里 GeoFenceController 用的那一组
//      完全对得上：geo.circle.lat / geo.circle.lng / geo.circle.radius /
//      geo.circle.reset / geo.geoname。
//
//   2. 历史轨迹（track）
//      顶部「切换」+ 横向日期页签（日期 + 当天里程）+ 四项小结（里程 / 时长 /
//      均速 / 最高速）+ 开始时间与位置 + 结束时间与位置。对应 HistoryListView
//      的 txndate / times / avgspd / maxspd / miles 五个字段。
//
//   3. GPS 功能设置（devcfg）
//      GPS 开关 / 电子围栏 / 隐私模式 三行开关 + 查询 / 保存两个按钮。
//      对应安卓包里 DataHelper.getcfg(dev, "config.devcfg.privacy") 和
//      parseVstStatus 里读的 gps_opn / gps_cls / gps_loc 三个状态位。
//
//  布局按截图，配色沿用本项目的深色主题 —— 其余界面都是深色，这里单独做白底
//  会跟整个 App 割裂。
//
//  另外有一处刻意和原版不一样、必须写清楚：
//  原版左侧那两个浮在地图上的圆按钮，这里挪进了底部面板。原因在 1.37 已经踩过：
//  SwiftUI 画的按钮不是 UIView，全屏 MKMapView 在下面时，触摸会先被地图的手势
//  识别器接走，表现就是「点了没反应」。放进面板里就不抢触摸了。
//


// MARK: - 公共零件

/// 整屏页面的顶栏：左返回箭头、居中标题、右侧一个动作（文字或图标）。
/// 原版三个页面都是这个样子，抽出来省得各写一遍。
struct PageTopBar: View {

    var title: String
    var rightText: String = ""
    var rightIcon: String = ""
    var onBack: () -> Void
    var onRight: (() -> Void)? = nil

    var body: some View {
        ZStack {
            Text(title)
                .font(.system(size: 17, weight: .semibold))
                .foregroundColor(.white)

            HStack(spacing: 0) {
                Button {
                    onBack()
                } label: {
                    Image(systemName: "arrow.left")
                        .font(.system(size: 18, weight: .semibold))
                        .foregroundColor(.white)
                        .frame(width: 48, height: 48)
                        .contentShape(Rectangle())
                }
                .buttonStyle(PlainButtonStyle())

                Spacer(minLength: 0)

                if let act = onRight {
                    Button {
                        act()
                    } label: {
                        rightLabel
                            .frame(width: 48, height: 48)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(PlainButtonStyle())
                }
            }
        }
        .frame(height: 48)
        .background(Color(red: 0.105, green: 0.105, blue: 0.118))
    }

    @ViewBuilder
    private var rightLabel: some View {
        if rightText.isEmpty {
            Image(systemName: rightIcon.isEmpty ? "plus" : rightIcon)
                .font(.system(size: 19, weight: .semibold))
                .foregroundColor(.white)
        } else {
            Text(rightText)
                .font(.system(size: 15))
                .foregroundColor(.white)
        }
    }
}

/// 毫秒时间戳 → "2026-11-14 01:10:59"（原版列表里就是这个格式）。
func mpStamp(_ ms: Int64) -> String {
    if ms <= 0 { return "--" }
    let sec = ms > 100_000_000_000 ? ms / 1000 : ms
    let f = DateFormatter()
    f.dateFormat = "yyyy-MM-dd HH:mm:ss"
    f.locale = Locale(identifier: "en_US_POSIX")
    return f.string(from: Date(timeIntervalSince1970: TimeInterval(sec)))
}

/// "yyyyMMdd" → "11-14"（日期页签上那一行）。
func mpMonthDay(_ key: String) -> String {
    if key.count >= 8 {
        let m = key.index(key.startIndex, offsetBy: 4)
        let d = key.index(key.startIndex, offsetBy: 6)
        return String(key[m..<d]) + "-" + String(key[d...])
    }
    return key
}

// MARK: - 1. 电子围栏编辑页

/// 整屏地图 + 底部面板。新建和修改用的是同一个页面：传 fence 就是改，传 nil 就是新建。
struct FenceEditPage: View {

    @EnvironmentObject var e: AutoEngine

    private let editingId: String?
    private let carLatLng: (Double, Double)?
    private let mineLatLng: (Double, Double)?
    private let carTitle: String
    private let onBack: () -> Void
    private let onSaved: () -> Void

    @State private var name: String
    @State private var radiusKm: Double
    @State private var centerLat: Double
    @State private var centerLng: Double
    @State private var inAlert: Bool
    @State private var outAlert: Bool
    @State private var tip = ""

    // 视野控制：recenter 变一次就是把镜头拉回车；focusMine 变一次是拉回我的位置。
    @State private var recenter = 0
    @State private var focusMine = 0

    init(fence: FenceStore.Fence?,
         carLatLng: (Double, Double)?,
         mineLatLng: (Double, Double)?,
         carTitle: String,
         onBack: @escaping () -> Void,
         onSaved: @escaping () -> Void) {

        self.editingId = fence?.id
        self.carLatLng = carLatLng
        self.mineLatLng = mineLatLng
        self.carTitle = carTitle
        self.onBack = onBack
        self.onSaved = onSaved

        let seed = carLatLng ?? mineLatLng ?? (0.0, 0.0)
        _name = State(initialValue: fence?.name ?? FenceStore.shared.nextName())
        _radiusKm = State(initialValue: (fence?.radius ?? 500.0) / 1000.0)
        _centerLat = State(initialValue: fence?.lat ?? seed.0)
        _centerLng = State(initialValue: fence?.lng ?? seed.1)
        _inAlert = State(initialValue: fence?.inAlert ?? false)
        _outAlert = State(initialValue: fence?.outAlert ?? true)
    }

    // MARK: 坐标

    private var carCoord: CLLocationCoordinate2D? {
        guard let p = carLatLng, p.0 != 0, p.1 != 0 else { return nil }
        return MapGeo.display(lat: p.0, lng: p.1)
    }

    private var mineCoord: CLLocationCoordinate2D? {
        guard let p = mineLatLng, p.0 != 0, p.1 != 0 else { return nil }
        return MapGeo.display(lat: p.0, lng: p.1)
    }

    /// 地图镜头。有车就对着车，没车就对着圆心 —— 否则会飘到几内亚湾。
    private var mapCenter: CLLocationCoordinate2D {
        if let c = carCoord { return c }
        if centerLat != 0 || centerLng != 0 {
            return MapGeo.display(lat: centerLat, lng: centerLng)
        }
        return CLLocationCoordinate2D(latitude: 24.8741, longitude: 118.6757)
    }

    private var rings: [FenceRing] {
        let c = MapGeo.display(lat: centerLat, lng: centerLng)
        let key = String(format: "edit,%.6f,%.6f,%.0f",
                         c.latitude, c.longitude, radiusKm * 1000.0)
        return [FenceRing(key: key, center: c, radius: radiusKm * 1000.0, on: true)]
    }

    // MARK: 界面

    var body: some View {
        VStack(spacing: 0) {
            PageTopBar(title: "电子围栏", onBack: onBack)

            MapCanvas(center: mapCenter,
                      name: carTitle,
                      follow: false,
                      recenter: recenter,
                      rings: rings,
                      track: [],
                      route: [],
                      mine: mineCoord,
                      focusMine: focusMine,
                      replayDot: nil,
                      satellite: false,
                      traffic: false)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .clipped()

            bottomPanel
        }
        .background(UI.bg)
    }

    private var bottomPanel: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Button {
                    onBack()
                } label: {
                    Text("返回列表")
                        .font(.system(size: 16))
                        .foregroundColor(UI.accent)
                        .padding(.vertical, 11)
                        .contentShape(Rectangle())
                }
                .buttonStyle(PlainButtonStyle())

                Spacer(minLength: 0)

                roundBtn("location.fill") { centerOnMine() }
                roundBtn("car.fill") { centerOnCar() }

                Spacer(minLength: 0)

                Button {
                    save()
                } label: {
                    Text("保存")
                        .font(.system(size: 16, weight: .semibold))
                        .foregroundColor(UI.accent)
                        .padding(.vertical, 11)
                        .contentShape(Rectangle())
                }
                .buttonStyle(PlainButtonStyle())
            }
            .padding(.horizontal, 12)

            rowLine

            // 半径：原版滑杆右端直接跟一个「0.5KM」。范围 0.1~5.0 公里、步长 0.1，
            // 和 GeoFenceController 那边默认 500 米、上限 5000 米、步长 100 一致。
            HStack(spacing: 10) {
                Text("半径")
                    .font(.system(size: 15))
                    .foregroundColor(UI.text)
                    .frame(width: 68, alignment: .leading)

                Slider(value: $radiusKm, in: 0.1...5.0, step: 0.1)
                    .accentColor(UI.accent)

                Text(String(format: "%.1fKM", radiusKm))
                    .font(.system(size: 14))
                    .foregroundColor(UI.text)
                    .frame(width: 62, alignment: .trailing)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 4)

            rowLine

            HStack(spacing: 10) {
                Text("围栏名称")
                    .font(.system(size: 15))
                    .foregroundColor(UI.text)
                    .frame(width: 68, alignment: .leading)

                TextField("围栏名称", text: $name)
                    .font(.system(size: 15))
                    .foregroundColor(UI.text)
                    .accentColor(UI.accent)
                    .padding(.vertical, 9)
                    .padding(.horizontal, 10)
                    .background(UI.cardHi)
                    .cornerRadius(7)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 4)

            rowLine

            switchRow("入围栏报警", $inAlert)
            rowLine
            switchRow("出围栏报警", $outAlert)

            if !tip.isEmpty {
                Text(tip)
                    .font(.system(size: 11))
                    .foregroundColor(UI.dim)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 14)
                    .padding(.bottom, 4)
            }
        }
        .padding(.top, 2)
        .padding(.bottom, 6)
        .background(UI.card)
    }

    private var rowLine: some View {
        Rectangle()
            .fill(UI.line)
            .frame(height: 1)
            .padding(.leading, 14)
    }

    private func roundBtn(_ icon: String, _ act: @escaping () -> Void) -> some View {
        Button {
            act()
        } label: {
            Image(systemName: icon)
                .font(.system(size: 13, weight: .semibold))
                .foregroundColor(UI.accent)
                .frame(width: 34, height: 34)
                .background(UI.cardHi)
                .clipShape(Circle())
                .contentShape(Circle())
        }
        .buttonStyle(PlainButtonStyle())
    }

    private func switchRow(_ label: String, _ bind: Binding<Bool>) -> some View {
        HStack(spacing: 10) {
            Text(label)
                .font(.system(size: 15))
                .foregroundColor(UI.text)
            Spacer(minLength: 0)
            Toggle("", isOn: bind)
                .labelsHidden()
                .toggleStyle(SwitchToggleStyle(tint: UI.accent))
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 7)
    }

    // MARK: 动作

    private func centerOnCar() {
        guard let p = carLatLng, p.0 != 0 else {
            tip = "还没拿到车的位置，回地图页点一下「刷新」"
            return
        }
        centerLat = p.0
        centerLng = p.1
        recenter += 1
        tip = "圆心已放到车的位置"
    }

    private func centerOnMine() {
        guard let p = mineLatLng, p.0 != 0 else {
            tip = "还没拿到手机定位，回主界面把「定位」打开"
            return
        }
        centerLat = p.0
        centerLng = p.1
        focusMine += 1
        tip = "圆心已放到我的位置"
    }

    private func save() {
        if centerLat == 0 && centerLng == 0 {
            tip = "还没有圆心：先点上面的手机或车图标"
            return
        }
        let raw = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let finalName = raw.isEmpty ? FenceStore.shared.nextName() : raw

        let f = FenceStore.Fence(id: editingId ?? UUID().uuidString,
                                 name: finalName,
                                 lat: centerLat,
                                 lng: centerLng,
                                 radius: radiusKm * 1000.0,
                                 on: true,
                                 inAlert: inAlert,
                                 outAlert: outAlert)
        FenceStore.shared.save(f)
        e.log("▶ 保存围栏「" + finalName + "」半径 "
              + String(Int(radiusKm * 1000)) + " 米")
        onSaved()
    }
}

// MARK: - 2. 电子围栏列表页

/// 原版从地图页点「电子围栏」先进这张列表，右上角加号进编辑页。
struct FenceListPage: View {

    @EnvironmentObject var e: AutoEngine

    var onBack: () -> Void
    var onAdd: () -> Void
    var onEdit: (FenceStore.Fence) -> Void

    @State private var list: [FenceStore.Fence] = []

    var body: some View {
        VStack(spacing: 0) {
            PageTopBar(title: "电子围栏",
                       rightIcon: "plus",
                       onBack: onBack,
                       onRight: onAdd)

            ScrollView {
                VStack(spacing: 10) {
                    if list.isEmpty {
                        VStack(spacing: 10) {
                            Image(systemName: "circle.dashed")
                                .font(.system(size: 34))
                                .foregroundColor(UI.dim)
                            Text("还没有围栏")
                                .font(.system(size: 14))
                                .foregroundColor(UI.text)
                            Text("点右上角「+」新建一个，圆心默认放在车的位置")
                                .font(.system(size: 12))
                                .foregroundColor(UI.dim)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 60)
                    } else {
                        ForEach(list) { f in
                            fenceRow(f)
                        }
                        Text("点一条进去改半径和报警；长按删除。")
                            .font(.system(size: 11))
                            .foregroundColor(UI.dim)
                            .padding(.top, 6)
                    }
                }
                .padding(14)
            }
        }
        .background(UI.bg)
        .onAppear {
            FenceStore.shared.reload()
            list = FenceStore.shared.list
        }
    }

    private func fenceRow(_ f: FenceStore.Fence) -> some View {
        // 整行不用 Button 包：里面已经有一个 Toggle 了，Button 套 Toggle 的时候
        // 点开关会连带把行点击也触发一次（一按就跳进编辑页，开关反而拨不动）。
        HStack(spacing: 10) {
            Image(systemName: "circle.dashed")
                .font(.system(size: 16, weight: .semibold))
                .foregroundColor(f.on ? UI.ok : UI.dim)
                .frame(width: 24)

            VStack(alignment: .leading, spacing: 3) {
                Text(f.name)
                    .font(.system(size: 15))
                    .foregroundColor(UI.text)
                Text(radiusText(f.radius) + " · "
                     + (f.inAlert ? "入圈报警" : "入圈静默") + " / "
                     + (f.outAlert ? "出圈报警" : "出圈静默"))
                    .font(.system(size: 11))
                    .foregroundColor(UI.dim)
            }

            Spacer(minLength: 0)

            Toggle("", isOn: Binding(
                get: { f.on },
                set: { v in
                    FenceStore.shared.setOn(id: f.id, v)
                    list = FenceStore.shared.list
                }))
                .labelsHidden()
                .toggleStyle(SwitchToggleStyle(tint: UI.ok))

            Image(systemName: "chevron.right")
                .font(.system(size: 11, weight: .bold))
                .foregroundColor(UI.dim.opacity(0.6))
        }
        .padding(12)
        .background(UI.card)
        .cornerRadius(11)
        .contentShape(Rectangle())
        .onTapGesture { onEdit(f) }
        .contextMenu {
            Button("删除这个围栏") {
                FenceStore.shared.remove(id: f.id)
                list = FenceStore.shared.list
                e.log("▶ 删除围栏「" + f.name + "」")
            }
        }
    }

    private func radiusText(_ m: Double) -> String {
        if m >= 1000 {
            return String(format: "%.1f 公里", m / 1000.0)
        }
        return String(Int(m)) + " 米"
    }
}

// MARK: - 3. 历史轨迹页

/// 原版：顶部「切换」，下面一排日期页签（每个页签两行：日期 + 当天里程），
/// 选中那天在下面出四项小结和起止时间地点。「切换」在本版是列表 ↔ 地图。
struct HistoryPage: View {

    @EnvironmentObject var e: AutoEngine

    var carCoord: CLLocationCoordinate2D?
    var carTitle: String
    var onBack: () -> Void

    @State private var days: [TrackStore.Day] = []
    @State private var sel = 0
    @State private var mapMode = false

    @State private var raw: [TrackStore.Pt] = []
    @State private var pts: [CLLocationCoordinate2D] = []
    @State private var idx: Double = 0
    @State private var playing = false
    @State private var timer: Timer? = nil

    // 逆地理结果缓存，key 是「天 + 起止标记」。
    @State private var places: [String: String] = [:]

    var body: some View {
        VStack(spacing: 0) {
            PageTopBar(title: "历史轨迹",
                       rightText: "切换",
                       onBack: onBack,
                       onRight: { mapMode = !mapMode })

            if days.isEmpty {
                emptyView
            } else {
                dayTabs
                ScrollView {
                    VStack(spacing: 12) {
                        if mapMode { mapBox }
                        summaryBox
                        placeBox
                        if mapMode { replayBar }
                        footNote
                    }
                    .padding(14)
                }
            }
        }
        .background(UI.bg)
        .onAppear { load() }
        .onDisappear { stopTimer() }
    }

    // MARK: 顶部页签

    private var dayTabs: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 0) {
                // 不用 Array(enumerated()) —— 它的元素是元组，而 KeyPath 不能
                // 指向元组成员（\.element.key 编译不过）。用下标最省事。
                ForEach(days.indices, id: \.self) { i in
                    tabCell(i, days[i])
                }
            }
            .padding(.horizontal, 4)
        }
        .frame(height: 62)
        .background(UI.card)
    }

    private func tabCell(_ i: Int, _ d: TrackStore.Day) -> some View {
        let on = (i == sel)
        return Button {
            sel = i
            loadDay()
        } label: {
            VStack(spacing: 2) {
                Text(mpMonthDay(d.key))
                    .font(.system(size: 15, weight: on ? .semibold : .regular))
                    .foregroundColor(on ? UI.bad : UI.text)
                Text(String(format: "%.2fKM", d.km))
                    .font(.system(size: 11))
                    .foregroundColor(on ? UI.bad : UI.dim)
            }
            .frame(width: 76)
            .padding(.vertical, 6)
            .contentShape(Rectangle())
            .overlay(
                Rectangle()
                    .fill(on ? UI.bad : Color.clear)
                    .frame(height: 2),
                alignment: .bottom
            )
        }
        .buttonStyle(PlainButtonStyle())
    }

    // MARK: 当天小结（截图里那一行四个数）

    private var summaryBox: some View {
        HStack(spacing: 0) {
            statCell("flag.fill", kmText, UI.text)
            statCell("clock", durText, UI.text)
            statCell("speedometer", avgText, UI.text)
            statCell("exclamationmark.circle.fill", maxText, UI.bad)
        }
        .padding(.vertical, 12)
        .background(UI.card)
        .cornerRadius(11)
    }

    private func statCell(_ icon: String, _ text: String, _ color: Color) -> some View {
        HStack(spacing: 4) {
            Image(systemName: icon)
                .font(.system(size: 12, weight: .semibold))
                .foregroundColor(color)
            Text(text)
                .font(.system(size: 13, weight: .semibold))
                .foregroundColor(color)
                .lineLimit(1)
                .minimumScaleFactor(0.7)
        }
        .frame(maxWidth: .infinity)
    }

    // MARK: 起止时间与位置

    private var placeBox: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("开始时间：" + mpStamp(cur?.startAt ?? 0))
                .font(.system(size: 13))
                .foregroundColor(UI.text)
            placeLine(placeKey(0))

            Rectangle().fill(UI.line).frame(height: 1).padding(.vertical, 2)

            Text("结束时间：" + mpStamp(cur?.endAt ?? 0))
                .font(.system(size: 13))
                .foregroundColor(UI.text)
            placeLine(placeKey(1))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(UI.card)
        .cornerRadius(11)
    }

    private func placeLine(_ key: String) -> some View {
        HStack(alignment: .top, spacing: 0) {
            Text("位置：")
                .font(.system(size: 12))
                .foregroundColor(UI.dim)
            Text(places[key] ?? "定位中…")
                .font(.system(size: 12))
                .foregroundColor(places[key] == nil ? UI.dim : UI.text)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
    }

    // MARK: 地图（「切换」之后）

    private var mapBox: some View {
        MapCanvas(center: nil,
                  name: carTitle,
                  follow: false,
                  recenter: 0,
                  rings: [],
                  track: pts,
                  route: [],
                  mine: nil,
                  focusMine: 0,
                  replayDot: curCoord,
                  satellite: false,
                  traffic: false,
                  fit: pts)
            .frame(height: 260)
            .clipped()
            .cornerRadius(11)
    }

    private var replayBar: some View {
        VStack(spacing: 6) {
            HStack(spacing: 10) {
                Button {
                    togglePlay()
                } label: {
                    Image(systemName: playing ? "pause.fill" : "play.fill")
                        .font(.system(size: 14, weight: .bold))
                        .foregroundColor(.white)
                        .frame(width: 34, height: 34)
                        .background(UI.accent)
                        .clipShape(Circle())
                        .contentShape(Circle())
                }
                .buttonStyle(PlainButtonStyle())

                Slider(value: Binding(
                    get: { idx },
                    set: { v in
                        idx = v
                        stopTimer()
                    }), in: 0...Double(max(1, raw.count - 1)))
                    .accentColor(UI.warn)

                Text(kphText)
                    .font(.system(size: 12, weight: .semibold, design: .monospaced))
                    .foregroundColor(UI.warn)
                    .frame(width: 66, alignment: .trailing)
            }

            HStack {
                Text(curPt == nil ? "--" : mpStamp(curPt?.ts ?? 0))
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(UI.dim)
                Spacer(minLength: 0)
                Text("\(curIdx + 1) / \(raw.count)")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(UI.dim)
            }
        }
        .padding(10)
        .background(UI.card)
        .cornerRadius(11)
    }

    private var footNote: some View {
        Text("轨迹由本机记录：App 没开的那段录不到。原版是从车机上报的历史里按天拉回来的。")
            .font(.system(size: 10))
            .foregroundColor(UI.dim)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var emptyView: some View {
        VStack(spacing: 10) {
            Image(systemName: "point.topleft.down.curvedto.point.bottomright.up")
                .font(.system(size: 34))
                .foregroundColor(UI.dim)
            Text("还没有轨迹")
                .font(.system(size: 14))
                .foregroundColor(UI.text)
            Text("开出去转一圈，App 每次刷到车的位置就会记一个点。")
                .font(.system(size: 12))
                .foregroundColor(UI.dim)
                .multilineTextAlignment(.center)
        }
        .padding(30)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: 数据

    private var cur: TrackStore.Day? {
        if sel < 0 || sel >= days.count { return nil }
        return days[sel]
    }

    private var kmText: String {
        return String(format: "%.2fKM", cur?.km ?? 0)
    }

    private var durText: String {
        guard let d = cur else { return "0分0秒" }
        let sec = max(0, (d.endAt - d.startAt) / 1000)
        return String(sec / 60) + "分" + String(sec % 60) + "秒"
    }

    private var avgText: String {
        return String(format: "%.1fKM/H", cur?.avgKph ?? 0)
    }

    private var maxText: String {
        return String(format: "%.0fKM/H", cur?.maxKph ?? 0)
    }

    private var curIdx: Int {
        if raw.isEmpty { return 0 }
        return min(max(0, Int(idx)), raw.count - 1)
    }

    private var curPt: TrackStore.Pt? {
        if raw.isEmpty { return nil }
        return raw[curIdx]
    }

    private var curCoord: CLLocationCoordinate2D? {
        if pts.isEmpty { return nil }
        return pts[min(max(0, Int(idx)), pts.count - 1)]
    }

    private var kphText: String {
        return String(format: "%.0f km/h", curPt?.kph ?? 0)
    }

    private func placeKey(_ tag: Int) -> String {
        guard let d = cur else { return "none-" + String(tag) }
        return d.key + "-" + String(tag)
    }

    private func load() {
        days = TrackStore.shared.days()
        sel = 0
        if !days.isEmpty { loadDay() }
    }

    /// 换一天：读点、画线、清回放位置、重新解析起止地点。
    private func loadDay() {
        stopTimer()
        playing = false
        idx = 0
        guard let d = cur else {
            raw = []
            pts = []
            return
        }
        raw = TrackStore.shared.points(day: d.key)
        var out: [CLLocationCoordinate2D] = []
        out.reserveCapacity(raw.count)
        for p in raw {
            out.append(MapGeo.display(lat: p.lat, lng: p.lng))
        }
        pts = out
        if let a = raw.first { askPlace(d.key, 0, a.lat, a.lng) }
        if let b = raw.last { askPlace(d.key, 1, b.lat, b.lng) }
        e.log("▶ 历史轨迹 " + d.key + " 共 " + String(raw.count) + " 点")
    }

    /// 逆地理。原版这两行是「省市区街道 + 门牌 + [POI 名 距离]」，
    /// 距离那一截得靠服务端的 POI 库，这里用系统的 CLGeocoder 拿到能拿的部分。
    private func askPlace(_ dayKey: String, _ tag: Int, _ lat: Double, _ lng: Double) {
        let key = dayKey + "-" + String(tag)
        if places[key] != nil { return }
        if lat == 0 || lng == 0 { return }
        let loc = CLLocation(latitude: lat, longitude: lng)
        CLGeocoder().reverseGeocodeLocation(loc) { marks, _ in
            guard let m = marks?.first else { return }
            var s = ""
            let parts: [String?] = [m.administrativeArea, m.locality,
                                    m.subLocality, m.thoroughfare, m.subThoroughfare]
            for p in parts {
                if let x = p, !x.isEmpty { s += x }
            }
            if let n = m.name, !n.isEmpty, s.range(of: n) == nil {
                s += "[" + n + "]"
            }
            if s.isEmpty { return }
            DispatchQueue.main.async {
                self.places[key] = s
            }
        }
    }

    // MARK: 回放

    private func togglePlay() {
        if playing {
            stopTimer()
            return
        }
        guard raw.count >= 2 else { return }
        if Int(idx) >= raw.count - 1 { idx = 0 }
        playing = true
        timer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { _ in
            DispatchQueue.main.async {
                if Int(self.idx) >= self.raw.count - 1 {
                    self.stopTimer()
                    return
                }
                self.idx = self.idx + 1
            }
        }
    }

    private func stopTimer() {
        playing = false
        if let t = timer {
            t.invalidate()
            timer = nil
        }
    }
}

// MARK: - 4. GPS 功能设置页

/// 原版这一页就三行开关加两个按钮。三个开关对应的车机字段在安卓包里能查到
/// （config.devcfg.privacy、parseVstStatus 里的 gps_opn / gps_cls），但写入走哪条
/// 指令码没找到实证 —— iOS 包的主二进制是加密的，读不出来。所以这一版：
///   · 开关的状态记在本机，下次进来还在；
///   · 「查询」真去问一次车机（203100），把结果回显；
///   · 「保存」如实告诉用户：这一版还没接车机的写入通道。
/// 宁可少发，也不能瞎发一条配置指令把车机参数改坏。
struct GpsSetPage: View {

    @EnvironmentObject var e: AutoEngine

    var onBack: () -> Void

    @State private var gpsOn = Store.shared.flag("dev_gps_on", true)
    @State private var fenceOn = Store.shared.flag("dev_fence_on", true)
    @State private var privacy = Store.shared.flag("dev_privacy", false)
    @State private var hint = ""
    @State private var busy = false

    var body: some View {
        VStack(spacing: 0) {
            PageTopBar(title: "GPS功能设置", onBack: onBack)

            VStack(spacing: 1) {
                switchRow("GPS开关", $gpsOn)
                switchRow("电子围栏", $fenceOn)
                switchRow("隐私模式", $privacy)
            }
            .background(UI.line)
            .padding(.top, 10)

            HStack(spacing: 56) {
                blueBtn("查询") { query() }
                blueBtn("保存") { save() }
            }
            .padding(.top, 28)

            if !hint.isEmpty {
                Text(hint)
                    .font(.system(size: 12))
                    .foregroundColor(UI.dim)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, 24)
                    .padding(.top, 16)
            }

            Spacer(minLength: 0)
        }
        .background(UI.bg)
    }

    private func switchRow(_ label: String, _ bind: Binding<Bool>) -> some View {
        HStack(spacing: 10) {
            Text(label)
                .font(.system(size: 15))
                .foregroundColor(UI.text)
            Spacer(minLength: 0)
            Toggle("", isOn: bind)
                .labelsHidden()
                .toggleStyle(SwitchToggleStyle(tint: UI.accent))
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 11)
        .background(UI.card)
    }

    private func blueBtn(_ title: String, _ act: @escaping () -> Void) -> some View {
        Button {
            act()
        } label: {
            Text(title)
                .font(.system(size: 16))
                .foregroundColor(.white)
                .frame(width: 108, height: 42)
                .background(busy ? UI.dim : UI.accent)
                .cornerRadius(6)
                .contentShape(Rectangle())
        }
        .buttonStyle(PlainButtonStyle())
    }

    private func query() {
        if busy { return }
        busy = true
        hint = "正在问车机…"
        e.refreshStatus { c in
            self.busy = false
            guard let c = c else {
                self.hint = "没查到。车机可能没在线，稍后再试。"
                return
            }
            var s = "已查到：最后定位 " + mpStamp(c.reportedAt)
            if !c.volt.isEmpty { s += " · 电压 " + c.volt + "V" }
            if !c.temp.isEmpty { s += " · " + c.temp + "°" }
            self.hint = s
            self.e.log("▶ GPS功能设置：查询成功")
        }
    }

    private func save() {
        Store.shared.putFlag("dev_gps_on", gpsOn)
        Store.shared.putFlag("dev_fence_on", fenceOn)
        Store.shared.putFlag("dev_privacy", privacy)
        hint = "开关已记在手机上。这三项属于车机固件设置，写入指令还没接通 —— "
            + "原版走的是车机协议，码在加密的 iOS 包里读不出来，硬发可能把车机参数改坏。"
        e.log("▶ GPS功能设置：保存 GPS=" + String(gpsOn)
              + " 围栏=" + String(fenceOn) + " 隐私=" + String(privacy))
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
                HStack(spacing: 14) {
                    AppLogo.view(62, radius: 15)
                    VStack(alignment: .leading, spacing: 5) {
                        Text("五菱控车")
                            .font(.system(size: 28, weight: .bold))
                            .foregroundColor(UI.text)
                        Text("iOS 版 · 蓝牙直连 + 网络兜底")
                            .font(.system(size: 12))
                            .foregroundColor(UI.dim)
                    }
                    Spacer(minLength: 0)
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

                VStack(spacing: 3) {
                    Text("作者：胖胖胖")
                        .font(.system(size: 11))
                        .foregroundColor(UI.dim)
                    Text("微信：zhengyongfu")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(UI.dim.opacity(0.85))
                }
                .frame(maxWidth: .infinity)
                .padding(.top, 4)
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
