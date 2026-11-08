import Foundation

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
