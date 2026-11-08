import Foundation

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
