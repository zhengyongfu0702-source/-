import Foundation

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

    /// 这一帧是不是「事件帧」而不是「周期帧」。
    ///
    /// 实车日志里绝大多数状态帧的 body[3] 是 0x00（3 秒一帧的心跳），
    /// 但开锁后 10 秒、长时间停放后各出现过一次 body[3]=0x0F，其余字节结构也不同。
    /// 这很可能就是车门 / 遥控事件的入口 —— 门位大概率藏在这类帧里。
    ///
    /// 现在只做识别与记录（整帧 hex 进日志），不动任何动作。
    static func isEventBody(_ body: [UInt8]) -> Bool {
        return body.count > 3 && body[3] != 0x00
    }
}
