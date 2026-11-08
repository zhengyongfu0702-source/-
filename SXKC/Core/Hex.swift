import Foundation

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
