import Foundation
import CommonCrypto

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
