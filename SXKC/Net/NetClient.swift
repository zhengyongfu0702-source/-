import Foundation

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
