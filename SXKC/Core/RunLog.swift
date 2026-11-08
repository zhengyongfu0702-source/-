import Foundation

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
