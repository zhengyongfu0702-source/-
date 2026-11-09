import Foundation

/// 主 App 与小组件共享的一份「当前状态」快照。
///
/// iOS 的 App 和 Widget 扩展是**两个独立进程**：内存不互通，普通的
/// `UserDefaults.standard` 也各自一份。唯一能共享的是 App Group 容器。
/// 所以流程只能是：
///
///     主 App 状态一变 → 把快照写进 App Group → 小组件读出来画界面
///
/// 没有 App Group 就没法共享，这是 iOS 的硬限制，不是实现上偷懒。
/// 读不到时返回 `.empty`，小组件会显示「状态未知」，而不是编一个假状态出来——
/// 一个停在旧数据的「已锁车」，比明写「未知」危险得多。
///
/// 这个文件同时编进主 App 和小组件两个 target（见 project.yml），
/// 保证两边用的是同一套字段名和同一个 group id。
enum SharedKit {

    /// 必须和 project.yml 里 entitlements 的 group 一字不差
    static let groupId = "group.cn.sxkc.lite"

    private static let key = "sxkc.widget.snapshot"

    struct Snapshot: Codable, Equatable {
        /// 车锁上没锁上
        var armed: Bool
        /// 这个值是不是真的拿到过（没收到状态帧时是 false）
        var armedKnown: Bool
        /// 蓝牙连没连上
        var connected: Bool
        /// 距车多少米，< 0 表示未知
        var distance: Double
        /// 快照写入时刻（秒级时间戳），小组件用它算「几分钟前」
        var updatedAt: Double
        /// 最近一次操作结果，比如「开锁成功（蓝牙）」
        var lastResult: String

        static let empty = Snapshot(armed: false, armedKnown: false,
                                    connected: false, distance: -1,
                                    updatedAt: 0, lastResult: "")
    }

    static var defaults: UserDefaults? {
        UserDefaults(suiteName: groupId)
    }

    /// 有没有收到过主 App 写下的快照。
    ///
    /// 注意别用 `UserDefaults(suiteName:) != nil` 来判断 App Group 通不通 ——
    /// 那个调用即使容器不存在也会返回一个对象，永远非 nil，测不出来。
    /// 真正的判据是「里面有没有数据」：一直 false 说明要么 App Group 没生效，
    /// 要么主 App 从没连上过车。
    static var hasData: Bool {
        load().updatedAt > 0
    }

    static func save(_ s: Snapshot) {
        guard let d = defaults else { return }
        if let data = try? JSONEncoder().encode(s) {
            d.set(data, forKey: key)
        }
    }

    static func load() -> Snapshot {
        guard let d = defaults,
              let data = d.data(forKey: key),
              let s = try? JSONDecoder().decode(Snapshot.self, from: data) else {
            return .empty
        }
        return s
    }

    // MARK: 小组件按钮的跳转地址
    //
    // 小组件没法自己连蓝牙：系统不给 Widget 长连 BLE 的机会，而这台车机
    // 平时不广播、必须主动连才扫得到。所以按钮做的事情只能是「把 App 拉起来」，
    // 由 App 去真正下发开锁 / 锁车指令。这不是偷懒，是 iOS 的边界。

    static let unlockURL = URL(string: "sxkc://unlock")!
    static let lockURL = URL(string: "sxkc://lock")!
    static let openURL = URL(string: "sxkc://open")!
}
