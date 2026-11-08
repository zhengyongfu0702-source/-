import Foundation

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
