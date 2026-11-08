import Foundation
import UIKit
import UserNotifications

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
        center.setNotificationCategories([cat])

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
