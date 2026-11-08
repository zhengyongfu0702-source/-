import SwiftUI
import UserNotifications

@main
struct SXKCApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var engine = AutoEngine.shared
    @Environment(\.scenePhase) private var phase

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(engine)
                .preferredColorScheme(.dark)
                .onChange(of: phase) { p in
                    // 没有定时器之后，网络兜底就靠这一次「回到前台」。
                    if p == .active {
                        engine.onForeground()
                    } else if p == .background {
                        engine.onBackground()
                    }
                }
        }
    }
}

/// 通知代理。
///
/// 两件事必须在这里做，SwiftUI 的 App 生命周期里没有对应的钩子：
/// 1. **前台也显示**：默认前台收到的本地通知是静默的，自动锁车就白发了；
/// 2. **「手动锁车」按钮**：连续 3 次没锁上时，点通知上的按钮直接在后台再锁一次，
///    不用先解锁手机、找到 App、再翻按钮 —— 那几秒钟可能正好是车门被拉开的几秒。
final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        return true
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                willPresent notification: UNNotification,
                                withCompletionHandler completionHandler:
                                    @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .list, .sound])
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        if response.actionIdentifier == Notify.actionManualLock {
            DispatchQueue.main.async {
                AutoEngine.shared.manualLockNow()
            }
        }
        completionHandler()
    }
}

struct RootView: View {
    @EnvironmentObject var e: AutoEngine

    var body: some View {
        Group {
            if e.signedIn {
                MainView()
            } else {
                LoginView()
            }
        }
        .background(UI.bg.ignoresSafeArea())
    }
}
