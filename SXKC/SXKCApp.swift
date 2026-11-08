import SwiftUI

@main
struct SXKCApp: App {
    @StateObject private var engine = AutoEngine.shared
    @Environment(\.scenePhase) private var phase

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(engine)
                .preferredColorScheme(.dark)
                .onChange(of: phase) { p in
                    // 没有定时器之后，网络兜底就靠这一次「回到前台」。
                    // 后台只吃蓝牙事件，能不动射频就不动。
                    if p == .active {
                        engine.onForeground()
                    }
                }
        }
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
