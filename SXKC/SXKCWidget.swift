import WidgetKit
import SwiftUI

// MARK: - 数据

struct SXEntry: TimelineEntry {
    let date: Date
    let snap: SharedKit.Snapshot
}

struct SXProvider: TimelineProvider {

    func placeholder(in context: Context) -> SXEntry {
        SXEntry(date: Date(),
                snap: SharedKit.Snapshot(armed: true, armedKnown: true,
                                         connected: true, distance: 42,
                                         updatedAt: Date().timeIntervalSince1970,
                                         lastResult: "开锁成功（蓝牙）"))
    }

    func getSnapshot(in context: Context, completion: @escaping (SXEntry) -> Void) {
        completion(SXEntry(date: Date(), snap: SharedKit.load()))
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<SXEntry>) -> Void) {
        let e = SXEntry(date: Date(), snap: SharedKit.load())
        // 15 分钟只是兜底。真正让小组件变新的，是主 App 每次状态变化时
        // 调用的 WidgetCenter.reloadAllTimelines()——锁车、开关门、距离变化都会触发。
        completion(Timeline(entries: [e],
                            policy: .after(Date().addingTimeInterval(15 * 60))))
    }
}

// MARK: - 界面

struct SXWidgetView: View {

    @Environment(\.widgetFamily) private var family
    var entry: SXEntry

    private var snap: SharedKit.Snapshot { entry.snap }

    // 配色跟主界面保持一致：绿=已锁、橙=未锁、灰=未知
    private let cOk = Color(red: 0.133, green: 0.773, blue: 0.369)
    private let cWarn = Color(red: 0.961, green: 0.620, blue: 0.043)
    private let cDim = Color.white.opacity(0.45)

    private var stateText: String {
        if !snap.armedKnown { return "状态未知" }
        return snap.armed ? "已锁车" : "未锁车"
    }

    private var stateColor: Color {
        if !snap.armedKnown { return cDim }
        return snap.armed ? cOk : cWarn
    }

    private var distText: String {
        if snap.distance < 0 { return "--" }
        if snap.distance < 1000 { return String(format: "%.0f", snap.distance) }
        return String(format: "%.1f", snap.distance / 1000)
    }

    private var distUnit: String {
        if snap.distance < 0 { return "距离未知" }
        return snap.distance < 1000 ? "米" : "公里"
    }

    /// 快照有多旧。主 App 不跑了，小组件就停在最后一帧上，
    /// 这里必须如实写出来，不能让用户以为是刚读到的。
    private var agoText: String {
        guard snap.updatedAt > 0 else { return "还没同步过" }
        let d = Date().timeIntervalSince1970 - snap.updatedAt
        if d < 60 { return "刚刚同步" }
        if d < 3600 { return "\(Int(d / 60)) 分钟前" }
        if d < 86400 { return "\(Int(d / 3600)) 小时前" }
        return "\(Int(d / 86400)) 天前"
    }

    var body: some View {
        Group {
            if family == .systemSmall {
                smallBody
            } else {
                mediumBody
            }
        }
        .widgetBackground(
            LinearGradient(colors: [Color(red: 0.106, green: 0.129, blue: 0.169),
                                    Color(red: 0.047, green: 0.059, blue: 0.078)],
                           startPoint: .topLeading,
                           endPoint: .bottomTrailing)
        )
    }

    // MARK: 小尺寸

    private var smallBody: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 5) {
                Circle().fill(stateColor).frame(width: 8, height: 8)
                Text(stateText)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundColor(stateColor)
                    .lineLimit(1)
                Spacer(minLength: 0)
            }

            Spacer(minLength: 4)

            HStack(alignment: .lastTextBaseline, spacing: 3) {
                Text(distText)
                    .font(.system(size: 30, weight: .bold, design: .rounded))
                    .foregroundColor(.white)
                    .minimumScaleFactor(0.6)
                    .lineLimit(1)
                Text(distUnit)
                    .font(.system(size: 11))
                    .foregroundColor(cDim)
            }

            Spacer(minLength: 4)

            HStack(spacing: 6) {
                Link(destination: SharedKit.unlockURL) {
                    Text("开锁")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 6)
                        .background(RoundedRectangle(cornerRadius: 8, style: .continuous)
                                        .fill(cWarn.opacity(0.85)))
                }
                Link(destination: SharedKit.lockURL) {
                    Text("锁车")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 6)
                        .background(RoundedRectangle(cornerRadius: 8, style: .continuous)
                                        .fill(cOk.opacity(0.85)))
                }
            }
        }
    }

    // MARK: 中尺寸

    private var mediumBody: some View {
        VStack(alignment: .leading, spacing: 0) {

            HStack {
                Text("顺心控车")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(cDim)
                    .tracking(0.4)
                Spacer()
                HStack(spacing: 5) {
                    Circle().fill(stateColor).frame(width: 7, height: 7)
                    Text(stateText)
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundColor(stateColor)
                }
            }

            Spacer(minLength: 6)

            HStack(alignment: .lastTextBaseline, spacing: 5) {
                Text(distText)
                    .font(.system(size: 34, weight: .bold, design: .rounded))
                    .foregroundColor(.white)
                    .minimumScaleFactor(0.6)
                    .lineLimit(1)
                Text(distUnit)
                    .font(.system(size: 12))
                    .foregroundColor(cDim)

                Spacer(minLength: 6)

                VStack(alignment: .trailing, spacing: 2) {
                    Text(snap.connected ? "蓝牙已连" : "蓝牙未连")
                        .font(.system(size: 10))
                        .foregroundColor(snap.connected ? cOk : cDim)
                    Text(agoText)
                        .font(.system(size: 9))
                        .foregroundColor(cDim.opacity(0.8))
                }
            }

            if !snap.lastResult.isEmpty {
                Text(snap.lastResult)
                    .font(.system(size: 10))
                    .foregroundColor(cDim)
                    .lineLimit(1)
                    .padding(.top, 2)
            }

            Spacer(minLength: 6)

            HStack(spacing: 8) {
                Link(destination: SharedKit.unlockURL) {
                    Text("开锁")
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 7)
                        .background(RoundedRectangle(cornerRadius: 9, style: .continuous)
                                        .fill(cWarn.opacity(0.85)))
                }
                Link(destination: SharedKit.lockURL) {
                    Text("锁车")
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 7)
                        .background(RoundedRectangle(cornerRadius: 9, style: .continuous)
                                        .fill(cOk.opacity(0.85)))
                }
            }
        }
    }
}

// MARK: - iOS 17 的背景规则
//
// iOS 17 起，小组件必须用 containerBackground 铺底，用 .background 会被系统
// 套上一层默认底色。这里两个分支都写上，14 / 15 / 16 / 17 都能正常显示。

extension View {
    @ViewBuilder
    func widgetBackground<V: View>(_ v: V) -> some View {
        if #available(iOS 17.0, *) {
            containerBackground(for: .widget) { v }
        } else {
            background(v)
        }
    }
}

// MARK: - 入口

@main
struct SXWidget: Widget {
    var body: some WidgetConfiguration {
        StaticConfiguration(kind: "SXKCWidget", provider: SXProvider()) { entry in
            SXWidgetView(entry: entry)
                .padding(0)
        }
        .configurationDisplayName("开关锁与距离")
        .description("显示车辆锁止状态和距车距离，点一下就能开锁或锁车。")
        .supportedFamilies([.systemSmall, .systemMedium])
    }
}
