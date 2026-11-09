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
//
// 排版原则（1.23 重写）：
//
// 1. **所有文字 lineLimit(1) + minimumScaleFactor**。小组件的容器宽度由系统给，
//    我们估算不准；一旦某段文字按自己的理想宽度撑开，整块内容就会比容器宽，
//    SwiftUI 不改尺寸而是**居中溢出**——表现就是左右两边都被切掉一截
//    （旧版标题左边缺字、右上「状态未知」右边缺字，就是这么来的）。
// 2. **按钮给固定高度**，不用 vertical padding 撑。padding 撑出来的高度
//    跟着字号和动态字体变，动态字体一放大，按钮就顶出小组件下沿。
// 3. **.frame 加在 Link 外面**，不加在 Link 里面的 Text 上。Link 会按自己算出的
//    理想尺寸参与布局，里面再写 maxWidth: .infinity 容易和它打架。
// 4. 距离未知时不再拼「-- 距离未知」两段，直接换一句 15 号的「距离未知」。

struct SXWidgetView: View {

    @Environment(\.widgetFamily) private var family
    var entry: SXEntry

    private var snap: SharedKit.Snapshot { entry.snap }

    // 配色跟主界面保持一致：绿=已锁、橙=未锁、灰=未知
    private let cOk = Color(red: 0.133, green: 0.773, blue: 0.369)
    private let cWarn = Color(red: 0.961, green: 0.620, blue: 0.043)
    private let cDim = Color.white.opacity(0.45)
    private let cFaint = Color.white.opacity(0.30)

    private var stateText: String {
        if !snap.armedKnown { return "状态未知" }
        return snap.armed ? "已锁车" : "未锁车"
    }

    private var stateColor: Color {
        if !snap.armedKnown { return cDim }
        return snap.armed ? cOk : cWarn
    }

    /// 距离未知时单独走一句话，不要拿 "--" 去占那个大字号的位置
    private var distKnown: Bool { return snap.distance >= 0 }

    private var distMain: String {
        if snap.distance < 1000 { return String(format: "%.0f", snap.distance) }
        return String(format: "%.1f", snap.distance / 1000)
    }

    private var distUnit: String { return snap.distance < 1000 ? "米" : "公里" }

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

    private var linkText: String { return snap.connected ? "已连接" : "未连接" }

    private var linkColor: Color { return snap.connected ? cOk : cFaint }

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
                Circle().fill(stateColor).frame(width: 7, height: 7)
                Text(stateText)
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundColor(stateColor)
                    .lineLimit(1)
                    .minimumScaleFactor(0.7)
                Spacer(minLength: 0)
            }
            .frame(height: 16)

            Spacer(minLength: 2)

            // 距离：已知走大数字，未知就一句话，避免 "--" 和单位挤成两块
            Group {
                if distKnown {
                    HStack(alignment: .lastTextBaseline, spacing: 3) {
                        Text(distMain)
                            .font(.system(size: 27, weight: .bold, design: .rounded))
                            .foregroundColor(.white)
                            .lineLimit(1)
                            .minimumScaleFactor(0.6)
                        Text(distUnit)
                            .font(.system(size: 10))
                            .foregroundColor(cDim)
                            .lineLimit(1)
                    }
                } else {
                    Text("距离未知")
                        .font(.system(size: 15, weight: .medium))
                        .foregroundColor(cDim)
                        .lineLimit(1)
                        .minimumScaleFactor(0.8)
                }
            }
            .frame(height: 32, alignment: .leading)

            HStack(spacing: 6) {
                Circle().fill(linkColor).frame(width: 5, height: 5)
                Text(linkText)
                    .font(.system(size: 9))
                    .foregroundColor(cFaint)
                    .lineLimit(1)
                Spacer(minLength: 0)
            }
            .frame(height: 12)

            Spacer(minLength: 4)

            HStack(spacing: 6) {
                actionLink("开锁", url: SharedKit.unlockURL, color: cWarn, height: 28)
                actionLink("锁车", url: SharedKit.lockURL, color: cOk, height: 28)
            }
        }
    }

    // MARK: 中尺寸

    private var mediumBody: some View {
        VStack(alignment: .leading, spacing: 0) {

            // 第一行：名字 + 状态。名字给固定宽度优先级，避免和右边的状态互挤
            HStack(spacing: 6) {
                Text("五菱控车")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(cDim)
                    .tracking(0.3)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
                Spacer(minLength: 4)
                Circle().fill(stateColor).frame(width: 7, height: 7)
                Text(stateText)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundColor(stateColor)
                    .lineLimit(1)
                    .minimumScaleFactor(0.7)
            }
            .frame(height: 18)

            Spacer(minLength: 2)

            // 第二行：距离（左）+ 蓝牙与同步时间（右）
            HStack(alignment: .bottom, spacing: 8) {

                Group {
                    if distKnown {
                        HStack(alignment: .lastTextBaseline, spacing: 3) {
                            Text(distMain)
                                .font(.system(size: 28, weight: .bold, design: .rounded))
                                .foregroundColor(.white)
                                .lineLimit(1)
                                .minimumScaleFactor(0.6)
                            Text(distUnit)
                                .font(.system(size: 11))
                                .foregroundColor(cDim)
                                .lineLimit(1)
                        }
                    } else {
                        Text("距离未知")
                            .font(.system(size: 16, weight: .medium))
                            .foregroundColor(cDim)
                            .lineLimit(1)
                            .minimumScaleFactor(0.8)
                    }
                }
                .frame(height: 34, alignment: .bottomLeading)

                Spacer(minLength: 4)

                VStack(alignment: .trailing, spacing: 3) {
                    HStack(spacing: 4) {
                        Circle().fill(linkColor).frame(width: 5, height: 5)
                        Text(linkText)
                            .font(.system(size: 10))
                            .foregroundColor(cFaint)
                            .lineLimit(1)
                    }
                    Text(agoText)
                        .font(.system(size: 9))
                        .foregroundColor(cFaint.opacity(0.85))
                        .lineLimit(1)
                }
                .fixedSize(horizontal: true, vertical: false)
            }

            Spacer(minLength: 4)

            if !snap.lastResult.isEmpty {
                Text(snap.lastResult)
                    .font(.system(size: 10))
                    .foregroundColor(cDim)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
                    .frame(height: 13, alignment: .leading)
            }

            Spacer(minLength: 4)

            HStack(spacing: 8) {
                actionLink("开锁", url: SharedKit.unlockURL, color: cWarn, height: 30)
                actionLink("锁车", url: SharedKit.lockURL, color: cOk, height: 30)
            }
        }
    }

    // MARK: 按钮

    /// 小组件里的按钮。
    ///
    /// 高度是**写死的**，不靠 vertical padding 撑：padding 撑出来的高度会跟着
    /// 动态字体一起变，用户一开大字模式，按钮就顶出小组件下沿（旧版就是这样）。
    @ViewBuilder
    private func actionLink(_ title: String, url: URL, color: Color, height: CGFloat) -> some View {
        Link(destination: url) {
            Text(title)
                .font(.system(size: 13, weight: .semibold))
                .foregroundColor(.white)
                .lineLimit(1)
                .minimumScaleFactor(0.8)
                .frame(maxWidth: .infinity)
                .frame(height: height)
                .background(
                    RoundedRectangle(cornerRadius: 8, style: .continuous)
                        .fill(color.opacity(0.9))
                )
        }
        // frame 加在 Link 外面：Link 会按自己的理想尺寸参与布局，
        // 里面再写 maxWidth: .infinity 容易和它打架，撑宽整块内容。
        .frame(maxWidth: .infinity, minHeight: height, maxHeight: height)
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
        }
        .configurationDisplayName("开关锁与距离")
        .description("显示车辆锁止状态和距车距离，点一下就能开锁或锁车。")
        .supportedFamilies([.systemSmall, .systemMedium])
    }
}
