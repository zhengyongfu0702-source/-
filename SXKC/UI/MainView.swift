import SwiftUI

struct MainView: View {
    @EnvironmentObject var e: AutoEngine

    @State private var thr: Double = Double(Store.shared.thr)
    @State private var bleThr: Double = Double(Store.shared.bleLockThr)
    @State private var showDiag = false
    @State private var showSettings = false
    @State private var showLogout = false

    private var armedText: String {
        if !e.armedKnown { return "状态未知" }
        return e.armed ? "已锁车" : "未锁车"
    }

    private var armedColor: Color {
        if !e.armedKnown { return UI.dim }
        return e.armed ? UI.ok : UI.warn
    }

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 14) {
                    statusCard
                    actionCard
                    autoCard
                    sliderCard
                    consoleCard
                    accountCard
                }
                .padding(16)
                .padding(.bottom, 24)
            }
            .background(UI.bg.ignoresSafeArea())
            .navigationTitle("顺心控车")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("诊断") { showDiag = true }
                        .foregroundColor(UI.accent)
                }
            }
            .sheet(isPresented: $showDiag) {
                DiagView().environmentObject(e)
            }
        }
        .navigationViewStyle(.stack)
    }

    // MARK: 状态

    private var statusCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 14) {
                HStack(alignment: .firstTextBaseline) {
                    Text(armedText)
                        .font(.system(size: 26, weight: .bold))
                        .foregroundColor(armedColor)
                    Spacer()
                    if e.acting {
                        HStack(spacing: 6) {
                            ProgressView().progressViewStyle(CircularProgressViewStyle(tint: UI.accent))
                            Text("执行中").font(.system(size: 12)).foregroundColor(UI.dim)
                        }
                    }
                }

                Text(e.devName.isEmpty ? "未绑定车辆" : e.devName)
                    .font(.system(size: 13))
                    .foregroundColor(UI.dim)

                Divider().background(UI.line)

                HStack(spacing: 18) {
                    statItem("蓝牙",
                             e.connected ? "已连接" : "未连接",
                             e.connected ? UI.ok : UI.dim)
                    statItem("信号",
                             e.rssi > -120 ? "\(e.rssi) dBm" : "--",
                             e.rssi >= Int(thr) ? UI.ok : UI.dim)
                    statItem("距离档", distanceText, UI.dim)
                }

                if !e.lastResult.isEmpty {
                    Text(e.lastResult)
                        .font(.system(size: 12))
                        .foregroundColor(UI.dim)
                }
            }
        }
    }

    private var distanceText: String {
        let r = e.rssi
        if r > -55 { return "很近 <1m" }
        if r > -65 { return "近 1~3m" }
        if r > -75 { return "中 3~8m" }
        if r > -85 { return "远 8~15m" }
        if r > -120 { return "很远 >15m" }
        return "--"
    }

    private func statItem(_ t: String, _ v: String, _ c: Color) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(t).font(.system(size: 11)).foregroundColor(UI.dim)
            Text(v).font(.system(size: 14, weight: .semibold)).foregroundColor(c)
        }
    }

    // MARK: 操作

    private var actionCard: some View {
        VStack(spacing: 10) {
            HStack(spacing: 10) {
                BigButton(title: "开锁", subtitle: "蓝牙优先", color: UI.accent) {
                    e.manual(unlock: true)
                }
                BigButton(title: "锁车", subtitle: "蓝牙优先", color: UI.warn) {
                    e.manual(unlock: false)
                }
            }
            HStack(spacing: 10) {
                GhostButton(title: "网络开锁", color: UI.accent) {
                    e.netOnly(unlock: true)
                }
                GhostButton(title: "网络锁车", color: UI.warn) {
                    e.netOnly(unlock: false)
                }
            }
            Text("蓝牙连不上时会自动转网络；右边的两个按钮只走网络，用于手动兜底。")
                .font(.system(size: 11))
                .foregroundColor(UI.dim)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    // MARK: 自动模式

    private var autoCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("自动靠近开锁 / 离开落锁")
                            .font(.system(size: 15, weight: .semibold))
                            .foregroundColor(UI.text)
                        Text("事件驱动：连上车机判开锁，蓝牙断开即锁车")
                            .font(.system(size: 11))
                            .foregroundColor(UI.dim)
                    }
                    Spacer()
                    Toggle("", isOn: Binding(
                        get: { e.running },
                        set: { on in
                            if on { e.start() } else { e.stop() }
                        }
                    ))
                    .labelsHidden()
                    .toggleStyle(SwitchToggleStyle(tint: UI.accent))
                }

                if !e.powerText.isEmpty {
                    Text(e.powerText)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(UI.ok)
                }

                if e.armedKnown && e.rssi > -120 {
                    Text(e.connected
                         ? "已连车机，信号 \(e.rssi)dBm，门限 \(Int(thr))dBm"
                         : "未连接，到达车边会自动重连")
                        .font(.system(size: 11))
                        .foregroundColor(UI.dim)
                }
            }
        }
    }

    // MARK: 参数

    private var sliderCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 20) {
                SectionTitle(text: "距离与延时")

                SliderRow(title: "开锁信号门限",
                          unit: " dBm",
                          value: $thr,
                          range: -95 ... -45,
                          step: 1,
                          hint: "信号强于此值才算「靠近」。后台拿不到信号时，只要连上车机就按「在附近」处理。")

                VStack(alignment: .leading, spacing: 6) {
                    Text("离开判定：蓝牙一断开就锁车")
                        .font(.system(size: 14, weight: .medium))
                        .foregroundColor(UI.text)
                    Text("iOS 后台没有可靠的定时器，做不了「离开 30 秒再锁」。只在本次到访确实开过锁时才会锁，"
                        + "刚锁完、车辆在行驶、或正在执行别的指令时都会跳过。")
                        .font(.system(size: 11))
                        .foregroundColor(UI.dim)
                        .fixedSize(horizontal: false, vertical: true)
                }

                SliderRow(title: "蓝牙锁车最远信号",
                          unit: " dBm",
                          value: $bleThr,
                          range: -95 ... -70,
                          step: 1,
                          hint: "断开时信号若还强于此值，先尝试蓝牙锁车；否则直接走网络。")

                Button {
                    e.refreshStatus()
                } label: {
                    Text("刷新车辆状态")
                        .font(.system(size: 14, weight: .medium))
                        .foregroundColor(UI.accent)
                }
            }
        }
        .onChange(of: thr) { v in Store.shared.thr = Int(v) }
        .onChange(of: bleThr) { v in Store.shared.bleLockThr = Int(v) }
    }

    // MARK: 日志

    private var consoleCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    SectionTitle(text: "运行日志")
                    Spacer()
                    Button("清空") { e.clearLog() }
                        .font(.system(size: 12))
                        .foregroundColor(UI.dim)
                }
                ScrollViewReader { proxy in
                    ScrollView {
                        VStack(alignment: .leading, spacing: 2) {
                            ForEach(Array(e.logs.enumerated()), id: \.offset) { idx, line in
                                Text(line)
                                    .font(.system(size: 11, design: .monospaced))
                                    .foregroundColor(logColor(line))
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .id(idx)
                            }
                        }
                    }
                    .frame(height: 190)
                    .onChange(of: e.logs.count) { _ in
                        if let last = e.logs.indices.last {
                            withAnimation { proxy.scrollTo(last, anchor: .bottom) }
                        }
                    }
                }
            }
        }
    }

    private func logColor(_ s: String) -> Color {
        if s.contains("✗") { return UI.bad }
        if s.contains("✓") { return UI.ok }
        if s.contains("◇") || s.contains("▶") { return UI.accent }
        if s.contains("⚠︎") { return UI.warn }
        return UI.text.opacity(0.82)
    }

    // MARK: 账号

    /// 换账号的入口。刻意放在最底下：日常用车不该被它干扰，但要找的时候一定找得到。
    ///
    /// 这里不提供「同时忘记车机」：iOS 只认系统分配的 identifier，车机又不广播，
    /// 一旦清掉很可能再也扫不回来（Android 还能按 MAC 重连，iOS 没这条路）。
    private var accountCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                SectionTitle(text: "账号")

                HStack(alignment: .center) {
                    Text(e.accountText.isEmpty ? "未登录" : e.accountText)
                        .font(.system(size: 16, weight: .semibold))
                        .foregroundColor(UI.text)
                    Spacer()
                    Button {
                        showLogout = true
                    } label: {
                        Text("退出登录")
                            .font(.system(size: 13, weight: .medium))
                            .foregroundColor(UI.bad)
                            .padding(.horizontal, 14)
                            .padding(.vertical, 7)
                            .background(
                                RoundedRectangle(cornerRadius: 14, style: .continuous)
                                    .stroke(UI.bad.opacity(0.45), lineWidth: 1)
                            )
                    }
                }

                Text("换账号请先退出登录。已记住的车机会保留，不用重新配对。")
                    .font(.system(size: 11))
                    .foregroundColor(UI.dim)
            }
        }
        .actionSheet(isPresented: $showLogout) {
            ActionSheet(
                title: Text("退出登录"),
                message: Text("当前账号 \(e.accountText)\n\n"
                    + "退出后会关闭自动模式、断开蓝牙并清除登录信息，下次使用要重新输入密码。"),
                buttons: [
                    .destructive(Text("退出登录")) { e.logout() },
                    .cancel(Text("取消"))
                ]
            )
        }
    }
}
