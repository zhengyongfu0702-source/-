import SwiftUI

struct MainView: View {
    @EnvironmentObject var e: AutoEngine

    @State private var thr: Double = Double(Store.shared.thr)
    @State private var bleThr: Double = Double(Store.shared.bleLockThr)
    @State private var geoNear: Double = Store.shared.geoNearM
    @State private var showSettings = false
    @State private var showLogout = false
    @State private var showEngine = false
    @State private var engineStart = true
    /// 同一个视图上挂两个 .sheet，在 iOS 14 上只有第一个会生效。
    /// 所以这里用一个可选的枚举统一驱动，而不是两个 isPresented。
    @State private var sheet: SheetKind?

    private enum SheetKind: Int, Identifiable {
        case diag, cards
        var id: Int { return rawValue }
    }

    /// 版本号从 Bundle 读，装完一眼能确认是哪一版，不用去系统设置里翻
    static var versionText: String {
        let info = Bundle.main.infoDictionary
        let v = (info?["CFBundleShortVersionString"] as? String) ?? "?"
        let b = (info?["CFBundleVersion"] as? String) ?? "?"
        return "顺心控车 Lite  v\(v) (\(b))"
    }

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
                    // 顺序和显隐来自 Cards（本地存储），不再是写死的九块。
                    // 关掉排序页回来时 showCards 变化会触发重算，这里就会重排。
                    ForEach(Cards.visible, id: \.self) { id in
                        cardView(id)
                    }

                    Button {
                        sheet = .cards
                    } label: {
                        Text("卡片顺序 · 显示与隐藏")
                            .font(.system(size: 12))
                            .foregroundColor(UI.dim)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 10)
                    }
                }
                .padding(16)
                .padding(.bottom, 24)
            }
            .background(UI.bg.ignoresSafeArea())
            .navigationTitle("顺心控车")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("卡片") { sheet = .cards }
                        .foregroundColor(UI.accent)
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("诊断") { sheet = .diag }
                        .foregroundColor(UI.accent)
                }
            }
            .sheet(item: $sheet) { kind in
                if kind == .diag {
                    DiagView().environmentObject(e)
                } else {
                    CardOrderView()
                }
            }
        }
        .navigationViewStyle(.stack)
    }

    /// 卡片 id → 视图。新增卡片只改这里和 Cards 的枚举，主界面不用动。
    @ViewBuilder
    private func cardView(_ id: CardID) -> some View {
        switch id {
        case .status:  statusCard
        case .actions: actionCard
        case .loc:     locCard
        case .auto:    autoCard
        case .wash:    washCard
        case .stats:   statsCard
        case .slider:  sliderCard
        case .console: consoleCard
        case .account: accountCard
        }
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
                    statItem("判据",
                             e.geoActive ? "定位" : "蓝牙",
                             e.geoActive ? UI.ok : UI.dim)
                }

                if !e.distText.isEmpty {
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Text(e.distText)
                            .font(.system(size: 15, weight: .medium))
                            .foregroundColor(e.geoActive ? UI.ok : UI.dim)
                        Spacer()
                        Text(e.locText)
                            .font(.system(size: 11))
                            .foregroundColor(UI.dim)
                    }
                }

                if !e.lastResult.isEmpty {
                    Text(e.lastResult)
                        .font(.system(size: 12))
                        .foregroundColor(UI.dim)
                }

                // 门位还没逆出来。这里如实写「未知」，而不是留空让人以为门是关的：
                // 「门没关严就落锁」是所有方案都强调的问题，宁可显示未知也不能假装正常。
                Text(e.doorText)
                    .font(.system(size: 10))
                    .foregroundColor(UI.dim.opacity(0.85))
            }
        }
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
                BigButton(title: "开锁", subtitle: "双通道竞速", color: UI.accent) {
                    e.manual(unlock: true)
                }
                BigButton(title: "锁车", subtitle: "双通道竞速", color: UI.warn) {
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
            HStack(spacing: 10) {
                GhostButton(title: "一键启动", color: UI.ok) {
                    engineStart = true
                    showEngine = true
                }
                GhostButton(title: "熄火", color: UI.dim) {
                    engineStart = false
                    showEngine = true
                }
            }
            Text("定位可用时走网络，失败自动转蓝牙；定位不可用时仍是蓝牙优先。"
                + "最后的两个按钮走网络，人在车外也能用。")
                .font(.system(size: 11))
                .foregroundColor(UI.dim)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .alert(isPresented: $showEngine) {
            Alert(
                title: Text(engineStart ? "远程启动发动机？" : "远程熄火？"),
                message: Text(engineStart
                              ? "请确认车停在安全位置、档位在 P 挡、周围没有人。启动后车辆会保持怠速。"
                              : "行驶中熄火会失去助力，请确认车已停稳。"),
                primaryButton: .destructive(Text(engineStart ? "启动" : "熄火")) {
                    if engineStart { e.startEngine() } else { e.stopEngine() }
                },
                secondaryButton: .cancel(Text("取消"))
            )
        }
    }

    // MARK: 定位

    /// 定位设置。放两个开关：总开关（决定「按距离判」还是「按信号判」）、
    /// 后台开关（决定锁屏后还算不算距离）。
    private var locCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("定位判距")
                            .font(.system(size: 15, weight: .semibold))
                            .foregroundColor(UI.text)
                        Text("按车辆定位算真实距离：\(Int(Store.shared.geoNearM)) 米内开锁，超过 \(Int(Store.shared.geoFarM)) 米锁车")
                            .font(.system(size: 11))
                            .foregroundColor(UI.dim)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer()
                    Toggle("", isOn: Binding(
                        get: { e.geoEnabled },
                        set: { e.setGeoEnabled($0) }
                    ))
                    .labelsHidden()
                    .toggleStyle(SwitchToggleStyle(tint: UI.accent))
                }

                Divider().background(UI.line)

                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("后台持续定位")
                            .font(.system(size: 15, weight: .semibold))
                            .foregroundColor(UI.text)
                        Text("锁屏后也能判距并自动开关锁。耗电明显增加，系统状态栏会出现定位箭头。")
                            .font(.system(size: 11))
                            .foregroundColor(UI.dim)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer()
                    Toggle("", isOn: Binding(
                        get: { e.locBackground },
                        set: { e.setLocBackground($0) }
                    ))
                    .labelsHidden()
                    .toggleStyle(SwitchToggleStyle(tint: UI.accent))
                }

                Text(e.distText.isEmpty ? "还没有定位数据" : e.distText)
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(e.geoActive ? UI.ok : UI.dim)

                Text(e.locText)
                    .font(.system(size: 11))
                    .foregroundColor(UI.dim)
            }
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
                        Text("定位可用时按真实距离判；不可用时连上车机判开锁、断开即锁")
                            .font(.system(size: 11))
                            .foregroundColor(UI.dim)
                            .fixedSize(horizontal: false, vertical: true)
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

                Divider().background(UI.line)

                toggleRow("双通道竞速",
                          "开锁 / 锁车时蓝牙与网络同时下发，谁先回执算谁。两条都是幂等指令，不会多锁一次。",
                          isOn: Binding(get: { e.raceEnabled }, set: { e.setRace($0) }))

                toggleRow("离车较远时降低定位精度",
                          "300 米外降到粗略定位，回到车附近自动升到 GPS 高频。精度只在需要时花钱。",
                          isOn: Binding(get: { e.fenceEnabled }, set: { e.setFence($0) }))

                toggleRow("通知与震动",
                          "自动锁车发一条带距离的通知，开锁轻震一下；连续 3 次锁不上会发强提醒。",
                          isOn: Binding(get: { e.notifyEnabled }, set: { e.setNotify($0) }))

                toggleRow("门没关好不锁车",
                          "车机会报门位。有门开着就不下发锁车指令，关好后自动补锁，并弹一条可「仍然锁车」的提醒。",
                          isOn: Binding(get: { e.doorGuardEnabled }, set: { e.setDoorGuard($0) }))
            }
        }
    }

    private func toggleRow(_ title: String, _ hint: String, isOn: Binding<Bool>) -> some View {
        HStack(alignment: .center) {
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.system(size: 14, weight: .medium))
                    .foregroundColor(UI.text)
                Text(hint)
                    .font(.system(size: 10))
                    .foregroundColor(UI.dim)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            Toggle("", isOn: isOn)
                .labelsHidden()
                .toggleStyle(SwitchToggleStyle(tint: UI.accent))
        }
    }

    // MARK: 洗车 / 代客模式

    private var washCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                SectionTitle(text: "洗车 / 代客模式")

                Text("洗车、代客泊车时车辆会反复移动，自动判定就会不停开锁关锁。暂停期间只停自动逻辑，手动按钮照常可用；到点自动恢复。")
                    .font(.system(size: 11))
                    .foregroundColor(UI.dim)
                    .fixedSize(horizontal: false, vertical: true)

                Text(e.washText.isEmpty ? "当前：未开启" : "当前：\(e.washText)")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundColor(e.washText.isEmpty ? UI.dim : UI.ok)

                HStack(spacing: 10) {
                    GhostButton(title: "暂停 30 分钟", color: UI.accent) {
                        e.setWash(minutes: 30)
                    }
                    GhostButton(title: "立即恢复", color: UI.dim) {
                        e.setWash(minutes: 0)
                    }
                }
            }
        }
    }

    // MARK: 开锁表现（罚站率）

    private var statsCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    SectionTitle(text: "开锁表现")
                    Spacer()
                    Button("清空") { e.resetStats() }
                        .font(.system(size: 12))
                        .foregroundColor(UI.dim)
                }

                Text(e.statsText.isEmpty ? Stats.summary() : e.statsText)
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(UI.text)
                    .fixedSize(horizontal: false, vertical: true)

                Text("罚站率 =（超过 3 秒才开 + 没开成）/ 总次数。行业参考：UWB 约 1%，纯蓝牙约 10%。只统计自动开锁。")
                    .font(.system(size: 10))
                    .foregroundColor(UI.dim)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    // MARK: 参数

    private var sliderCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 20) {
                SectionTitle(text: "距离与延时")

                SliderRow(title: "靠近门限",
                          unit: " 米",
                          value: $geoNear,
                          range: 5 ... 30,
                          step: 1,
                          hint: "定位算出的直线距离小于它就算「在车旁」。离开门限自动取它的 2 倍（\(Int(geoNear * 2)) 米），中间这段是死区，专门吃掉 GPS 抖动。")

                SliderRow(title: "开锁信号门限",
                          unit: " dBm",
                          value: $thr,
                          range: -95 ... -45,
                          step: 1,
                          hint: "定位用不了时才看这一项：信号强于此值才算「靠近」。后台拿不到信号时，只要连上车机就按「在附近」处理。")

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
        .onChange(of: geoNear) { v in
            Store.shared.geoNearM = v
            // 离开门限跟着走，保持「至少 2 倍」，否则死区会被挤没
            Store.shared.geoFarM = max(v * 2, v + 10)
        }
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

                Text(MainView.versionText)
                    .font(.system(size: 11))
                    .foregroundColor(UI.dim.opacity(0.8))
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
