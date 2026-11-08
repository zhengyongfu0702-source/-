import SwiftUI
import UIKit
import CoreBluetooth

struct DiagView: View {
    @EnvironmentObject var e: AutoEngine
    @Environment(\.presentationMode) var presentation

    @State private var hexInput = ""
    @State private var calibrating = false
    @State private var calLeft = 0
    @State private var calSamples: [Int] = []
    @State private var calTimer: Timer?

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 14) {
                    scanCard
                    deviceCard
                    linkCard
                    quickCard
                    calibCard
                    diagConsole
                }
                .padding(16)
                .padding(.bottom, 24)
            }
            .background(UI.bg.ignoresSafeArea())
            .navigationTitle("蓝牙诊断")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("关闭") {
                        calTimer?.invalidate()
                        presentation.wrappedValue.dismiss()
                    }
                    .foregroundColor(UI.accent)
                }
            }
        }
        .navigationViewStyle(.stack)
        .onAppear { e.startDiagScan() }
        .onDisappear {
            calTimer?.invalidate()
            e.stopDiagScan()
        }
    }

    // MARK: 扫描

    private var scanCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                SectionTitle(text: "扫描")
                HStack(spacing: 10) {
                    GhostButton(title: e.diagScanning ? "正在扫描…" : "全量扫描",
                                color: UI.accent) {
                        e.startDiagScan()
                    }
                    GhostButton(title: "停止", color: UI.dim) {
                        e.stopDiagScan()
                    }
                }
                Text("iOS 拿不到 MAC 地址，只能看到系统分配的 UUID。带 FFE0 标记的就是本车。")
                    .font(.system(size: 11))
                    .foregroundColor(UI.dim)
                    .lineSpacing(3)
            }
        }
    }

    // MARK: 设备列表

    private var deviceCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    SectionTitle(text: "设备 \(e.diagDevices.count)")
                    Spacer()
                    Text("按信号排序").font(.system(size: 11)).foregroundColor(UI.dim)
                }
                if e.diagDevices.isEmpty {
                    Text("还没有扫到设备")
                        .font(.system(size: 12))
                        .foregroundColor(UI.dim)
                }
                ForEach(e.diagDevices) { d in
                    Button {
                        e.connectDiag(d)
                    } label: {
                        HStack(spacing: 10) {
                            VStack(alignment: .leading, spacing: 3) {
                                HStack(spacing: 6) {
                                    Text(d.name.isEmpty ? "未命名" : d.name)
                                        .font(.system(size: 14, weight: .semibold))
                                        .foregroundColor(UI.text)
                                    if d.hasCarSvc {
                                        Text("FFE0")
                                            .font(.system(size: 10, weight: .bold))
                                            .foregroundColor(.white)
                                            .padding(.horizontal, 5)
                                            .padding(.vertical, 2)
                                            .background(Capsule().fill(UI.ok))
                                    }
                                }
                                Text(d.id.uuidString)
                                    .font(.system(size: 9, design: .monospaced))
                                    .foregroundColor(UI.dim)
                                    .lineLimit(1)
                            }
                            Spacer()
                            Text("\(d.rssi)")
                                .font(.system(size: 13, weight: .semibold, design: .monospaced))
                                .foregroundColor(d.rssi > -75 ? UI.ok : UI.dim)
                        }
                        .padding(.vertical, 8)
                        .contentShape(Rectangle())
                    }
                }
            }
        }
    }

    // MARK: 连接与 GATT

    private var linkCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                SectionTitle(text: "连接")
                HStack(spacing: 14) {
                    badge(e.connected ? "已连接" : "未连接", e.connected ? UI.ok : UI.dim)
                    badge("RSSI \(e.rssi)", e.rssi > -120 ? UI.text : UI.dim)
                    badge(batteryText, UI.dim)
                }
                if e.connected {
                    GhostButton(title: "断开连接", color: UI.bad) {
                        e.ble.disconnect()
                    }
                }
                if !e.diagServices.isEmpty {
                    Divider().background(UI.line)
                    SectionTitle(text: "服务 \(e.diagServices.count)")
                    ForEach(e.diagServices, id: \.self) { s in
                        Text("  \(s)")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(s.uppercased().contains("FFE0") ? UI.ok : UI.dim)
                    }
                }
            }
        }
    }

    private var batteryText: String {
        let b = e.ble.batteryLevel
        return b >= 0 ? "电池 \(b)%" : "电池 --"
    }

    private func badge(_ t: String, _ c: Color) -> some View {
        Text(t)
            .font(.system(size: 12, weight: .semibold))
            .foregroundColor(c)
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(Capsule().fill(UI.cardHi))
    }

    // MARK: 快捷指令

    private var quickCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                SectionTitle(text: "快捷帧")
                Text("握手会在连上后自动完成；下面两个按钮直接下发控制帧（自动派生 btrand）。")
                    .font(.system(size: 11))
                    .foregroundColor(UI.dim)
                    .lineSpacing(3)

                HStack(spacing: 10) {
                    GhostButton(title: "开锁帧", color: UI.accent) { e.diagControl(unlock: true) }
                    GhostButton(title: "锁车帧", color: UI.warn) { e.diagControl(unlock: false) }
                }

                HStack(spacing: 8) {
                    TextField("HEX，如 FF12…", text: $hexInput)
                        .font(.system(size: 12, design: .monospaced))
                        .autocapitalization(.allCharacters)
                        .disableAutocorrection(true)
                        .padding(10)
                        .background(RoundedRectangle(cornerRadius: 8).fill(UI.cardHi))
                        .foregroundColor(UI.text)
                    Button("发送") {
                        e.sendHex(hexInput)
                    }
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundColor(.white)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 10)
                    .background(RoundedRectangle(cornerRadius: 8).fill(UI.accent))
                }
            }
        }
    }

    // MARK: 距离标定

    private var calibCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                SectionTitle(text: "距离标定")
                Text("站在车前 1 米处点开始，保持不动，30 秒后看记录的平均值。用它来定「开锁信号门限」。")
                    .font(.system(size: 11))
                    .foregroundColor(UI.dim)
                    .lineSpacing(3)

                if calibrating {
                    Text("采样中… 剩余 \(calLeft)s　当前 \(e.rssi)dBm　样本 \(calSamples.count)")
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundColor(UI.accent)
                    GhostButton(title: "停止", color: UI.bad) { stopCalib() }
                } else {
                    GhostButton(title: "开始 30 秒标定", color: UI.accent) { startCalib() }
                }

                if !calSamples.isEmpty {
                    Text(summary())
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundColor(UI.text)
                }
            }
        }
    }

    private func startCalib() {
        guard e.connected else {
            e.log("✗ 先连上车机再标定")
            return
        }
        calibrating = true
        calLeft = 30
        calSamples = []
        calTimer?.invalidate()
        calTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { t in
            e.ble.readRssi(force: true)
            calSamples.append(e.rssi)
            calLeft -= 1
            if calLeft <= 0 {
                t.invalidate()
                calibrating = false
                e.log("标定完成：" + summary())
            }
        }
    }

    private func stopCalib() {
        calTimer?.invalidate()
        calibrating = false
        e.log("标定中止：" + summary())
    }

    private func summary() -> String {
        let valid = calSamples.filter { $0 < 0 && $0 > -120 }
        guard !valid.isEmpty else { return "样本无效" }
        let avg = valid.reduce(0, +) / valid.count
        let lo = valid.min() ?? 0
        let hi = valid.max() ?? 0
        return "平均 \(avg)dBm　最低 \(lo)　最高 \(hi)　样本 \(valid.count)"
    }

    // MARK: 日志

    private var diagConsole: some View {
        Card {
            VStack(alignment: .leading, spacing: 8) {
                SectionTitle(text: "日志")
                HStack(spacing: 8) {
                    GhostButton(title: "后台日志", color: UI.accent) {
                        e.readRunLog()
                    }
                    GhostButton(title: "复制", color: UI.dim) {
                        UIPasteboard.general.string = e.logs.joined(separator: "\n")
                        e.log("· 已复制 \(e.logs.count) 行到剪贴板")
                    }
                    GhostButton(title: "清空", color: UI.dim) {
                        e.clearLog()
                    }
                }
                Text("「清空」只清界面；App 被系统回收后，只有落盘那份还能找回。")
                    .font(.system(size: 10))
                    .foregroundColor(UI.dim)
                Button {
                    e.clearRunLog()
                } label: {
                    Text("删除落盘日志文件")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(UI.bad)
                }
                ScrollView {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(Array(e.logs.enumerated()), id: \.offset) { _, line in
                            Text(line)
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundColor(UI.text.opacity(0.8))
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                }
                .frame(height: 200)
            }
        }
    }
}
