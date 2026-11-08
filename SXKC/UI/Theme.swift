import SwiftUI

/// 深色车载风格的基础配色与小组件
enum UI {
    static let bg = Color(red: 0.047, green: 0.059, blue: 0.078)
    static let card = Color(red: 0.086, green: 0.106, blue: 0.137)
    static let cardHi = Color(red: 0.114, green: 0.141, blue: 0.180)
    static let line = Color.white.opacity(0.08)
    static let text = Color(red: 0.925, green: 0.941, blue: 0.961)
    static let dim = Color.white.opacity(0.45)
    static let accent = Color(red: 0.231, green: 0.510, blue: 0.965)
    static let warn = Color(red: 0.961, green: 0.620, blue: 0.043)
    static let ok = Color(red: 0.133, green: 0.773, blue: 0.369)
    static let bad = Color(red: 0.937, green: 0.267, blue: 0.267)
}

struct Card<Content: View>: View {
    let content: Content
    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }
    var body: some View {
        content
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .fill(UI.card)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .stroke(UI.line, lineWidth: 1)
            )
    }
}

struct SectionTitle: View {
    let text: String
    var body: some View {
        Text(text)
            .font(.system(size: 13, weight: .semibold))
            .foregroundColor(UI.dim)
            .tracking(0.5)
    }
}

/// 大圆角主操作按钮
struct BigButton: View {
    let title: String
    let subtitle: String
    let color: Color
    var enabled: Bool = true
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(spacing: 6) {
                Text(title)
                    .font(.system(size: 22, weight: .bold))
                Text(subtitle)
                    .font(.system(size: 12))
                    .opacity(0.7)
            }
            .foregroundColor(.white)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 22)
            .background(
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .fill(color.opacity(enabled ? 1 : 0.35))
            )
        }
        .disabled(!enabled)
    }
}

/// 描边的小按钮（网络备用通道）
struct GhostButton: View {
    let title: String
    let color: Color
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(title)
                .font(.system(size: 14, weight: .semibold))
                .foregroundColor(color)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 12)
                .background(
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .stroke(color.opacity(0.55), lineWidth: 1.2)
                )
        }
    }
}

/// 带数值滑条
struct SliderRow: View {
    let title: String
    let unit: String
    @Binding var value: Double
    let range: ClosedRange<Double>
    let step: Double
    let hint: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(title).font(.system(size: 14, weight: .medium)).foregroundColor(UI.text)
                Spacer()
                Text("\(Int(value))\(unit)")
                    .font(.system(size: 14, weight: .semibold, design: .monospaced))
                    .foregroundColor(UI.accent)
            }
            Slider(value: $value, in: range, step: step)
                .accentColor(UI.accent)
            Text(hint)
                .font(.system(size: 11))
                .foregroundColor(UI.dim)
        }
    }
}
