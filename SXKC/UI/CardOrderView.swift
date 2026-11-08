import SwiftUI

/// 卡片顺序与显示。用系统的 `List` + `onMove`，拖动手感就是 iOS 原生的那一套，
/// 不需要自己写手势（自研手势在后台恢复、长按与滚动抢事件这些地方很容易出问题）。
///
/// 拖动把手在右侧、显示开关在左侧：两者刻意分开放，避免手指打架。
/// 改一下立刻写本地并回到主界面生效，不设「保存」按钮 —— 多一次点击没有意义。
struct CardOrderView: View {
    @Environment(\.presentationMode) private var pm

    @State private var list: [CardID] = Cards.order
    @State private var hidden: Set<String> = Cards.hidden

    var body: some View {
        NavigationView {
            List {
                Section(
                    header: Text("按住右侧把手拖动排序"),
                    footer: Text("只有打开的卡片会显示在主界面。左侧开关只管显示，数据和功能都还在。"),
                ) {
                    ForEach(list, id: \.self) { c in
                        row(c)
                    }
                    .onMove(perform: move)
                }

                Section {
                    Button {
                        Cards.reset()
                        list = Cards.order
                        hidden = Cards.hidden
                    } label: {
                        Text("恢复默认顺序，全部显示")
                            .foregroundColor(UI.accent)
                    }
                }
            }
            .listStyle(GroupedListStyle())
            // 常开编辑态：直接就能拖，不用先点「编辑」
            .environment(\.editMode, .constant(.active))
            .navigationTitle("卡片")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("完成") { pm.wrappedValue.dismiss() }
                        .foregroundColor(UI.accent)
                }
            }
        }
        .navigationViewStyle(.stack)
    }

    private func row(_ c: CardID) -> some View {
        HStack(spacing: 12) {
            Toggle("", isOn: Binding(
                get: { !hidden.contains(c.rawValue) },
                set: { on in
                    // 最后一张不给关：关完主界面一片空白，比不给关更糟
                    if !on && list.filter({ !hidden.contains($0.rawValue) }).count <= 1 {
                        return
                    }
                    if on {
                        hidden.remove(c.rawValue)
                    } else {
                        hidden.insert(c.rawValue)
                    }
                    Cards.hidden = hidden
                }
            ))
            .labelsHidden()
            .toggleStyle(SwitchToggleStyle(tint: UI.accent))

            VStack(alignment: .leading, spacing: 2) {
                Text(c.title)
                    .font(.system(size: 15))
                    .foregroundColor(hidden.contains(c.rawValue) ? UI.dim : UI.text)
                Text(c.hint)
                    .font(.system(size: 10))
                    .foregroundColor(UI.dim)
                    .lineLimit(1)
            }

            Spacer(minLength: 0)
        }
        .padding(.vertical, 2)
        .listRowBackground(UI.card)
    }

    private func move(from: IndexSet, to: Int) {
        list.move(fromOffsets: from, toOffset: to)
        Cards.order = list
    }
}
