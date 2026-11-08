import SwiftUI

struct LoginView: View {
    @EnvironmentObject var e: AutoEngine

    @State private var user: String = Store.shared.str(StoreKey.user)
    @State private var pass: String = ""
    @State private var busy = false
    @State private var err = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("顺心控车")
                        .font(.system(size: 32, weight: .bold))
                        .foregroundColor(UI.text)
                    Text("iOS 版 · 蓝牙直连 + 网络兜底")
                        .font(.system(size: 13))
                        .foregroundColor(UI.dim)
                }
                .padding(.top, 40)

                Card {
                    VStack(alignment: .leading, spacing: 14) {
                        SectionTitle(text: "账号登录")
                        TextField("手机号 / 账号", text: $user)
                            .autocapitalization(.none)
                            .disableAutocorrection(true)
                            .keyboardType(.numberPad)
                            .padding(12)
                            .background(RoundedRectangle(cornerRadius: 10).fill(UI.cardHi))
                            .foregroundColor(UI.text)

                        SecureField("密码", text: $pass)
                            .padding(12)
                            .background(RoundedRectangle(cornerRadius: 10).fill(UI.cardHi))
                            .foregroundColor(UI.text)

                        if !err.isEmpty {
                            Text(err)
                                .font(.system(size: 12))
                                .foregroundColor(UI.bad)
                        }

                        Button {
                            submit()
                        } label: {
                            HStack {
                                if busy { ProgressView().progressViewStyle(CircularProgressViewStyle(tint: .white)) }
                                Text(busy ? "登录中…" : "登录")
                                    .font(.system(size: 16, weight: .semibold))
                            }
                            .foregroundColor(.white)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 14)
                            .background(RoundedRectangle(cornerRadius: 12).fill(UI.accent))
                        }
                        .disabled(busy || user.isEmpty || pass.isEmpty)
                    }
                }

                Card {
                    VStack(alignment: .leading, spacing: 8) {
                        SectionTitle(text: "第一次使用")
                        Text("1. 登录后拿到车机的 btkey（蓝牙密钥）\n2. 进「蓝牙诊断」，全量扫描，连上名字像车机的设备\n3. 连上后能看到 FFE0/FFE1 就是本车，会自动记住\n4. 之后主界面的开锁/锁车就会先走蓝牙")
                            .font(.system(size: 12))
                            .foregroundColor(UI.dim)
                            .lineSpacing(4)
                    }
                }
            }
            .padding(20)
        }
        .background(UI.bg.ignoresSafeArea())
    }

    private func submit() {
        busy = true
        err = ""
        e.login(user: user, password: pass) { ok, msg in
            busy = false
            if !ok { err = msg }
        }
    }
}
