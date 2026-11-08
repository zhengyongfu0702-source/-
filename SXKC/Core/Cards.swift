import Foundation

/// 主界面卡片的身份。顺序与「显示 / 隐藏」存在本地，改完立刻生效。
///
/// 为什么要有这一层：卡片原本是写死在 `VStack` 里的九块，谁想把自己不看的
/// 「运行日志」挪到底下、把「手动控车」顶到最上面，只能等我改代码重新出包。
/// 现在顺序是数据，不是代码。
///
/// `allCases` 的声明顺序就是**默认顺序**，也就是 1.16 之前的写死顺序 —— 老用户
/// 升级上来看到的布局和以前一模一样，不会突然被重排。
enum CardID: String, CaseIterable {
    case status    // 车辆状态
    case actions   // 手动控车
    case loc       // 定位判距
    case auto      // 自动模式
    case wash      // 洗车 / 代客模式
    case stats     // 开锁表现
    case slider    // 距离与延时
    case console   // 运行日志
    case account   // 账号

    var title: String {
        switch self {
        case .status:  return "车辆状态"
        case .actions: return "手动控车"
        case .loc:     return "定位判距"
        case .auto:    return "自动模式"
        case .wash:    return "洗车 / 代客模式"
        case .stats:   return "开锁表现"
        case .slider:  return "距离与延时"
        case .console: return "运行日志"
        case .account: return "账号与版本"
        }
    }

    /// 一句话说明，排序页里给人看，避免只看标题不知道那张卡是干嘛的
    var hint: String {
        switch self {
        case .status:  return "锁车状态、蓝牙信号、与车的距离"
        case .actions: return "开锁 / 锁车 / 启动 / 熄火"
        case .loc:     return "定位判距开关、后台定位、当前距离"
        case .auto:    return "自动模式总开关，竞速 / 围栏 / 通知"
        case .wash:    return "洗车、代客泊车时暂停自动判定"
        case .stats:   return "罚站率、P95 耗时、各通道次数"
        case .slider:  return "靠近门限、信号门限、蓝牙锁车门限"
        case .console: return "最近运行日志，出问题先看这里"
        case .account: return "当前账号、退出登录、版本号"
        }
    }
}

enum Cards {
    private static let kOrder = "card_order"
    private static let kHidden = "card_hidden"

    private static var d: UserDefaults { UserDefaults.standard }

    /// 当前顺序。存的是逗号分隔的 rawValue。
    ///
    /// 读取时做两件事：丢掉已经不存在的 id（版本升级删过卡片时），
    /// 把新加的卡片补到末尾。这样老数据永远不会让界面漏卡或崩。
    static var order: [CardID] {
        get {
            var out: [CardID] = []
            let raw = d.string(forKey: kOrder) ?? ""
            for p in raw.split(separator: ",") {
                if let c = CardID(rawValue: String(p)), !out.contains(c) {
                    out.append(c)
                }
            }
            for c in CardID.allCases where !out.contains(c) {
                out.append(c)
            }
            return out
        }
        set {
            d.set(newValue.map { $0.rawValue }.joined(separator: ","), forKey: kOrder)
        }
    }

    static var hidden: Set<String> {
        get {
            let raw = d.string(forKey: kHidden) ?? ""
            return Set(raw.split(separator: ",").map { String($0) })
        }
        set {
            d.set(newValue.sorted().joined(separator: ","), forKey: kHidden)
        }
    }

    static func isHidden(_ c: CardID) -> Bool {
        return hidden.contains(c.rawValue)
    }

    /// 主界面真正要渲染的卡片，顺序已排好、隐藏的已剔除
    static var visible: [CardID] {
        return order.filter { !isHidden($0) }
    }

    /// 至少留一张。全关掉主界面就是一片空白，用户会以为 App 坏了。
    static func canHide(_ c: CardID) -> Bool {
        if isHidden(c) { return true }
        return visible.count > 1
    }

    static func reset() {
        d.removeObject(forKey: kOrder)
        d.removeObject(forKey: kHidden)
    }
}
