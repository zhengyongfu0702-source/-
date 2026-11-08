import Foundation
import CoreBluetooth

protocol BleCentralDelegate: AnyObject {
    func bleLog(_ b: BleCentral, _ s: String)
    func bleLink(_ b: BleCentral, _ s: String)
    func bleRssi(_ b: BleCentral, _ rssi: Int)
    func bleArmed(_ b: BleCentral, _ armed: Bool)
    func bleDone(_ b: BleCentral, ok: Bool, msg: String)
    func bleConnected(_ b: BleCentral, _ connected: Bool)
    /// 诊断页：扫描到设备
    func bleDiscovered(_ b: BleCentral, _ p: CBPeripheral, rssi: Int, adv: [String: Any])
    /// 诊断页：服务枚举完成
    func bleServices(_ b: BleCentral, _ services: [CBService])
}

extension BleCentralDelegate {
    func bleLog(_ b: BleCentral, _ s: String) {}
    func bleLink(_ b: BleCentral, _ s: String) {}
    func bleRssi(_ b: BleCentral, _ rssi: Int) {}
    func bleArmed(_ b: BleCentral, _ armed: Bool) {}
    func bleDone(_ b: BleCentral, ok: Bool, msg: String) {}
    func bleConnected(_ b: BleCentral, _ connected: Bool) {}
    func bleDiscovered(_ b: BleCentral, _ p: CBPeripheral, rssi: Int, adv: [String: Any]) {}
    func bleServices(_ b: BleCentral, _ services: [CBService]) {}
}

/// 蓝牙通道（iOS 重写版）。
///
/// ## 与 Android 版最本质的差别
///
/// Android 能拿到车机 MAC `99:99:16:20:C3:0D` 并按地址直连；**iOS 不允许**。
/// CoreBluetooth 从系统层面屏蔽了 MAC，扫描只返回 `CBPeripheral.identifier`
/// ——一个在本机生成、会随系统重装/抹机变化的 UUID。
///
/// 所以定位方式改成两级：
/// 1. 首次：扫描 → 连上 → 校验 0xFFE0/0xFFE1 指纹 → 把 identifier 存进 UserDefaults；
/// 2. 以后：`retrievePeripherals(withIdentifiers:)` 直接取回对象并 `connect()`。
///
/// 第 2 步不依赖广播包内容，所以即使车机广播里不带 0xFFE0 也能连
/// ——这也正是 Android 那套「记住地址」思路在 iOS 上唯一等价的做法。
///
/// 一次动作的时序（实测）：连接 0.5s → 发现服务 0.4s → 订阅 0.05s →
/// 握手 0.1s → 回执 0.1s。已连状态下开锁只剩「握手 + 指令」约 0.2s。
final class BleCentral: NSObject {

    static let svcCar = CBUUID(string: "FFE0")
    static let chrCar = CBUUID(string: "FFE1")
    static let svcBattery = CBUUID(string: "180F")
    static let chrBattery = CBUUID(string: "2A19")
    private static let restoreId = "cn.sxkc.ios.central"

    private static let CONNECT_TIMEOUT_MS: Int = 10000

    // MARK: 状态

    weak var delegate: BleCentralDelegate?

    private(set) var central: CBCentralManager!
    private(set) var peripheral: CBPeripheral?
    private var chr: CBCharacteristic?
    private var batteryChr: CBCharacteristic?

    private(set) var ready = false
    private(set) var busy = false
    private(set) var connected = false
    private(set) var rssi = -127
    private(set) var battery = -1

    private var btkey: [UInt8]?
    private var busKey: [UInt8]?
    private var tid = ""
    private var seq = 1

    private var keepAlive = false
    private var wantUnlock = false
    private var done = false
    private var hsTries = 0
    private var lastRssiAt: Int64 = 0
    private var lastAttemptAt: Int64 = 0
    private var lastSeen: Int64 = 0
    private var lastLoggedMissing = ""
    private var lastArmedLog: Bool? = nil

    /// 每次动作递增，用于让旧定时器失效
    private var gen = 0

    private var scanning = false
    private var sawAnyDevice = false
    private(set) var diagMode = false

    /// 用户手动清空的日志位置（诊断页）
    var connectHint = ""

    // MARK: 生命周期

    override init() {
        super.init()
        central = CBCentralManager(delegate: self,
                                   queue: .main,
                                   options: [CBCentralManagerOptionRestoreIdentifierKey: BleCentral.restoreId])
    }

    func configure(tid: String, btkeyHex: String) {
        self.tid = tid
        if !btkeyHex.isEmpty {
            let k = Hex.to(btkeyHex)
            if k.count == 16 { btkey = k }
        }
        if let s = savedUuid, let p = central?.retrievePeripherals(withIdentifiers: [s]).first {
            if peripheral == nil {
                peripheral = p
                p.delegate = self
            }
        }
    }

    func setKeepAlive(_ on: Bool) {
        keepAlive = on
    }

    var hasSavedTarget: Bool {
        return savedUuid != nil
    }

    var savedName: String {
        return Store.shared.str(StoreKey.peripheralName)
    }

    private var savedUuid: UUID? {
        let s = Store.shared.str(StoreKey.peripheralId)
        return UUID(uuidString: s)
    }

    var lastSeenMs: Int64 { return lastSeen }
    var isConnected: Bool { return connected }
    var isReady: Bool { return ready && peripheral != nil }
    var chargerCharacteristic: CBCharacteristic? { return batteryChr }
    var batteryLevel: Int { return battery }

    // MARK: - 连接

    /// 需要时连上去；已连或正在连则什么都不做
    func ensureConnected() {
        guard central.state == .poweredOn else {
            logOnce("no-bt", "蓝牙未开启或未授权蓝牙权限")
            return
        }
        if let p = peripheral {
            if p.state == .connected { return }
            if p.state == .connecting { return }
            let now = CarAPI.nowMs()
            if now - lastAttemptAt < 4000 { return }
            lastAttemptAt = now
            p.delegate = self
            connectHint = p.name ?? p.identifier.uuidString
            log("重连车机 \(connectHint)")
            central.connect(p, options: nil)
            scheduleConnectTimeout()
            return
        }
        if let u = savedUuid,
           let p = central.retrievePeripherals(withIdentifiers: [u]).first {
            peripheral = p
            p.delegate = self
            lastAttemptAt = CarAPI.nowMs()
            log("连接已记住的车机 \(p.name ?? u.uuidString)")
            central.connect(p, options: nil)
            scheduleConnectTimeout()
            return
        }
        // 没有任何记录 → 只能扫一遍把车机找出来
        startScan(filtered: true)
    }

    func disconnect() {
        gen += 1          // 让所有挂起的超时回调失效
        scanning = false
        central.stopScan()
        if let p = peripheral {
            central.cancelPeripheralConnection(p)
        }
        peripheral = nil
        chr = nil
        ready = false
        connected = false
        busKey = nil
        rssi = -127
        log("断开蓝牙")
    }

    /// 退出登录时的清场：断链 + 清掉内存里的会话密钥。
    ///
    /// 与 `disconnect()` 的区别是这里还会清 tid / btkey / 序号，防止换账号后
    /// 残留上一账号的解密密钥；但**不动** Store 里的 `peripheralId` ——
    /// 车机平时不广播，identifier 一删可能就再也找不回来了（iOS 没有 MAC 可兜底）。
    func releaseSession() {
        gen += 1
        keepAlive = false
        scanning = false
        diagMode = false
        central?.stopScan()
        if let p = peripheral {
            central?.cancelPeripheralConnection(p)
        }
        peripheral = nil
        chr = nil
        batteryChr = nil
        ready = false
        connected = false
        busy = false
        done = false
        wantUnlock = false
        hsTries = 0
        tid = ""
        btkey = nil
        busKey = nil
        seq = 1
        rssi = -127
        battery = -1
        lastSeen = 0
        lastRssiAt = 0
        lastAttemptAt = 0
        lastArmedLog = nil
        lastLoggedMissing = ""
        log("已清空蓝牙会话（车机记录保留）")
    }

    private func scheduleConnectTimeout() {
        let g = gen
        DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(BleCentral.CONNECT_TIMEOUT_MS)) { [weak self] in
            guard let self = self, self.gen == g else { return }
            if !self.ready && self.peripheral != nil && !self.connected {
                self.log("连接超时，放弃本次")
                if self.busy && !self.done {
                    self.fail("连不上车机 \(self.connectHint)")
                }
                self.disconnect()
            }
        }
    }

    // MARK: - 扫描

    func startScan(filtered: Bool) {
        guard central.state == .poweredOn else { return }
        if scanning { central.stopScan() }
        scanning = true
        sawAnyDevice = false
        let services: [CBUUID]? = filtered ? [BleCentral.svcCar] : nil
        log(filtered ? "扫描车机（按 0xFFE0 服务过滤）…" : "全量扫描（不过滤）…")
        central.scanForPeripherals(withServices: services,
                                   options: [CBCentralManagerScanOptionAllowDuplicatesKey: true])

        // 过滤扫不到就退化为全量扫；全量也找不到就提示去诊断页
        if filtered {
            DispatchQueue.main.asyncAfter(deadline: .now() + 6.0) { [weak self] in
                guard let self = self, self.scanning, self.peripheral == nil, !self.sawAnyDevice else { return }
                self.log("广播里没有 0xFFE0，退化为全量扫描")
                self.startScan(filtered: false)
            }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 20.0) { [weak self] in
            guard let self = self, !self.diagMode, self.scanning, self.peripheral == nil else { return }
            self.scanning = false
            self.central.stopScan()
            self.log("扫不到车机。请到「蓝牙诊断」页全量扫描，手动连接一次，之后会自动记住")
        }
    }

    func startDiagScan() {
        diagMode = true
        startScan(filtered: false)
    }

    func stopDiagScan() {
        scanning = false
        central.stopScan()
        diagMode = false
        log("停止扫描")
    }

    /// 诊断页手动指定设备
    func connectManually(_ p: CBPeripheral) {
        diagMode = true
        scanning = false
        central.stopScan()
        if let old = peripheral, old.identifier != p.identifier {
            central.cancelPeripheralConnection(old)
        }
        peripheral = p
        p.delegate = self
        ready = false
        connected = false
        lastAttemptAt = CarAPI.nowMs()
        connectHint = p.name ?? p.identifier.uuidString
        log("手动连接 \(p.name ?? "未命名") / \(p.identifier.uuidString)")
        central.connect(p, options: nil)
        scheduleConnectTimeout()
    }

    // MARK: - 动作

    /// 执行一次开锁 / 锁车；结果通过 delegate 回传
    func perform(unlock: Bool) {
        if busy {
            finish(false, "上一条指令还在执行")
            return
        }
        guard let k = btkey, k.count == 16 else {
            finish(false, "还没有 btkey，请先登录成功一次")
            return
        }
        gen += 1
        busy = true
        done = false
        wantUnlock = unlock
        hsTries = 0

        if ready && chr != nil && busKey != nil {
            // 已连好且握过手：0.2 秒就能发出去
            sendAction()
            return
        }
        ensureConnected()
        let g = gen
        DispatchQueue.main.asyncAfter(deadline: .now() + 13.0) { [weak self] in
            guard let self = self, self.gen == g else { return }
            if self.busy && !self.done && !self.ready {
                self.fail("连不上车机，请靠近车辆再试")
            }
        }
    }

    /// 读一次 RSSI（距离判定的唯一来源；内部 800ms 节流）
    func readRssi(force: Bool = false) {
        guard let p = peripheral, p.state == .connected else { return }
        let now = CarAPI.nowMs()
        if !force && now - lastRssiAt < 800 { return }
        lastRssiAt = now
        p.readRSSI()
    }

    /// 诊断页用：直接发一段 HEX（不加密、不加帧头）
    func sendRawHex(_ s: String) {
        let bytes = Hex.to(s)
        guard !bytes.isEmpty, let p = peripheral, let c = chr else {
            log("✗ 没有连接或没有可写特征")
            return
        }
        log("直发 \(Hex.of(bytes))")
        p.writeValue(Data(bytes), for: c, type: .withResponse)
    }

    /// 诊断页用：自动派生 btrand 后发控制帧
    func sendControlFrame(unlock: Bool) {
        guard let k = btkey, k.count == 16 else {
            log("✗ 没有 btkey")
            return
        }
        let rk = Frame.btrandKey(CarAPI.nowMs())
        busKey = Hex.to(rk + "FFFF")
        let payload: [UInt8] = unlock ? [0x01] : [0x00, 0x01]
        guard let f = try? Frame.build(type: Frame.TYPE_CTRL, seq: nextSeq(),
                                       payload: payload, key: busKey!, handshake: false) else {
            log("✗ 组帧失败")
            return
        }
        write(f)
        log((unlock ? "开锁帧 " : "锁车帧 ") + Hex.of(f))
    }

    // MARK: - 握手 / 指令

    private func nextSeq() -> Int {
        seq += 1
        if seq > 0xFFFF { seq = 1 }
        return seq
    }

    private func handshake() {
        guard !ready, let c = chr, let p = peripheral, let k = btkey else { return }
        hsTries += 1
        let rk = Frame.btrandKey(CarAPI.nowMs())
        busKey = Hex.to(rk + "FFFF")
        guard let f = try? Frame.build(type: Frame.TYPE_HANDSHAKE, seq: nextSeq(),
                                       payload: Hex.to(rk), key: k, handshake: true) else {
            fail("握手组帧失败")
            return
        }
        log("握手 #\(hsTries) key=\(rk)")
        p.writeValue(Data(f), for: c, type: .withResponse)

        let g = gen
        if hsTries < 3 {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.9) { [weak self] in
                guard let self = self, self.gen == g, !self.ready, self.peripheral != nil else { return }
                self.handshake()
            }
        } else {
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) { [weak self] in
                guard let self = self, self.gen == g else { return }
                if !self.ready && self.busy && !self.done { self.fail("握手无应答") }
            }
        }
    }

    private func sendAction() {
        guard let k = busKey, let c = chr, let p = peripheral else {
            fail("业务密钥缺失")
            return
        }
        let payload: [UInt8] = wantUnlock ? [0x01] : [0x00, 0x01]
        guard let f = try? Frame.build(type: Frame.TYPE_CTRL, seq: nextSeq(),
                                       payload: payload, key: k, handshake: false) else {
            fail("指令组帧失败")
            return
        }
        p.writeValue(Data(f), for: c, type: .withResponse)
        log((wantUnlock ? "开锁 " : "锁车 ") + Hex.of(f))

        let g = gen
        DispatchQueue.main.asyncAfter(deadline: .now() + 5.0) { [weak self] in
            guard let self = self, self.gen == g else { return }
            if self.busy && !self.done { self.fail("车机未回执") }
        }
    }

    private func write(_ f: [UInt8]) {
        guard let p = peripheral, let c = chr else { return }
        p.writeValue(Data(f), for: c, type: .withResponse)
    }

    // MARK: - 收包

    private func onFrame(_ v: [UInt8]) {
        guard v.count >= 20 else { return }
        lastSeen = CarAPI.nowMs()

        // 接收方向一律先试 btrand（握手应答 / 状态帧 / 回执都是它加密的），再退回 btkey。
        // open() 内部会校验帧头与 CRC，用错密钥必然返回 nil。
        var body: [UInt8]?
        if let k = busKey { body = Frame.open(v, k) }
        if body == nil, let k = btkey { body = Frame.open(v, k) }
        guard let b = body, b.count >= 3 else { return }

        let type = Int(b[0])
        let st = Int(b[2])

        if type == Frame.TYPE_HANDSHAKE {
            if st == 0x00 {
                ready = true
                log("握手成功")
                link("蓝牙就绪")
                if busy && !done { sendAction() }
            } else {
                log("握手被拒 code=\(st)")
                if hsTries >= 2 { fail("握手被拒 code=\(st)") }
            }
        } else if type == Frame.TYPE_STATUS {
            let armed = Frame.armedOfStatusBody(b)
            // 状态帧 3 秒一帧，只在翻转时记日志，否则日志会被刷爆
            if lastArmedLog != armed {
                lastArmedLog = armed
                log("状态帧 flags=\(Frame.statusFlags(b)) \(armed ? "已锁" : "未锁")")
            }
            delegate?.bleArmed(self, armed)
            if busy && !done && armed == !wantUnlock {
                succeed(wantUnlock ? "已解锁" : "已锁车")
            }
        } else if type == Frame.TYPE_CTRL {
            if st == 0x00 {
                succeed("车机已执行")
            } else {
                fail("车机返回 \(st)")
            }
        }
    }

    // MARK: - 收尾

    private func succeed(_ msg: String) { finish(true, msg) }
    private func fail(_ msg: String) { finish(false, msg) }

    private func finish(_ ok: Bool, _ msg: String) {
        if done { return }
        done = true
        busy = false
        lastSeen = CarAPI.nowMs()
        log((ok ? "✓ " : "✗ ") + msg)
        delegate?.bleDone(self, ok: ok, msg: msg)
        if !keepAlive {
            let g = gen
            DispatchQueue.main.asyncAfter(deadline: .now() + 8.0) { [weak self] in
                guard let self = self, self.gen == g, !self.busy, !self.keepAlive else { return }
                self.disconnect()
            }
        }
    }

    // MARK: - 工具

    private func log(_ s: String) {
        delegate?.bleLog(self, s)
    }

    private func link(_ s: String) {
        delegate?.bleLink(self, s)
    }

    private func logOnce(_ key: String, _ s: String) {
        if key == lastLoggedMissing { return }
        lastLoggedMissing = key
        log(s)
    }
}

// MARK: - CBCentralManagerDelegate

extension BleCentral: CBCentralManagerDelegate {

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        switch central.state {
        case .poweredOn:
            log("蓝牙就绪")
            if keepAlive { ensureConnected() }
        case .unauthorized:
            log("✗ 蓝牙权限被拒绝：设置 → 隐私 → 蓝牙，打开本 App")
        case .poweredOff:
            log("✗ 系统蓝牙已关闭")
            connected = false
            ready = false
        case .unsupported:
            log("✗ 此设备不支持 BLE")
        default:
            break
        }
    }

    func centralManager(_ central: CBCentralManager,
                        willRestoreState dict: [String: Any]) {
        if let ps = dict[CBCentralManagerRestoredStatePeripheralsKey] as? [CBPeripheral],
           let p = ps.first {
            peripheral = p
            p.delegate = self
            connected = (p.state == .connected)
            log("后台恢复：拿回车机连接")
        }
    }

    func centralManager(_ central: CBCentralManager,
                        didDiscover peripheral: CBPeripheral,
                        advertisementData: [String: Any],
                        rssi RSSI: NSNumber) {
        sawAnyDevice = true
        let adv = advertisementData
        delegate?.bleDiscovered(self, peripheral, rssi: RSSI.intValue, adv: adv)

        let advServices = (adv[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID]) ?? []
        let hasCarSvc = advServices.contains(BleCentral.svcCar)
        let saved = savedUuid

        if diagMode {
            // 诊断页只看不连，用户手动点
            return
        }

        if let s = saved {
            if peripheral.identifier == s {
                scanning = false
                central.stopScan()
                self.peripheral = peripheral
                peripheral.delegate = self
                log("扫到已记住的车机，连接…")
                central.connect(peripheral, options: nil)
                scheduleConnectTimeout()
            }
            return
        }

        // 第一次用：认 0xFFE0 广播做指纹
        if hasCarSvc && peripheral.state == .disconnected {
            scanning = false
            central.stopScan()
            self.peripheral = peripheral
            peripheral.delegate = self
            log("发现带 0xFFE0 的设备 \(peripheral.name ?? "未命名")，连接校验…")
            central.connect(peripheral, options: nil)
            scheduleConnectTimeout()
        }
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        self.peripheral = peripheral
        connected = true
        ready = false
        rssi = -127
        log("已连接 \(peripheral.name ?? "未命名") / \(peripheral.identifier.uuidString)")
        link("发现服务…")
        delegate?.bleConnected(self, true)
        peripheral.discoverServices(nil)
    }

    func centralManager(_ central: CBCentralManager,
                        didFailToConnect peripheral: CBPeripheral,
                        error: Error?) {
        connected = false
        log("连接失败 \(error?.localizedDescription ?? "")")
        if busy && !done { fail("连接失败") }
        self.peripheral = nil
    }

    func centralManager(_ central: CBCentralManager,
                        didDisconnectPeripheral peripheral: CBPeripheral,
                        error: Error?) {
        connected = false
        ready = false
        rssi = -127
        busKey = nil
        delegate?.bleConnected(self, false)
        if busy && !done {
            fail("连接断开")
        } else {
            log("蓝牙断开 \(error?.localizedDescription ?? "")")
            link("蓝牙断开")
        }
        self.peripheral = peripheral   // 保留对象，方便下次直接 connect
    }
}

// MARK: - CBPeripheralDelegate

extension BleCentral: CBPeripheralDelegate {

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        if let e = error {
            fail("服务发现失败 \(e.localizedDescription)")
            return
        }
        let services = peripheral.services ?? []
        delegate?.bleServices(self, services)
        log("服务发现完成，共 \(services.count) 个")
        for s in services {
            log("  ├ \(s.uuid.uuidString)")
        }

        var foundCar = false
        for s in services {
            if s.uuid == BleCentral.svcCar {
                foundCar = true
                peripheral.discoverCharacteristics(nil, for: s)
            } else if s.uuid == BleCentral.svcBattery {
                peripheral.discoverCharacteristics(nil, for: s)
            }
        }
        if !foundCar {
            // 身份指纹：没有 0xFFE0/0xFFE1 就不是这台车
            log("✗ 没有 0xFFE0：这不是车机")
            fail("这台设备没有 0xFFE0/0xFFE1，不是车机")
            central.cancelPeripheralConnection(peripheral)
            self.peripheral = nil
        }
    }

    func peripheral(_ peripheral: CBPeripheral,
                    didDiscoverCharacteristicsFor service: CBService,
                    error: Error?) {
        if let e = error {
            log("特征发现失败 \(e.localizedDescription)")
            return
        }
        for c in service.characteristics ?? [] {
            log("  │ \(service.uuid.uuidString) / \(c.uuid.uuidString) \(BleCentral.props(c))")
            if c.uuid == BleCentral.chrCar {
                chr = c
                // 首次校验成功：把 identifier 记下来，以后不再依赖广播
                Store.shared.put(StoreKey.peripheralId, peripheral.identifier.uuidString)
                Store.shared.put(StoreKey.peripheralName, peripheral.name ?? "")
                log("✓ 指纹命中 0xFFE0/0xFFE1，已记住这台车机")
                peripheral.setNotifyValue(true, for: c)
            } else if c.uuid == BleCentral.chrBattery {
                batteryChr = c
                peripheral.readValue(for: c)
            }
        }
    }

    func peripheral(_ peripheral: CBPeripheral,
                    didUpdateNotificationStateFor characteristic: CBCharacteristic,
                    error: Error?) {
        if let e = error {
            fail("订阅通知失败 \(e.localizedDescription)")
            return
        }
        if characteristic.isNotifying {
            // 订阅确认一到就握手，不等固定延时
            log("已订阅通知，开始握手")
            handshake()
        }
    }

    func peripheral(_ peripheral: CBPeripheral,
                    didWriteValueFor characteristic: CBCharacteristic,
                    error: Error?) {
        if let e = error {
            log("写入失败 \(e.localizedDescription)")
        }
    }

    func peripheral(_ peripheral: CBPeripheral,
                    didUpdateValueFor characteristic: CBCharacteristic,
                    error: Error?) {
        guard let d = characteristic.value else { return }
        if characteristic.uuid == BleCentral.chrBattery {
            let b = [UInt8](d)
            if let first = b.first {
                battery = Int(first)
                log("车机电池 \(battery)%")
            }
            return
        }
        if characteristic.uuid == BleCentral.chrCar {
            onFrame([UInt8](d))
        }
    }

    func peripheral(_ peripheral: CBPeripheral,
                    didReadRSSI RSSI: NSNumber,
                    error: Error?) {
        if error != nil { return }
        rssi = RSSI.intValue
        lastSeen = CarAPI.nowMs()
        delegate?.bleRssi(self, rssi)
    }

    static func props(_ c: CBCharacteristic) -> String {
        var a: [String] = []
        let p = c.properties
        if p.contains(.read) { a.append("read") }
        if p.contains(.write) { a.append("write") }
        if p.contains(.writeWithoutResponse) { a.append("writeNR") }
        if p.contains(.notify) { a.append("notify") }
        if p.contains(.indicate) { a.append("indicate") }
        return "[" + a.joined(separator: ",") + "]"
    }
}
