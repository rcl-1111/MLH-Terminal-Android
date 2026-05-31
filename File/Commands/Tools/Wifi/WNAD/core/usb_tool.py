"""
WNAD - USB 设备检测模块
检测外部连接设备、网卡、监控插拔
跨平台: Windows / Linux / Android
"""

import os
import re
import sys
import time
import json
import subprocess
from datetime import datetime
from core.utils import C, CHECK, CROSS, INFO, WARN, ARROW, print_table, is_windows


# ── USB 设备类型分类 ──
NET_CLASSES = {
    "ethernet", "network", "wireless", "wifi", "wlan",
    "02", "0200", "0280",  # USB-IF 类代码
}
STORAGE_CLASSES = {"08", "0806", "mass storage", "storage"}
HID_CLASSES = {"03", "0301", "0302", "human interface", "hid"}


# ═══════════════════════════════════════════════
#  核心: 获取 USB 设备列表
# ═══════════════════════════════════════════════

def get_usb_devices() -> list:
    """获取所有 USB 设备列表，跨平台（带缓存）"""
    if hasattr(get_usb_devices, "_cache"):
        return get_usb_devices._cache

    devs = []

    if is_windows():
        devs = _get_usb_windows()
    else:
        devs = _get_usb_linux()

    # 去重 (按 ID)
    seen = set()
    unique = []
    for d in devs:
        key = d.get("id", d.get("name", ""))
        if key not in seen:
            seen.add(key)
            unique.append(d)

    # 缓存结果供本次会话复用
    get_usb_devices._cache = unique
    return unique


def get_network_usb_devices() -> list:
    """获取外部网卡设备"""
    all_devs = get_usb_devices()
    return [d for d in all_devs if d.get("is_net")]


# ── Windows USB 检测 ──

def _get_usb_windows() -> list:
    """Windows: 一次性获取 USB 设备和网卡信息"""
    devs = []
    seen_ids = set()

    # 合并两个查询: Get-PnpDevice + Get-NetAdapter
    try:
        r = subprocess.run(
            ["powershell", "-Command", """
                $devs = Get-PnpDevice -PresentOnly | Where-Object {
                    $_.Class -eq 'USB' -or $_.Class -eq 'Net' -or $_.Class -eq 'Ports' -or
                    $_.Class -eq 'Image' -or $_.Class -eq 'HIDClass' -or $_.Class -eq 'Bluetooth'
                } | Select-Object FriendlyName, Class, DeviceID, Status, Manufacturer
                $nics = Get-NetAdapter | Select-Object Name, InterfaceDescription
                @($devs) + @($nics) | ConvertTo-Json -Compress
            """],
            capture_output=True, text=True, timeout=15,
            encoding="utf-8", errors="replace"
        )
        if r.returncode == 0 and r.stdout.strip():
            import json
            data = json.loads(r.stdout.strip())
            if isinstance(data, dict):
                data = [data]
            for item in data:
                name = item.get("FriendlyName", "") or item.get("Name", "") or item.get("DeviceID", "")
                cls = (item.get("Class", "") or "").lower()
                dev_id = item.get("DeviceID", "").split("\\")[-1] if "\\" in item.get("DeviceID", "") else \
                         item.get("Name", item.get("DeviceID", ""))
                has_ifdesc = bool(item.get("InterfaceDescription", ""))

                # is_net 判断（严格）
                is_net = False
                if cls in ("net", "bluetooth"):
                    is_net = True
                elif has_ifdesc:
                    # 来自 Get-NetAdapter → 一定是网卡
                    is_net = True
                elif cls in ("usb", "hidclass", "ports", "image", ""):
                    # 来自 Get-PnpDevice，需要关键词判断
                    name_lower = name.lower()
                    net_kw = ["ethernet", "wireless", "wifi", "wlan", "realtek",
                              "rtl", "network adapter", "lan"]
                    is_net = any(kw in name_lower for kw in net_kw)
                if is_net and not cls:
                    cls = "Net"
                dev = {
                    "name": name,
                    "class": cls,
                    "id": dev_id,
                    "status": item.get("Status", "OK"),
                    "vendor": item.get("Manufacturer", item.get("InterfaceDescription", "")),
                    "is_net": is_net,
                    "interface": cls if cls else "USB",
                    "bus": "USB",
                }
                if dev["id"] not in seen_ids:
                    seen_ids.add(dev["id"])
                    devs.append(dev)
    except Exception:
        pass

    return devs


# ── Linux/Android USB 检测 ──

def _get_usb_linux() -> list:
    """Linux/Android: 通过 lsusb 和 sysfs 获取 USB 设备"""
    devs = []

    # 方法1: lsusb
    try:
        r = subprocess.run(
            ["lsusb"],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0:
            for line in r.stdout.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                # 格式: Bus 001 Device 001: ID 1d6b:0001 Linux Foundation 1.1 root hub
                m = re.match(
                    r'Bus\s+(\d+)\s+Device\s+(\d+):\s+ID\s+([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\s+(.+)',
                    line
                )
                if m:
                    bus = m.group(1)
                    device = m.group(2)
                    vid = m.group(3)
                    pid = m.group(4)
                    desc = m.group(5).strip()
                    # 判断是否为网卡
                    is_net = any(kw in desc.lower() for kw in
                                 ["ethernet", "wireless", "wifi", "network", "realtek",
                                  "rtl", "ax88179", "ax88", "lan", "adapter"])
                    devs.append({
                        "name": desc,
                        "class": "",
                        "id": f"{vid}:{pid}",
                        "status": "OK",
                        "vendor": desc.split()[0] if desc else "",
                        "is_net": is_net,
                        "interface": "USB",
                        "bus": f"Bus {bus}",
                        "vid": vid,
                        "pid": pid,
                        "speed": "",
                    })
    except FileNotFoundError:
        pass
    except Exception:
        pass

    # 方法2: sysfs (/sys/bus/usb/devices/) 补充信息
    try:
        usb_path = "/sys/bus/usb/devices"
        if os.path.isdir(usb_path):
            for dev_name in sorted(os.listdir(usb_path)):
                dev_path = os.path.join(usb_path, dev_name)
                if not os.path.isdir(dev_path):
                    continue
                # 跳过 root hub 和配置接口
                if "-" not in dev_name and ":" in dev_name:
                    continue
                try:
                    product = ""
                    manufacturer = ""
                    vid = ""
                    pid = ""
                    prod_file = os.path.join(dev_path, "product")
                    if os.path.isfile(prod_file):
                        with open(prod_file, errors="ignore") as f:
                            product = f.read().strip()
                    man_file = os.path.join(dev_path, "manufacturer")
                    if os.path.isfile(man_file):
                        with open(man_file, errors="ignore") as f:
                            manufacturer = f.read().strip()
                    vid_file = os.path.join(dev_path, "idVendor")
                    if os.path.isfile(vid_file):
                        with open(vid_file) as f:
                            vid = f.read().strip()
                    pid_file = os.path.join(dev_path, "idProduct")
                    if os.path.isfile(pid_file):
                        with open(pid_file) as f:
                            pid = f.read().strip()

                    if product or vid:
                        did = f"{vid}:{pid}" if vid and pid else dev_name
                        # 跳过已通过 lsusb 添加的
                        if any(d["id"] == did for d in devs):
                            continue

                        is_net = any(kw in product.lower() for kw in
                                     ["ethernet", "wireless", "wifi", "network",
                                      "lan", "adapter", "realtek"])
                        devs.append({
                            "name": product or dev_name,
                            "class": "",
                            "id": did,
                            "status": "OK",
                            "vendor": manufacturer or "",
                            "is_net": is_net,
                            "interface": "USB",
                            "bus": "sysfs",
                            "vid": vid,
                            "pid": pid,
                            "speed": "",
                        })
                except Exception:
                    continue
    except Exception:
        pass

    # 方法3: 强制检查所有网络接口中的 USB 网卡 (即使 devs 已有数据)
    try:
        net_path = "/sys/class/net"
        if os.path.isdir(net_path):
            for iface in sorted(os.listdir(net_path)):
                if iface == "lo":
                    continue
                # 收集此接口的识别信息
                vid = pid = product = driver = ""
                is_usb_net = False

                # 3a: device/uevent → USB 识别
                uevent_path = os.path.join(net_path, iface, "device", "uevent")
                if os.path.isfile(uevent_path):
                    with open(uevent_path, errors="ignore") as f:
                        content = f.read()
                    if "USB" in content or "usb" in content:
                        is_usb_net = True
                        m = re.search(r'PRODUCT=([0-9a-fA-F]+)/([0-9a-fA-F]+)', content)
                        if m:
                            vid, pid = m.group(1), m.group(2)
                    # 从 uevent 取产品名
                    m_name = re.search(r'INTERFACE_NAME=(.+)', content)
                    if m_name:
                        product = m_name.group(1).strip()

                # 3b: device/driver → 驱动名
                if not is_usb_net:
                    driver_sym = os.path.join(net_path, iface, "device", "driver")
                    if os.path.islink(driver_sym):
                        try:
                            driver = os.path.basename(os.readlink(driver_sym))
                            if driver in ("ax88179_178a", "asix", "rtl8150", "r8152",
                                          "pegasus", "cdc_ether", "rndis_host",
                                          "cdc_ncm", "cdc_eem", "smsc75xx", "smsc95xx"):
                                is_usb_net = True
                        except Exception:
                            pass

                # 3c: 按接口名猜 (usb0, eth0 等常见 USB 网卡)
                iface_lower = iface.lower()
                if not is_usb_net and iface_lower in ("usb0", "usb1", "rndis0", "eth0", "eth1"):
                    is_usb_net = True

                # 3d: 进 device 目录看 class 是否为 02 (网络)
                if not is_usb_net:
                    cls_path = os.path.join(net_path, iface, "device", "bDeviceClass")
                    if os.path.isfile(cls_path):
                        with open(cls_path) as f:
                            if f.read().strip() in ("02", "00"):
                                is_usb_net = True

                if is_usb_net:
                    did = f"{vid}:{pid}" if vid and pid else iface
                    if not any(d["id"] == did for d in devs):
                        devs.append({
                            "name": product or f"{iface} ({driver or 'USB'})",
                            "class": "Net",
                            "id": did,
                            "status": "OK",
                            "vendor": driver or "USB网卡",
                            "is_net": True,
                            "interface": "以太网",
                            "bus": iface,
                            "vid": vid,
                            "pid": pid,
                            "speed": "",
                        })
    except Exception:
        pass

    return devs


# ═══════════════════════════════════════════════
#  显示函数
# ═══════════════════════════════════════════════

def _get_iface_status(iface_name: str) -> str:
    """获取网络接口的实时状态: UP / DOWN / 未知"""
    try:
        # Linux/Android: ip link show
        r = subprocess.run(
            ["ip", "link", "show", iface_name],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0 and "state UP" in r.stdout:
            return "UP"
        if r.returncode == 0 and "state DOWN" in r.stdout:
            return "DOWN"
        if r.returncode == 0:
            return "UNKNOWN"
    except Exception:
        pass

    try:
        # Windows: Get-NetAdapter
        r = subprocess.run(
            ["powershell", "-Command",
             f"Get-NetAdapter -Name '{iface_name}' | Select-Object -ExpandProperty Status"],
            capture_output=True, text=True, timeout=5,
            encoding="utf-8", errors="replace"
        )
        if r.returncode == 0:
            raw = r.stdout.strip()
            if raw == "Up":
                return "UP"
            if raw == "Down":
                return "DOWN"
            return raw.upper() if raw else "?"
    except Exception:
        pass

    return "?"


def _is_attack_capable(dev: dict) -> tuple:
    """
    判断设备是否可用于网络攻击
    返回: (capable: bool, category: str, detail: str)
    排除: WAN Miniport / 虚拟网卡 / USB控制器等
    """
    if not dev.get("is_net"):
        return (False, "", "")

    name_lower = (dev.get("name", "") + dev.get("vendor", "") +
                  dev.get("interface", "")).lower()
    cls = (dev.get("class", "") or dev.get("interface", "")).lower()

    # ── 排除名单：虚拟/软件网卡 ──
    skip_keywords = ["wan miniport", "microsoft kernel debug",
                     "loopback", "vmware", "virtual", "hyper-v", "ms_", "kernel debug"]
    if any(kw in name_lower for kw in skip_keywords):
        return (False, "", "")

    # ── 排除 USB 控制器/Hub ──
    controller_keywords = ["root hub", "usb host", "pci to usb", "usb controller",
                           "82371", "usb 输入设备", "通信端口"]
    if any(kw in name_lower for kw in controller_keywords):
        return (False, "", "")

    # ✦ WiFi / Wireless → WiFi 攻击 (监控模式/Deauth/握手捕获)
    wifi_keywords = ["wireless", "wifi", "wlan", "rtl", "realtek", "ralink",
                     "mediatek", "broadcom", "atheros", "rt3070", "rt5370",
                     "mt7601", "mt7921", "iwlwifi", "iwl", "ac8265", "ac3160"]
    if any(kw in name_lower for kw in wifi_keywords):
        return (True, "WIFI", "WiFi 攻击: Deauth/握手捕获/监控模式")

    # ✦ USB 以太网 → 网络攻击 (ARP欺骗/嗅探/扫描)
    eth_keywords = ["ethernet", "lan", "ax88179", "asix", "r8152", "rtl8150",
                    "cdc_ether", "rndis", "usb ethernet", "usb lan", "realtek usb",
                    "gigabit", "pci express", "以太网"]
    if any(kw in name_lower for kw in eth_keywords):
        return (True, "ETH", "网络攻击: ARP欺骗/流量嗅探/端口扫描")

    # ✦ 物理网卡（非虚拟）→ 通用网络攻击
    if any(kw in name_lower for kw in ["pci", "realtek", "intel", "broadcom",
                                        "atheros", "qualcomm", "ralink"]):
        return (True, "NET", "通用网络攻击: 扫描/嗅探/ARP欺骗")

    # 蓝牙
    if "bluetooth" in name_lower or cls in ("bluetooth",):
        return (True, "BT", "蓝牙攻击 (需额外工具)")

    # 默认：不标记为攻击可用
    return (False, "", "")


def show_usb_list(devices: list = None):
    """列出 USB 设备，含状态和攻击能力标注"""
    if devices is None:
        devices = get_usb_devices()

    if not devices:
        print(f" {INFO} 未检测到 USB 设备")
        print(f" {INFO} 提示: Android 设备需要支持 {C.CYAN}OTG{C.NC} 模式")
        print(f" {INFO} 请确认:")
        print(f"   {C.YELLOW}1.{C.NC} USB转接头是 OTG 规格 (非普通充电线)")
        print(f"   {C.YELLOW}2.{C.NC} 手机已开启 OTG 功能 (部分机型需在设置中打开)")
        print(f"   {C.YELLOW}3.{C.NC} 外接设备已正确连接")
        print(f"   {C.YELLOW}4.{C.NC} 如果手机上弹出 \"传输文件\" 选项，选择 {C.GREEN}\"仅充电\"{C.NC}")
        print(f"\n {INFO} 连接后可通过 {C.CYAN}wnad usb -l{C.NC} 再次检测")
        print(f"   或使用 {C.CYAN}wnad usb --connect{C.NC} 交互式选择")
        return

    rows = []
    net_count = 0
    attack_count = 0
    _status_cache = {}  # 缓存接口状态，避免重复调用

    # Windows: 批量查询所有网卡的真实 UP/DOWN 状态
    _win_nic_status = {}
    if is_windows():
        try:
            r = subprocess.run(
                ["powershell", "-Command",
                 "Get-NetAdapter | Select-Object Name, Status, InterfaceDescription | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=10,
                encoding="utf-8", errors="replace"
            )
            if r.returncode == 0 and r.stdout.strip():
                import json
                data = json.loads(r.stdout.strip())
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    nic_name = (item.get("Name", "") or "").lower().strip()
                    nic_desc = (item.get("InterfaceDescription", "") or "").lower().strip()
                    nic_status = (item.get("Status", "") or "").lower()
                    # 按名字存
                    _win_nic_status[nic_name] = nic_status
                    # 按描述存（驱动全名，和 PnP FriendlyName 匹配）
                    if nic_desc:
                        _win_nic_status[nic_desc] = nic_status
                        # 也存截断版（FriendlyName 存到列表时可能被截断）
                        _win_nic_status[nic_desc[:30]] = nic_status
                        # 也存首词
                        first_desc_word = nic_desc.split()[0] if nic_desc else ""
                        if first_desc_word:
                            _win_nic_status[first_desc_word] = nic_status
        except Exception:
            pass

    for i, d in enumerate(devices):
        name = (d.get("name", "?") or "?")[:30]
        vid = d.get("vid", "")
        pid = d.get("pid", "")
        id_str = f"{vid}:{pid}" if vid and pid else (d.get("id", "") or "")[:15]
        bus = d.get("bus", "") or ""
        cls = d.get("class", "") or d.get("interface", "") or ""
        speed = d.get("speed", "") or ""
        _is_net = d.get("is_net", False)

        # ── 状态检测 ──
        status_display = ""
        if _is_net:
            net_count += 1
            if is_windows():
                # Windows: 从 Get-NetAdapter 查 UP/DOWN
                full_name = (d.get("name", "") or "").lower().strip()
                vendor_lower = (d.get("vendor", "") or "").lower().strip()

                # 尝试多种方式匹配 NIC 状态
                nic_st = _win_nic_status.get(full_name, "")
                if not nic_st and vendor_lower:
                    nic_st = _win_nic_status.get(vendor_lower, "")
                if not nic_st:
                    # 按首词匹配
                    first_word = full_name.split()[0] if full_name else ""
                    if first_word:
                        nic_st = _win_nic_status.get(first_word, "")
                if not nic_st:
                    # 按部分关键词匹配（遍历）
                    for key, val in _win_nic_status.items():
                        if not key or not full_name:
                            continue
                        if key in full_name or full_name[:25] in key:
                            nic_st = val
                            break

                if nic_st == "up":
                    status_display = f"{C.GREEN}UP{C.NC}"
                elif nic_st == "down":
                    status_display = f"{C.RED}DOWN{C.NC}"
                elif nic_st:
                    status_display = f"{C.DIM}{nic_st.upper()}{C.NC}"
                else:
                    status_display = f"{C.DIM}?{C.NC}"
            else:
                # Linux/Android: 快速 ip link 查状态（带缓存）
                iface_name = bus if bus and bus not in ("USB", "sysfs", "Bus") else name.split()[0]
                if iface_name not in _status_cache:
                    _status_cache[iface_name] = _get_iface_status(iface_name)
                iface_up = _status_cache[iface_name]
                if iface_up == "UP":
                    status_display = f"{C.GREEN}UP{C.NC}"
                elif iface_up == "DOWN":
                    status_display = f"{C.RED}DOWN{C.NC}"
                else:
                    status_display = f"{C.DIM}{iface_up or '?'}{C.NC}"
        else:
            status_display = f"{C.DIM}-{C.NC}"

        # ── 攻击能力标注 ──
        capable, cat, detail = _is_attack_capable(d)
        attack_tag = ""
        if capable:
            attack_count += 1
            if cat == "WIFI":
                attack_tag = f" {C.RED}{C.BOLD}[WiFi攻击]{C.NC}"
            elif cat == "ETH":
                attack_tag = f" {C.YELLOW}[网络攻击]{C.NC}"
            elif cat == "BT":
                attack_tag = f" {C.DIM}[蓝牙]{C.NC}"
            else:
                attack_tag = f" {C.CYAN}[网工工具]{C.NC}"
        else:
            attack_tag = f" {C.DIM}[-]{C.NC}"

        # 版本（USB 2.0/3.x/Type-C）
        ver_display = f"{C.DIM}{speed}{C.NC}" if speed else ""

        ent = {
            "num": i + 1,
            "name": name[:26],
            "id": id_str,
            "bus": bus,
            "cls": cls,
            "ver": ver_display,
            "status": status_display,
            "tag": attack_tag,
            "is_net": _is_net,
        }
        rows.append(ent)

    # 网卡排前面，非网卡排后面
    rows.sort(key=lambda r: (0 if r["is_net"] else 1, r["num"]))

    # 重新编号
    table_rows = []
    for idx, r in enumerate(rows):
        table_rows.append([
            str(idx + 1),
            r["name"],
            r["id"],
            r["bus"],
            r["cls"],
            r["ver"],
            r["status"],
            r["tag"],
        ])

    print(f" {CHECK} USB 设备: {len(devices)} 个 "
          f"({C.YELLOW}网卡:{net_count}{C.NC} "
          f"{C.RED}攻击可用:{attack_count}{C.NC})\n")
    print_table(["#", "设备名", "ID", "总线", "类型", "版本", "状态", "攻击适用"], table_rows)

    # 图例说明
    print(f"\n {C.DIM}图例:  {C.GREEN}UP{C.NC}=在线  {C.RED}DOWN{C.NC}=离线  {C.DIM}?{C.NC}=未知  "
          f"{C.RED}[WiFi攻击]{C.NC}=支持WiFi攻击  {C.YELLOW}[网络攻击]{C.NC}=支持网络攻击{C.NC}")
    print(f" {C.DIM}提示: WiFi攻击 = Deauth/握手捕获/监控模式  |  网络攻击 = ARP欺骗/嗅探/扫描{C.NC}")


def show_external_net_devices():
    """列出外部网卡设备（重点功能，统一使用 print_table）"""
    devs = get_network_usb_devices()

    if not devs:
        print(f" {INFO} 未检测到外部 USB 网卡")
        print(f" {INFO} 可能原因:")
        print(f"   {C.YELLOW}1.{C.NC} 未插入 USB 网卡或转接头不支持 OTG")
        print(f"   {C.YELLOW}2.{C.NC} 网卡驱动未加载 (Android 需内核支持)")
        print(f"   {C.YELLOW}3.{C.NC} USB 模式错误 (手机弹出选项请选 {C.GREEN}\"仅充电\"{C.NC})")
        print(f"\n {INFO} 若已正确连接, 检查内核模块:")
        print(f"   {C.CYAN}lsmod | grep -E 'usb|rndis|cdc_ether|asix|ax88'{C.NC}")
        return

    print(f" {CHECK} {C.GREEN}检测到 {len(devs)} 个外部网卡设备:{C.NC}\n")

    rows = []

    # 批量获取所有网卡的 IP 和接口状态（避免每个设备单独调 PowerShell）
    _nic_ips = {}  # name.lower() -> ip
    _nic_ifaces = {}  # name.lower() -> iface
    if is_windows():
        try:
            r = subprocess.run(
                ["powershell", "-Command",
                 "Get-NetAdapter | Select-Object Name, InterfaceDescription | ForEach-Object { $n=$_.Name; $ip=(Get-NetIPAddress -InterfaceAlias $n -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress); [PSCustomObject]@{Name=$n;Desc=$_.InterfaceDescription;IP=$ip} } | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=15,
                encoding="utf-8", errors="replace"
            )
            if r.returncode == 0 and r.stdout.strip():
                import json
                data = json.loads(r.stdout.strip())
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    nic_name = (item.get("Name", "") or "").lower().strip()
                    nic_desc = (item.get("Desc", "") or "").lower().strip()
                    nic_ip = (item.get("IP", "") or "").strip()
                    _nic_ips[nic_desc] = nic_ip
                    _nic_ips[nic_name] = nic_ip
                    _nic_ips[nic_desc[:30]] = nic_ip
                    first_w = nic_desc.split()[0] if nic_desc else ""
                    if first_w:
                        _nic_ips[first_w] = nic_ip
        except Exception:
            pass

    for d in devs:
        name = (d.get("name", "?") or "?")[:28]
        vid = d.get("vid", "")
        pid = d.get("pid", "")
        id_str = f"{vid}:{pid}" if vid and pid and vid != "?" else (d.get("id", "") or "-")[:18]
        vendor = (d.get("vendor", "") or "-")[:20]

        # 查找接口
        iface = _find_net_iface(d) or "-"
        ip_str = "-"
        if is_windows():
            # 从缓存查 IP
            lookup_key = (d.get("name", "") or "").lower().strip()
            ip_str = _nic_ips.get(lookup_key, "")
            if not ip_str:
                v = (d.get("vendor", "") or "").lower().strip()
                ip_str = _nic_ips.get(v, "")
            if not ip_str:
                fw = lookup_key.split()[0] if lookup_key else ""
                if fw:
                    ip_str = _nic_ips.get(fw, "")
            if not ip_str:
                for k, v in _nic_ips.items():
                    if k and lookup_key and (k in lookup_key or lookup_key[:20] in k):
                        ip_str = v
                        break
            if not ip_str:
                ip_str = "-"
        else:
            # Linux: ip addr show
            try:
                r = subprocess.run(
                    ["ip", "-4", "addr", "show", iface],
                    capture_output=True, text=True, timeout=5
                )
                m = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', r.stdout)
                if m:
                    ip_str = m.group(1)
            except Exception:
                pass

        # 攻击标注
        _, cat, _ = _is_attack_capable(d)
        if cat == "WIFI":
            tag = f"{C.RED}[WiFi攻击]{C.NC}"
        elif cat == "ETH":
            tag = f"{C.YELLOW}[网络攻击]{C.NC}"
        else:
            tag = f"{C.CYAN}[网工]{C.NC}"

        rows.append([name, id_str, vendor, iface, ip_str, tag])

    print_table(["设备名", "ID", "厂商", "接口", "IP 地址", "类型"], rows)


# ═══════════════════════════════════════════════
#  usb --connect  — 交互式网卡选择
# ═══════════════════════════════════════════════

def usb_connect():
    """
    交互式网卡选择器
    列出所有网络接口让用户选择并执行后续操作
    """
    from core.utils import is_windows

    print(f" {INFO} 扫描可用网络接口...\n")

    # 收集所有网络接口
    interfaces = []
    seen = set()

    # 1) 系统默认接口
    interfaces.append({
        "id": "__default__",
        "name": "系统默认",
        "desc": "自动选择当前活动的网络接口",
        "iface": "",
    })
    seen.add("__default__")

    # 2) USB 网卡
    for d in get_network_usb_devices():
        iface = _find_net_iface(d)
        name = d.get("name", "?")
        did = d.get("id", name)
        if did not in seen:
            seen.add(did)
            interfaces.append({
                "id": did,
                "name": name[:40],
                "desc": f"{d.get('vendor', '')} USB网卡".strip(),
                "iface": iface or "未绑定",
            })

    # 3) 系统其他接口
    try:
        if is_windows():
            r = subprocess.run(
                ["powershell", "-Command",
                 "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object Name, InterfaceDescription | ConvertTo-Json"],
                capture_output=True, text=True, timeout=10,
                encoding="utf-8", errors="replace"
            )
            if r.returncode == 0 and r.stdout.strip():
                import json
                data = json.loads(r.stdout.strip())
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    n = item.get("Name", "")
                    desc = item.get("InterfaceDescription", "")
                    if n and n not in seen and "__" not in n:
                        seen.add(n)
                        interfaces.append({
                            "id": n,
                            "name": n,
                            "desc": desc[:50] if desc else "系统接口",
                            "iface": n,
                        })
        else:
            r = subprocess.run(
                ["ip", "-4", "addr", "show"],
                capture_output=True, text=True, timeout=5
            )
            if r.returncode == 0:
                current_iface = ""
                for line in r.stdout.split("\n"):
                    m = re.match(r'^\d+:\s+(\S+):', line)
                    if m:
                        current_iface = m.group(1).split("@")[0]
                    if "inet " in line and current_iface:
                        ip = line.strip().split()[1]
                        if current_iface not in seen and current_iface != "lo":
                            seen.add(current_iface)
                            interfaces.append({
                                "id": current_iface,
                                "name": current_iface,
                                "desc": f"IP: {ip.split('/')[0]}",
                                "iface": current_iface,
                            })
    except Exception:
        pass

    if len(interfaces) <= 1:
        print(f" {CROSS} 未检测到可用网络接口")
        print(f" {INFO} 请确认:")
        print(f"   {C.YELLOW}1.{C.NC} USB网卡/转接头支持 OTG")
        print(f"   {C.YELLOW}2.{C.NC} 手机已开启 OTG (设置中搜索 OTG)")
        print(f"   {C.YELLOW}3.{C.NC} 弹出选项选择 {C.GREEN}\"仅充电\"{C.NC}")
        print(f"   {C.YELLOW}4.{C.NC} 检查驱动: {C.CYAN}lsmod | grep -E 'usb|eth|rndis'{C.NC}")
        return

    # ── 显示选择列表 ──
    print(f" {C.GREEN}选择网卡：{C.NC}\n")
    for i, iface in enumerate(interfaces):
        icon = " " + C.GREEN + "[网卡]" + C.NC if iface["id"] != "__default__" and ("USB" in iface["desc"] or "net" in str(iface).lower()) else ""
        print(f"  {C.YELLOW}{i+1}.{C.NC} {iface['name']}{icon}")
        if iface["desc"]:
            print(f"     {C.DIM}{iface['desc']}{C.NC}")
        print()

    # ── 用户选择 ──
    try:
        choice = input(f" {C.CYAN}选择（输入序号）:{C.NC} ").strip()
        idx = int(choice) - 1
        if idx < 0 or idx >= len(interfaces):
            print(f" {CROSS} 无效选择")
            return
    except (ValueError, EOFError, KeyboardInterrupt):
        print(f"\n {INFO} 已取消")
        return

    selected = interfaces[idx]
    print(f"\n {CHECK} 已选择: {C.CYAN}{selected['name']}{C.NC}")

    if selected["id"] == "__default__":
        print(f" {INFO} 使用系统默认设置")
        return

    # ── 显示网卡详情和后续操作 ──
    iface_name = selected.get("iface", "")
    print(f"\n {INFO} 网卡详情：\n")
    rows = [
        ("名称", selected["name"]),
        ("描述", selected["desc"]),
        ("接口", iface_name if iface_name else "未绑定"),
    ]

    # 获取 IP
    if iface_name and iface_name != "未绑定":
        try:
            r = subprocess.run(
                ["ip", "-4", "addr", "show", iface_name] if not is_windows()
                else ["powershell", "-Command", f"Get-NetIPAddress -InterfaceAlias '{iface_name}' -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress"],
                capture_output=True, text=True, timeout=5,
                encoding="utf-8", errors="replace"
            )
            if r.returncode == 0:
                ip = r.stdout.strip().split("\n")[0].strip() if "\n" in r.stdout else r.stdout.strip()
                if ip:
                    rows.append(("IP 地址", ip))
        except Exception:
            pass

        # MAC
        try:
            r = subprocess.run(
                ["ip", "link", "show", iface_name] if not is_windows()
                else ["powershell", "-Command", f"Get-NetAdapter -Name '{iface_name}' | Select-Object -ExpandProperty MacAddress"],
                capture_output=True, text=True, timeout=5,
                encoding="utf-8", errors="replace"
            )
            if r.returncode == 0:
                mac = r.stdout.strip()
                if mac:
                    rows.append(("MAC", mac))
        except Exception:
            pass

    print_table(["属性", "值"], rows)

    # ── 后续操作菜单 ──
    print(f"\n {INFO} 后续操作：")
    print(f"  1. 释放 IP (dhcp release)")
    print(f"  2. 重新获取 IP (dhcp renew)")
    print(f"  3. 设置静态 IP")
    print(f"  4. 显示详细信息")
    print(f"  0. 返回\n")

    try:
        action = input(f" {C.CYAN}选择操作（输入序号）:{C.NC} ").strip()
        if action == "0":
            return
        elif action == "1":
            if iface_name and iface_name != "未绑定":
                _dhcp_release(iface_name)
        elif action == "2":
            if iface_name and iface_name != "未绑定":
                _dhcp_renew(iface_name)
        elif action == "3":
            _set_static_ip(iface_name)
        elif action == "4":
            show_external_net_devices()
        else:
            print(f" {CROSS} 无效选择")
    except (EOFError, KeyboardInterrupt):
        print(f"\n {INFO} 已取消")


def _dhcp_release(iface: str):
    """释放 DHCP IP"""
    from core.utils import is_windows
    print(f" {INFO} 释放 IP ({iface})...")
    try:
        if is_windows():
            subprocess.run(["ipconfig", "/release", iface], timeout=10)
            print(f" {CHECK} IP 已释放")
        else:
            subprocess.run(["dhclient", "-r", iface], timeout=10)
            print(f" {CHECK} IP 已释放")
    except Exception as e:
        print(f" {CROSS} 释放失败: {e}")


def _dhcp_renew(iface: str):
    """重新获取 DHCP IP"""
    from core.utils import is_windows
    print(f" {INFO} 重新获取 IP ({iface})...")
    try:
        if is_windows():
            subprocess.run(["ipconfig", "/renew", iface], timeout=30)
            print(f" {CHECK} IP 已更新")
        else:
            subprocess.run(["dhclient", iface], timeout=30)
            print(f" {CHECK} IP 已获取")
    except Exception as e:
        print(f" {CROSS} 获取失败: {e}")


def _set_static_ip(iface: str):
    """设置静态 IP（交互式）"""
    print(f" {INFO} 设置静态 IP ({iface})\n")
    try:
        ip = input(f" {ARROW} IP 地址: ").strip()
        mask = input(f" {ARROW} 子网掩码 (默认 255.255.255.0): ").strip() or "255.255.255.0"
        gw = input(f" {ARROW} 网关 (留空跳过): ").strip()
        dns = input(f" {ARROW} DNS (留空跳过): ").strip()

        from core.utils import is_windows
        if is_windows():
            cmd = ["netsh", "interface", "ip", "set", "address",
                   f"name={iface}", f"source=static", ip, mask]
            if gw:
                cmd.append(gw)
            subprocess.run(cmd, timeout=10)
            if dns:
                subprocess.run(["netsh", "interface", "ip", "set", "dns",
                               f"name={iface}", f"source=static", dns], timeout=10)
            print(f" {CHECK} 静态 IP 已设置")
        else:
            # Linux: ip addr add
            prefix = sum(bin(int(b)).count("1") for b in mask.split("."))
            subprocess.run(["ip", "addr", "add", f"{ip}/{prefix}", "dev", iface], timeout=5)
            if gw:
                subprocess.run(["ip", "route", "add", "default", "via", gw, "dev", iface], timeout=5)
            print(f" {CHECK} 静态 IP 已设置")
    except Exception as e:
        print(f" {CROSS} 设置失败: {e}")


def _find_net_iface(usb_dev: dict) -> str:
    """通过 USB 设备信息查找对应的网络接口（快速）"""
    from core.utils import is_windows

    # Windows: 一次性获取所有 USB 网卡接口名
    if is_windows():
        if not hasattr(_find_net_iface, "_win_cache"):
            try:
                r = subprocess.run(
                    ["powershell", "-Command",
                     "Get-NetAdapter | Where-Object {$_.InterfaceDescription -match 'USB|Virtual|WAN|Realtek|ASIX|AX88|Red Hat'} | Select-Object Name, InterfaceDescription | ConvertTo-Json"],
                    capture_output=True, text=True, timeout=10,
                    encoding="utf-8", errors="replace"
                )
                _find_net_iface._win_cache = []
                if r.returncode == 0 and r.stdout.strip():
                    import json
                    data = json.loads(r.stdout.strip())
                    if isinstance(data, dict):
                        data = [data]
                    for item in data:
                        _find_net_iface._win_cache.append(item)
            except Exception:
                _find_net_iface._win_cache = []

        name_key = (usb_dev.get("name", "") + usb_dev.get("id", "")).lower()
        for item in _find_net_iface._win_cache:
            desc = item.get("InterfaceDescription", "").lower()
            if desc and any(kw in desc for kw in ["virtio", "red hat", "usb", "realtek", "asix", "ax88"]):
                if any(k in name_key for k in ["virtio", "red hat", "wan", "usb"]):
                    return item.get("Name", "")
        return ""

    # Linux: sysfs 快速匹配
    try:
        sys_net = "/sys/class/net"
        if not os.path.isdir(sys_net):
            return ""
        vid = usb_dev.get("vid", "")
        pid = usb_dev.get("pid", "")
        for iface in sorted(os.listdir(sys_net)):
            uevent = os.path.join(sys_net, iface, "device", "uevent")
            if os.path.isfile(uevent):
                with open(uevent, errors="ignore") as f:
                    content = f.read()
                if vid and pid:
                    if vid in content or pid in content:
                        return iface
        return ""
    except Exception:
        return ""


# ═══════════════════════════════════════════════
#  USB 监控模式
# ═══════════════════════════════════════════════

def usb_monitor(interval: float = 2.0):
    """
    监控 USB 设备插拔
    实时显示新增/移除的设备
    """
    print(f" {INFO} USB 设备监控 (每 {interval}s, Ctrl+C 停止)\n")
    prev = {d["id"]: d for d in get_usb_devices()}

    try:
        while True:
            time.sleep(interval)
            current = {d["id"]: d for d in get_usb_devices()}
            now = datetime.now().strftime("%H:%M:%S")

            # 新设备
            for did, d in current.items():
                if did not in prev:
                    name = d.get("name", "?")
                    marker = f" {C.GREEN}[网卡]{C.NC}" if d.get("is_net") else ""
                    print(f" {C.GREEN}[+]{C.NC}  {now}  {C.CYAN}{name[:40]}{C.NC}{marker}")
                    if d.get("is_net"):
                        iface = _find_net_iface(d)
                        if iface:
                            print(f"      接口: {iface}")
                            # 尝试获取 IP
                            try:
                                r = subprocess.run(
                                    ["ip", "-4", "addr", "show", iface],
                                    capture_output=True, text=True, timeout=3
                                )
                                m = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', r.stdout)
                                if m:
                                    print(f"      IP:   {C.CYAN}{m.group(1)}{C.NC}")
                            except Exception:
                                pass

            # 移除的设备
            for did, d in prev.items():
                if did not in current:
                    name = d.get("name", "?")
                    print(f" {C.RED}[-]{C.NC}  {now}  {name[:40]}")

            prev = current

    except KeyboardInterrupt:
        print(f"\n {CHECK} 监控已停止")


# ═══════════════════════════════════════════════
#  USB 安全检测 (检测 BadUSB 等)
# ═══════════════════════════════════════════════

def usb_security_check():
    """
    USB 安全检测
    检测异常 USB 设备和潜在威胁
    """
    print(f" {INFO} USB 安全检测...\n")
    devs = get_usb_devices()

    if not devs:
        print(f" {INFO} 未检测到 USB 设备")
        return

    issues = []
    net_devs = []
    ok_devs = []

    for d in devs:
        name = d.get("name", "?").lower()
        is_net = d.get("is_net", False)
        vid = d.get("vid", "")
        pid = d.get("pid", "")

        # 潜在威胁检查
        suspicious = False
        reasons = []

        # HID 设备同时也是网络设备 (BadUSB 特征)
        if is_net and ("keyboard" in name or "mouse" in name or "hid" in name):
            suspicious = True
            reasons.append("HID + 网卡混合设备 (BadUSB 特征!)")

        # 未知厂商的网络设备
        if is_net and not d.get("vendor", "").strip():
            suspicious = True
            reasons.append("未知厂商的 USB 网卡")

        if is_net:
            net_devs.append(d)

        if suspicious:
            issues.append((d, reasons))
        else:
            ok_devs.append(d)

    # 输出结果
    if net_devs:
        print(f" {CHECK} USB 网卡: {len(net_devs)} 个\n")
        for d in net_devs:
            name = d.get("name", "?")
            print(f"   {C.CYAN}● {name}{C.NC}")
            if d.get("vendor"):
                print(f"     厂商: {d['vendor']}")
            iface = _find_net_iface(d)
            if iface:
                print(f"     接口: {iface}")
    else:
        print(f" {INFO} 未检测到 USB 网卡")

    if issues:
        print(f"\n {CROSS} {C.RED}检测到 {len(issues)} 个异常设备!{C.NC}\n")
        for d, reasons in issues:
            print(f"   {C.RED}⚠{C.NC} {d.get('name', '?')}")
            for r in reasons:
                print(f"     {C.RED}→{C.NC} {r}")
    else:
        print(f"\n {CHECK} {C.GREEN}USB 安全状态正常{C.NC}")

    print(f"\n {INFO} 总计: {len(devs)} 设备 | 网卡: {len(net_devs)} | 异常: {len(issues)}")


# ═══════════════════════════════════════════════
#  Main dispatcher
# ═══════════════════════════════════════════════

def usb_main(args):
    """usb 命令主分发"""
    if hasattr(args, 'connect') and args.connect:
        usb_connect()
    elif hasattr(args, 'list_usb') and args.list_usb:
        show_usb_list()
    elif hasattr(args, 'ext_devices') and args.ext_devices:
        show_external_net_devices()
    elif hasattr(args, 'usb_monitor') and args.usb_monitor:
        usb_monitor()
    elif hasattr(args, 'usb_info') and args.usb_info:
        devs = get_usb_devices()
        target = args.usb_info.lower()
        for d in devs:
            if target in d.get("name", "").lower() or target in d.get("id", "").lower():
                print_table(["属性", "值"],
                           [[k, str(v)] for k, v in d.items() if v])
                if d.get("is_net"):
                    iface = _find_net_iface(d)
                    if iface:
                        print(f"\n   网络接口: {iface}")
                return
        print(f" {CROSS} 未找到设备: {args.usb_info}")
    elif hasattr(args, 'usb_security') and args.usb_security:
        usb_security_check()
    else:
        show_usb_list()
