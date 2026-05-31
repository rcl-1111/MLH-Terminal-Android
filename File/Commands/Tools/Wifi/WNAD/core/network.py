"""
WNAD - 本机网络信息模块
获取接口、IP、MAC、网关、DNS、网卡型号等信息
纯 Python 实现，兼容 Android Termux 环境
"""

import os
import socket
import subprocess
import re
from core.utils import C, CHECK, CROSS, INFO, print_table


def get_interfaces() -> list:
    """获取所有网络接口列表"""
    interfaces = []
    sys_class_net = "/sys/class/net"
    if os.path.isdir(sys_class_net):
        try:
            interfaces = sorted(os.listdir(sys_class_net))
        except PermissionError:
            # Android Termux 无 root 时无法访问 /sys/class/net
            pass
    if not interfaces:
        # 备用: 通过 ip link 命令 (Linux/Android)
        try:
            result = subprocess.run(
                ["ip", "link", "show"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                interfaces = re.findall(r'\d+:\s+(\S+):', result.stdout)
        except Exception:
            pass

    if not interfaces:
        # Windows: 通过 PowerShell 获取，使用索引避免编码问题
        from core.utils import is_windows
        if is_windows():
            try:
                result = subprocess.run(
                    ["powershell", "-Command",
                     "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object { $_.Name + '|' + $_.InterfaceIndex }"],
                    capture_output=True, text=True, timeout=10,
                    encoding="utf-8", errors="replace"
                )
                if result.returncode == 0:
                    for line in result.stdout.strip().split("\n"):
                        line = line.strip()
                        if "|" in line:
                            name, idx = line.split("|", 1)
                            # 用索引作为接口名（避免中文编码问题）
                            interfaces.append(f"eth{idx}")
            except Exception:
                pass

    return interfaces


def get_iface_info(iface: str) -> dict:
    """获取单个接口的网络信息"""
    info = {
        "name": iface,
        "ip": "无",
        "mac": "无",
        "status": "DOWN",
        "type": "未知",
    }

    from core.utils import is_windows

    # Windows 专用: 通过 PowerShell 获取 (接口名格式: eth<索引>)
    if is_windows():
        idx = iface.replace("eth", "")
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 f"Get-NetAdapter -InterfaceIndex {idx} | Select-Object Name, Status, MacAddress, InterfaceDescription | ConvertTo-Json"],
                capture_output=True, text=True, timeout=10,
                encoding="utf-8", errors="replace"
            )
            if result.returncode == 0 and result.stdout.strip():
                import json
                data = json.loads(result.stdout.strip())
                if data:
                    mac_raw = data.get("MacAddress", "")
                    if mac_raw:
                        info["mac"] = mac_raw.replace("-", ":")
                    status = data.get("Status", "")
                    info["status"] = "UP" if status == "Up" else "DOWN"
                    desc = data.get("InterfaceDescription", "")
                    if "Wireless" in desc or "WiFi" in desc or "WLAN" in desc:
                        info["type"] = "WiFi/WLAN"
                    elif "Ethernet" in desc or "以太网" in desc:
                        info["type"] = "以太网"
        except Exception:
            pass

        # Windows: 获取 IPv4 地址
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 f"Get-NetIPAddress -InterfaceIndex {idx} -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress"],
                capture_output=True, text=True, timeout=10,
                encoding="utf-8", errors="replace"
            )
            if result.returncode == 0 and result.stdout.strip():
                ip = result.stdout.strip().split("\n")[0].strip()
                if ip:
                    info["ip"] = ip
        except Exception:
            pass

        return info

    # 方法1: 通过 ip addr show 获取 IP 和状态
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", iface],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            # 提取 IP
            ips = re.findall(r'inet\s+(\d+\.\d+\.\d+\.\d+)', result.stdout)
            if ips:
                info["ip"] = ips[0]
            # 提取状态
            if "state UP" in result.stdout or "state UNKNOWN" in result.stdout:
                info["status"] = "UP"
    except Exception:
        pass

    # 方法2: 通过 ip link show 获取 MAC 和状态
    try:
        result = subprocess.run(
            ["ip", "link", "show", iface],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            # MAC 地址 (link/ether)
            mac_m = re.search(r'link/ether\s+([0-9a-fA-F:]{17})', result.stdout)
            if mac_m:
                info["mac"] = mac_m.group(1)
            # 状态回退
            if info["status"] == "DOWN" and "state UP" in result.stdout:
                info["status"] = "UP"
            # 识别接口类型
            if "wlan" in iface.lower() or "wl" in iface.lower():
                info["type"] = "WiFi/WLAN"
            elif "eth" in iface.lower():
                info["type"] = "以太网"
            elif "lo" == iface:
                info["type"] = "回环"
            elif "br-" in iface or "docker" in iface or "veth" in iface:
                info["type"] = "虚拟网桥"
            elif "tun" in iface or "tap" in iface:
                info["type"] = "VPN/隧道"
            elif "p2p" in iface or "nan" in iface:
                info["type"] = "WiFi直连"
    except Exception:
        pass

    # 方法3: /sys/class/net 补充信息（Android 无 root 时可能不可读）
    sys_path = f"/sys/class/net/{iface}"
    if os.path.isdir(sys_path):
        try:
            addr_path = f"{sys_path}/address"
            if os.path.isfile(addr_path):
                with open(addr_path) as f:
                    mac = f.read().strip()
                    if mac and mac != "00:00:00:00:00:00":
                        info["mac"] = mac
        except Exception:
            pass

        try:
            oper_path = f"{sys_path}/operstate"
            if os.path.isfile(oper_path):
                with open(oper_path) as f:
                    status = f.read().strip().upper()
                    if status in ("UP", "DOWN", "UNKNOWN"):
                        info["status"] = status
        except Exception:
            pass

        try:
            type_path = f"{sys_path}/type"
            if os.path.isfile(type_path):
                with open(type_path) as f:
                    iface_type = int(f.read().strip())
                    type_map = {
                        1: "以太网",
                        772: "WiFi/WLAN",
                        65534: "回环",
                        768: "IP隧道",
                    }
                    info["type"] = type_map.get(iface_type, f"类型{iface_type}")
        except Exception:
            pass

    # 过滤虚假的 IP（接口 DOWN 时不显示 IP）
    if info["status"] == "DOWN":
        info["ip"] = "无"

    return info


def get_gateway() -> str:
    """获取默认网关，跨平台"""
    from core.utils import is_windows

    # Windows: route print
    if is_windows():
        try:
            result = subprocess.run(
                ["route", "print", "0.0.0.0"],
                capture_output=True, text=True, timeout=5, encoding="utf-8", errors="replace"
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    # 格式:   0.0.0.0          0.0.0.0         192.168.1.1      192.168.1.100
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                        return parts[2]
        except Exception:
            pass

    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            match = re.search(r'default via\s+(\d+\.\d+\.\d+\.\d+)', result.stdout)
            if match:
                return match.group(1)
    except Exception:
        pass

    # 备用: 解析 /proc/net/route
    try:
        with open("/proc/net/route") as f:
            for line in f:
                fields = line.strip().split()
                if len(fields) >= 3 and fields[1] == "00000000":
                    # 网关是第三列，小端序
                    gw_hex = fields[2]
                    gw = ".".join(str(int(gw_hex[i:i+2], 16))
                                  for i in range(6, -1, -2))
                    return gw
    except Exception:
        pass

    return "未知"


def get_dns_servers() -> list:
    """获取 DNS 服务器，跨平台"""
    dns_list = []
    from core.utils import is_windows

    # Windows: 通过 PowerShell 获取 DNS 服务器
    if is_windows():
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses"],
                capture_output=True, text=True, timeout=10,
                encoding="utf-8", errors="replace"
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    ip = line.strip()
                    if ip and re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                        dns_list.append(ip)
                if dns_list:
                    return dns_list
        except Exception:
            pass

    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                match = re.search(r'^nameserver\s+(\S+)', line)
                if match:
                    dns_list.append(match.group(1))
    except Exception:
        pass

    if not dns_list:
        # Android 备用
        try:
            result = subprocess.run(
                ["getprop", "net.dns1"],
                capture_output=True, text=True, timeout=3
            )
            if result.stdout.strip():
                dns_list.append(result.stdout.strip())
            result2 = subprocess.run(
                ["getprop", "net.dns2"],
                capture_output=True, text=True, timeout=3
            )
            if result2.stdout.strip():
                dns_list.append(result2.stdout.strip())
        except Exception:
            pass

    return dns_list if dns_list else ["无"]


def get_wifi_info() -> dict:
    """获取 WiFi 相关信息（SSID、信号强度）"""
    info = {"ssid": "未知", "signal": "未知", "frequency": "未知"}

    # 通过 iwgetid (如果可用且root)
    try:
        result = subprocess.run(
            ["iwgetid", "-r"], capture_output=True, text=True, timeout=3
        )
        if result.stdout.strip():
            info["ssid"] = result.stdout.strip()
    except Exception:
        pass

    # iwconfig (兼容)
    try:
        result = subprocess.run(
            ["iwconfig"], capture_output=True, text=True, timeout=3
        )
        for line in result.stdout.split("\n"):
            if "ESSID:" in line:
                m = re.search(r'ESSID:"([^"]*)"', line)
                if m:
                    info["ssid"] = m.group(1)
            if "Signal level" in line:
                m = re.search(r'Signal level=([-\d]+ dBm)', line)
                if m:
                    info["signal"] = m.group(1)
            if "Frequency" in line:
                m = re.search(r'Frequency:([\d.]+ GHz)', line)
                if m:
                    info["frequency"] = m.group(1)
    except Exception:
        pass

    return info


def get_oui_vendor(mac: str) -> str:
    """通过 OUI 数据库查询 MAC 厂商"""
    if not mac or mac == "无" or len(mac) < 8:
        return "未知"
    prefix = mac[:8].upper().replace(":", "")
    oui_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "oui.txt")
    try:
        with open(oui_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith(prefix):
                    return line.split("\t", 1)[1].strip()
    except Exception:
        pass
    return "未知"


def resolve_device_name(ip: str) -> str:
    """
    多方法解析设备名 (跨平台)
    返回 设备名 或 空字符串
    尝试顺序: DNS反解 → mDNS → NetBIOS → DHCP
    """
    # 1) 标准 DNS 反解
    try:
        name = socket.gethostbyaddr(ip)[0]
        if name and name != ip:
            # 去掉尾部 .
            return name.rstrip(".")
    except Exception:
        pass

    # 2) mDNS (avahi)
    try:
        r = subprocess.run(
            ["avahi-resolve-address", ip],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0 and r.stdout.strip():
            parts = r.stdout.strip().split("\t")
            if len(parts) >= 2 and parts[1].strip():
                return parts[1].strip()
    except Exception:
        pass

    # 3) NetBIOS (nmblookup)
    try:
        r = subprocess.run(
            ["nmblookup", "-A", ip],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0:
            for line in r.stdout.split("\n"):
                # 格式: <00> -  <GROUP> X <NETBIOSNAME>
                m = re.search(r'^\s*([^\s<]+)\s+<00>', line)
                if m:
                    name = m.group(1).strip()
                    if name and name != "IN" and not name.startswith("__"):
                        return name
    except Exception:
        pass

    # 4) DHCP lease 文件 (Android Termux)
    try:
        leases_dir = "/data/misc/dhcp"
        if os.path.isdir(leases_dir):
            for fname in os.listdir(leases_dir):
                fpath = os.path.join(leases_dir, fname)
                if not os.path.isfile(fpath):
                    continue
                with open(fpath, errors="ignore") as f:
                    for line in f:
                        if line.startswith(f"dhcp-server-identifier={ip}"):
                            return fname.replace(".lease", "").replace("dhcpcd-", "")
                        if ip in line:
                            for l2 in f:
                                m = re.search(r'hostname=(.+)', l2)
                                if m:
                                    return m.group(1).strip()
    except Exception:
        pass

    return ""


def get_neighbor_table() -> dict:
    """
    获取邻居设备表 (IP -> MAC)
    尝试多种方法，兼容无 root 环境
    返回 {ip: {"mac": mac, "iface": iface}}
    """
    table = {}
    from core.utils import is_windows

    # Windows: arp -a
    if is_windows():
        try:
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True, text=True, timeout=5, encoding="utf-8", errors="replace"
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    # Windows 格式: 192.168.1.1      xx-xx-xx-xx-xx-xx     dynamic
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        mac = parts[1].replace("-", ":")
                        if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip) and re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', mac):
                            table[ip] = {"mac": mac, "iface": "?"}
                if table:
                    return table
        except Exception:
            pass

    # 方法1: /proc/net/arp (标准 Linux)
    try:
        if os.path.isfile("/proc/net/arp"):
            with open("/proc/net/arp") as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        ip = parts[0]
                        mac = parts[3]
                        iface = parts[5] if len(parts) > 5 else "?"
                        if mac != "00:00:00:00:00:00":
                            table[ip] = {"mac": mac, "iface": iface}
            if table:
                return table
    except PermissionError:
        pass  # Android 无 root 无法读取
    except Exception:
        pass

    # 方法2: ip neigh show (部分 Android 无需 root)
    try:
        result = subprocess.run(
            ["ip", "neigh", "show"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                parts = line.strip().split()
                # 格式: 192.168.1.1 dev wlan0 lladdr xx:xx:xx:xx:xx:xx REACHABLE
                if len(parts) >= 5 and "lladdr" in line:
                    ip = parts[0]
                    mac = ""
                    iface = parts[2] if len(parts) > 2 else "?"
                    for i, p in enumerate(parts):
                        if p == "lladdr" and i + 1 < len(parts):
                            mac = parts[i + 1]
                            break
                    if mac and mac != "00:00:00:00:00:00":
                        table[ip] = {"mac": mac, "iface": iface}
            if table:
                return table
    except Exception:
        pass

    # 方法3: arp -n (兼容)
    try:
        result = subprocess.run(
            ["arp", "-n"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                parts = line.strip().split()
                # 格式: 192.168.1.1  xx:xx:xx:xx:xx:xx  ...
                if len(parts) >= 3 and ":" in parts[2]:
                    ip = parts[0]
                    mac = parts[2]
                    iface = parts[5] if len(parts) > 5 else "?"
                    if mac != "00:00:00:00:00:00":
                        table[ip] = {"mac": mac, "iface": iface}
    except Exception:
        pass

    return table


def show_info():
    """显示完整本机网络信息"""
    print(f" {INFO} 正在收集本机网络信息...\n")

    try:
        headers = ["接口", "IP地址", "MAC地址", "状态", "类型"]
        rows = []

        # 排除 Android 虚拟接口
        skip_ifaces = {"dummy0", "ip_vti0@NONE", "ip6_vti0@NONE",
                       "sit0@NONE", "ip6tnl0@NONE",
                       "gretap0", "erspan0", "tunl0", "bond0"}

        for iface in get_interfaces():
            if iface == "lo":
                continue
            if iface in skip_ifaces or iface.startswith(("ip6", "ip_vti", "sit")):
                continue
            info = get_iface_info(iface)
            rows.append([
                info["name"],
                info["ip"],
                info["mac"],
                f"{C.GREEN}UP{C.NC}" if info["status"] == "UP" else f"{C.RED}DOWN{C.NC}",
                info["type"],
            ])

        print_table(headers, rows)
        print()

        # 网关 & DNS
        gw = get_gateway()
        dns_list = get_dns_servers()
        print(f" {C.CYAN}[网关]{C.NC} {gw}")
        print(f" {C.CYAN}[DNS]{C.NC} {', '.join(dns_list)}")

        # WiFi 信息（如有）
        wifi = get_wifi_info()
        if wifi["ssid"] != "未知":
            print(f"\n {C.CYAN}[WiFi]{C.NC}")
            print(f"   SSID:     {wifi['ssid']}")
            print(f"   信号强度: {wifi['signal']}")
            print(f"   频率:     {wifi['frequency']}")
    except Exception as e:
        print(f" {CROSS} 获取网络信息失败: {e}")
        print(f" {INFO} 部分功能在 Android Termux 无 root 环境下受限")
