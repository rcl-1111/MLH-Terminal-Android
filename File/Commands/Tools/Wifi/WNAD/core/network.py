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
        # 备用: 通过 ip link 命令
        try:
            result = subprocess.run(
                ["ip", "link", "show"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                interfaces = re.findall(r'\d+:\s+(\S+):', result.stdout)
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

    # 获取 IP 地址
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]
        sock.close()
        # 检查这个 IP 是否属于该接口
        info["ip"] = local_ip
    except Exception:
        pass

    # 通过 /sys/class/net 获取更准确信息
    sys_path = f"/sys/class/net/{iface}"
    if os.path.isdir(sys_path):
        # MAC 地址
        addr_path = f"{sys_path}/address"
        if os.path.isfile(addr_path):
            with open(addr_path) as f:
                mac = f.read().strip()
                if mac and mac != "00:00:00:00:00:00":
                    info["mac"] = mac

        # 接口状态
        oper_path = f"{sys_path}/operstate"
        if os.path.isfile(oper_path):
            with open(oper_path) as f:
                info["status"] = f.read().strip().upper()

        # 接口类型
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

        # 尝试获取 IP (通过 /proc/net/fib_trie 或 ifaddr)
        if info["ip"] == "无":
            try:
                result = subprocess.run(
                    ["ip", "-4", "addr", "show", iface],
                    capture_output=True, text=True, timeout=5
                )
                ips = re.findall(r'inet\s+(\d+\.\d+\.\d+\.\d+/\d+)', result.stdout)
                if ips:
                    info["ip"] = ips[0]
                    # 再取无掩码的
                    ip_clean = re.findall(r'inet\s+(\d+\.\d+\.\d+\.\d+)', result.stdout)
                    if ip_clean:
                        info["ip"] = ip_clean[0]
            except Exception:
                pass

    return info


def get_gateway() -> str:
    """获取默认网关"""
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
    """获取 DNS 服务器"""
    dns_list = []
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


def show_info():
    """显示完整本机网络信息"""
    print(f" {INFO} 正在收集本机网络信息...\n")

    try:
        headers = ["接口", "IP地址", "MAC地址", "状态", "类型"]
        rows = []

        for iface in get_interfaces():
            if iface == "lo":
                continue  # 跳过回环
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
