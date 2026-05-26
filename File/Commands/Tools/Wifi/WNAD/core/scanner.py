"""
WNAD - 网络扫描模块
ARP 扫描、Ping 存活探测、TCP 端口扫描、服务指纹识别
纯 Python 实现
"""

import os
import socket
import subprocess
import re
import concurrent.futures
import struct
from urllib.request import urlopen
from urllib.error import URLError
from core.utils import C, CHECK, CROSS, INFO, print_table, progress_bar, save_results
from core.network import get_gateway, get_oui_vendor
from datetime import datetime


# ── 常用服务端口 → 协议名称 ──
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# ── 服务 Banner 探针 ──
BANNER_PROBES = {
    21: b"",
    22: b"",
    23: b"",
    25: b"EHLO\r\n",
    80: b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    110: b"",
    143: b"",
    443: b"\x16\x03\x00\x00\x00\x00\x00",
    445: b"",
    993: b"",
    995: b"",
    3306: b"",
    5432: b"",
    5900: b"",
    6379: b"PING\r\n",
    8080: b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    8443: b"\x16\x03\x00\x00\x00\x00\x00",
}


def parse_cidr_from_ip(ip: str) -> str:
    """从本机 IP 推断 CIDR（/24）"""
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return ""


def scan_arp():
    """ARP 扫描局域网设备（解析 /proc/net/arp）"""
    arp_path = "/proc/net/arp"
    if not os.path.isfile(arp_path):
        print(f" {CROSS} 无法访问 {arp_path}（无 root 或无 ARP 表）")
        print(f" {INFO} 可尝试使用 {C.CYAN}scan --ping{C.NC} 代替")
        return []

    print(f" {INFO} 正在读取 ARP 表...\n")
    devices = []

    with open(arp_path) as f:
        lines = f.readlines()

    if len(lines) <= 1:
        print(f" {INFO} ARP 表为空")
        return []

    for line in lines[1:]:
        parts = line.strip().split()
        if len(parts) >= 4:
            ip = parts[0]
            hw_type = parts[1]
            flags = parts[2]
            mac = parts[3]

            # 跳过未完成的条目
            if mac == "00:00:00:00:00:00" or flags == "0x00":
                continue

            vendor = get_oui_vendor(mac)
            devices.append((ip, mac, vendor))

    if devices:
        print(f" {CHECK} 发现 {len(devices)} 个设备:\n")
        headers = ["IP 地址", "MAC 地址", "厂商"]
        print_table(headers, devices)

        # 保存结果
        save_results("arp_scan", {
            "time": datetime.now().isoformat(),
            "count": len(devices),
            "devices": [{"ip": d[0], "mac": d[1], "vendor": d[2]} for d in devices],
        })
    else:
        print(f" {INFO} ARP 表中无有效设备")

    return devices


def scan_ping(target_cidr: str = None, max_workers: int = 50):
    """Ping Sweep 存活探测"""
    if not target_cidr:
        print(f" {CROSS} 请指定网段，例如: {C.CYAN}wnad scan --ping 192.168.1.0/24{C.NC}")
        return []

    from core.iplookup import scan_cidr
    return scan_cidr(target_cidr, max_workers)


def _scan_port_tcp(ip: str, port: int, timeout: float = 1.0) -> dict:
    """单端口 TCP 连接扫描"""
    result = {"port": port, "state": "closed", "service": "", "banner": ""}
    service_name = COMMON_PORTS.get(port, "")
    result["service"] = service_name

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        result["state"] = "open"

        # 尝试读取 Banner
        if port in BANNER_PROBES:
            probe = BANNER_PROBES[port]
            if probe:
                try:
                    sock.send(probe)
                except Exception:
                    pass

            try:
                banner = sock.recv(1024)
                if banner:
                    # 清理不可见字符
                    clean = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', banner.decode("utf-8", errors="ignore"))
                    result["banner"] = clean[:80].strip()
            except socket.timeout:
                pass

        sock.close()
    except (socket.timeout, ConnectionRefusedError, OSError):
        result["state"] = "closed"
    except Exception:
        result["state"] = "filtered"

    return result


def scan_ports(ip: str, port_range: str, max_workers: int = 100, timeout: float = 1.0):
    """TCP 端口扫描"""
    # 解析端口范围
    ports = []
    for part in port_range.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))

    if not ports:
        ports = list(range(1, 1001))  # 默认 1-1000

    print(f" {INFO} 正在扫描 {C.CYAN}{ip}{C.NC} 的 {len(ports)} 个端口\n")

    open_ports = []
    scanned = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_scan_port_tcp, ip, p, timeout): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            scanned += 1
            if scanned % 20 == 0 or scanned == len(ports):
                progress_bar(scanned, len(ports), f"端口扫描 {scanned}/{len(ports)}")
            if result["state"] == "open":
                open_ports.append(result)

    print()
    if open_ports:
        print(f" {CHECK} 发现 {len(open_ports)} 个开放端口:\n")
        rows = []
        for p in open_ports:
            service = p["service"] if p["service"] else "?"
            banner = p["banner"][:40] if p["banner"] else ""
            rows.append([str(p["port"]), service, f"{C.GREEN}OPEN{C.NC}", banner])
        print_table(["端口", "服务", "状态", "Banner"], rows)

        # 保存结果
        save_results("port_scan", {
            "time": datetime.now().isoformat(),
            "target": ip,
            "port_range": port_range,
            "ports_scanned": len(ports),
            "open_ports": [{"port": p["port"], "service": p["service"], "banner": p["banner"]}
                          for p in open_ports],
        })
    else:
        print(f" {INFO} 未发现开放端口")

    return open_ports


# ── 服务 Banner 探针（针对 IP + 端口）──
def _banner_grab(ip: str, port: int, timeout: float = 2.0) -> str:
    """获取单个服务的 Banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # 发送通用探针
        if port == 80 or port == 8080:
            sock.send(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        elif port == 21:
            pass  # FTP 会主动发送 Banner
        elif port == 25:
            sock.send(b"EHLO scan\r\n")
        elif port == 22:
            pass  # SSH 会主动发送 Banner
        elif port == 443 or port == 8443:
            pass  # TLS 握手检测
        else:
            sock.send(b"\r\n")

        banner = sock.recv(2048)
        sock.close()
        if banner:
            clean = re.sub(r'[\x00-\x1f\x7f-\x9f]', ' ', banner.decode("utf-8", errors="ignore"))
            return clean[:120].strip()
    except Exception:
        pass
    return ""


def scan_service(ip: str, ports: list = None, max_workers: int = 30):
    """服务 Banner 指纹识别"""
    if not ports:
        ports = list(COMMON_PORTS.keys())

    print(f" {INFO} 正在识别 {C.CYAN}{ip}{C.NC} 的服务指纹 ({len(ports)} 个端口)\n")

    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_banner_grab, ip, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            banner = future.result()
            if banner:
                service = COMMON_PORTS.get(port, "?")
                results.append((str(port), service, banner[:60]))

    if results:
        print(f" {CHECK} 发现 {len(results)} 个服务:\n")
        print_table(["端口", "服务", "Banner"], results)
    else:
        print(f" {INFO} 未识别到服务 Banner")

    return results
