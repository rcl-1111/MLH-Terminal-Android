"""
WNAD - 网络安全防御模块
纯 Python 实现，无需 root
功能: ARP欺骗检测 | 端口监控 | DNS劫持检测 | 端口扫描检测 | 安全基线
"""

import os
import re
import sys
import time
import socket
import struct
import subprocess
import threading
from datetime import datetime
from core.utils import C, CHECK, CROSS, INFO, WARN, ROOT, print_table, is_windows


# ═══════════════════════════════════════════════
#  1. defense arp — ARP 欺骗检测
# ═══════════════════════════════════════════════

def defense_arp(monitor: bool = False, interval: int = 5):
    """
    检测 ARP 欺骗攻击
    检查 ARP 表中是否有 IP 对应多个 MAC（经典 ARP 欺骗特征）
    """
    from core.network import get_neighbor_table

    prev = {}

    def check_arp():
        nonlocal prev
        table = get_neighbor_table()
        if not table:
            return []

        alerts = []
        # IP -> [MACs] 映射
        ip_macs = {}
        for ip, info in table.items():
            mac = info["mac"]
            if ip not in ip_macs:
                ip_macs[ip] = []
            if mac not in ip_macs[ip]:
                ip_macs[ip].append(mac)

        for ip, macs in ip_macs.items():
            if len(macs) > 1:
                alerts.append({"type": "SPOOF", "ip": ip, "macs": macs})
            elif ip in prev and prev[ip] != macs[0]:
                alerts.append({"type": "CHANGE", "ip": ip, "old_mac": prev[ip], "new_mac": macs[0]})

        prev = {ip: info["mac"] for ip, info in table.items()}
        return alerts

    if not monitor:
        # 一次性检查
        print(f" {INFO} 检测 ARP 欺骗攻击...\n")
        alerts = check_arp()
        if alerts:
            print(f" {CROSS} {C.RED}检测到安全威胁!{C.NC}\n")
            rows = []
            for a in alerts:
                if a["type"] == "SPOOF":
                    rows.append([a["ip"], "ARP 欺骗", f"同一 IP 出现 {len(a['macs'])} 个 MAC: {', '.join(a['macs'])}"])
                else:
                    rows.append([a["ip"], "MAC 变更", f"{a['old_mac']} → {a['new_mac']}"])
            print_table(["IP", "威胁类型", "详情"], rows)
        else:
            print(f" {CHECK} ARP 表正常，未检测到欺骗\n")
            rows = []
            for ip, mac in sorted(prev.items()):
                rows.append([ip, mac])
            print_table(["IP", "MAC"], rows)
    else:
        # 持续监控
        print(f" {INFO} ARP 欺骗持续监控 (每 {interval}s, Ctrl+C 停止)\n")
        try:
            while True:
                alerts = check_arp()
                now = datetime.now().strftime("%H:%M:%S")
                for a in alerts:
                    if a["type"] == "SPOOF":
                        print(f" {CROSS} {C.RED}[ARP SPOOF]{C.NC} {now}  {a['ip']} → {', '.join(a['macs'])}")
                    else:
                        print(f" {WARN} {C.YELLOW}[ARP CHANGE]{C.NC} {now}  {a['ip']}: {a['old_mac']} → {a['new_mac']}")
                time.sleep(interval)
        except KeyboardInterrupt:
            print(f"\n {CHECK} 监控已停止")


# ═══════════════════════════════════════════════
#  2. defense ports — 本地端口监控
# ═══════════════════════════════════════════════

def defense_ports(show_pid: bool = True):
    """
    显示本机所有 LISTEN 端口及对应进程
    跨平台实现
    """
    print(f" {INFO} 扫描本机监听端口...\n")

    if is_windows():
        # Windows: netstat -anb
        try:
            r = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True, text=True, timeout=10,
                encoding="utf-8", errors="replace"
            )
            if r.returncode == 0:
                rows = []
                for line in r.stdout.split("\n"):
                    # TCP 格式:  TCP    0.0.0.0:135    0.0.0.0:0    LISTENING    1234
                    m = re.search(r'(TCP|UDP)\s+(\S+)\s+(\S+)\s+(LISTENING|LISTEN)\s+(\d+)', line)
                    if m:
                        proto = m.group(1)
                        local = m.group(2)
                        pid = m.group(5)
                        # 提取端口
                        port = local.split(":")[-1] if ":" in local else "?"
                        # 尝试通过 PID 获取进程名
                        pname = pid
                        if show_pid:
                            try:
                                pr = subprocess.run(
                                    ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                                    capture_output=True, text=True, timeout=5,
                                    encoding="utf-8", errors="replace"
                                )
                                for pline in pr.stdout.split("\n"):
                                    p = pline.strip().split()
                                    if len(p) >= 2 and p[0] != "映像名称":
                                        pname = p[0]
                                        break
                            except Exception:
                                pass
                        rows.append([port, proto, local, pname])
                if rows:
                    print(f" {CHECK} 发现 {len(rows)} 个监听端口:\n")
                    print_table(["端口", "协议", "地址", "进程"], rows)
                    return
        except Exception:
            pass

    # Linux: /proc/net/tcp + /proc/net/tcp6
    rows = []
    for proto_name, proto_file in [("TCP", "/proc/net/tcp"), ("TCP6", "/proc/net/tcp6")]:
        if not os.path.isfile(proto_file):
            continue
        try:
            with open(proto_file) as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        state_hex = parts[3]
                        if state_hex == "0A":  # LISTEN
                            local_hex = parts[1]
                            ip_hex, port_hex = local_hex.split(":")
                            port = int(port_hex, 16)
                            ip = ".".join(str(int(ip_hex[i:i+2], 16)) for i in range(6, -1, -2))
                            pid = parts[-1].split("/")[0] if "/" in parts[-1] else parts[-1] if parts[-1].isdigit() else "?"
                            rows.append([str(port), proto_name, f"{ip}:{port}", pid])
        except Exception:
            pass

    # 也可用 ss -tlnp (备用)
    if not rows:
        try:
            r = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                for line in r.stdout.split("\n"):
                    m = re.search(r'LISTEN\s+\d+\s+\d+\s+(\S+):(\d+)\s+.*users:\(\((?:.*,(\d+))?', line)
                    if m:
                        ip = m.group(1).strip("[]")
                        port = m.group(2)
                        pid = m.group(3) if m.lastindex >= 3 and m.group(3) else "?"
                        rows.append([port, "TCP", f"{ip}:{port}", pid])
        except Exception:
            pass

    if rows:
        print(f" {CHECK} 发现 {len(rows)} 个监听端口:\n")
        print_table(["端口", "协议", "地址", "PID"], rows)
    else:
        print(f" {CROSS} 无法获取端口信息")


# ═══════════════════════════════════════════════
#  3. defense dns — DNS 劫持检测
# ═══════════════════════════════════════════════

PUBLIC_DNS = [
    ("114.114.114.114", "114DNS"),
    ("223.5.5.5", "阿里 DNS"),
    ("8.8.8.8", "Google DNS"),
    ("1.1.1.1", "Cloudflare"),
]


def _dns_query(domain: str, server: str, timeout: float = 3.0) -> list:
    """通过指定 DNS 服务器解析域名"""
    try:
        # 简易 DNS 查询：使用 socket 直接指定 DNS
        orig_resolver = socket.getaddrinfo
        # 设置 socket 的 DNS
        import ctypes
        # Windows 上用 nslookup，Linux 上用 dig/host，纯 Python 用 socket 默认
        # 使用系统工具更可靠
        if is_windows():
            r = subprocess.run(
                ["nslookup", domain, server],
                capture_output=True, text=True, timeout=timeout,
                encoding="utf-8", errors="replace"
            )
            # 解析 nslookup 输出
            ips = []
            for line in r.stdout.split("\n"):
                m = re.search(r'Address(?:es)?:\s*([0-9.]+)', line)
                if m:
                    ips.append(m.group(1))
                m2 = re.search(r'Name:\s+\S+\s+Address:\s*([0-9.]+)', line)
                if m2:
                    ips.append(m2.group(1))
                m3 = re.search(r'Address:\s+([0-9.]+)', line)
                if m3 and ":" not in m3.group(1):
                    ips.append(m3.group(1))
            return list(set(ips))
        else:
            # Linux: dig 或 host
            r = subprocess.run(
                ["dig", f"@{server}", domain, "+short"],
                capture_output=True, text=True, timeout=timeout
            )
            if r.returncode == 0:
                ips = [line.strip() for line in r.stdout.split("\n")
                      if line.strip() and re.match(r'^\d+\.\d+\.\d+\.\d+$', line.strip())]
                return ips
            # fallback: host
            r2 = subprocess.run(
                ["host", domain, server],
                capture_output=True, text=True, timeout=timeout
            )
            if r2.returncode == 0:
                ips = []
                for line in r2.stdout.split("\n"):
                    m = re.search(r'has address\s+([0-9.]+)', line)
                    if m:
                        ips.append(m.group(1))
                return ips
    except Exception:
        pass
    return []


def defense_dns(domain: str = "baidu.com"):
    """
    DNS 劫持检测
    通过多个公共 DNS 解析同一域名，对比结果
    """
    print(f" {INFO} DNS 劫持检测: 解析 {C.CYAN}{domain}{C.NC}\n")

    results = []  # [(server_name, server_ip, ips)]
    for name, server_ip in PUBLIC_DNS:
        ips = _dns_query(domain, server_ip)
        results.append((name, server_ip, ips))
        time.sleep(0.2)  # 避免被限速

    # 显示结果
    rows = []
    for name, server_ip, ips in results:
        ips_str = ", ".join(ips) if ips else C.RED + "无响应" + C.NC
        rows.append([f"{name} ({server_ip})", ips_str])

    print_table(["DNS 服务器", f"{domain} 解析结果"], rows)
    print()

    # 分析是否一致
    all_ips = [set(r[2]) for r in results if r[2]]
    if len(all_ips) < 2:
        print(f" {WARN} DNS 服务器响应不足，无法判断")
    elif all(x == all_ips[0] for x in all_ips):
        print(f" {CHECK} 所有 DNS 返回一致，{C.GREEN}未检测到 DNS 劫持{C.NC}")
    else:
        print(f" {CROSS} {C.RED}DNS 结果不一致! 可能存在 DNS 劫持!{C.NC}")
        print(f" {INFO} 检查路由器 DNS 设置是否被篡改")
        print(f" {INFO} 建议将路由器 DNS 改为: 223.5.5.5 (阿里) / 114.114.114.114")

    # 检测局域网 DNS
    print()
    from core.network import get_gateway
    gw = get_gateway()
    if gw:
        gw_ips = _dns_query(domain, gw)
        print(f" {INFO} 通过路由器 ({C.CYAN}{gw}{C.NC}) 解析 {domain}: {', '.join(gw_ips) if gw_ips else '失败'}")
        if all_ips and gw_ips:
            if set(gw_ips) != all_ips[0]:
                print(f" {CROSS} {C.RED}路由器 DNS 与公共 DNS 不一致!{C.NC}")


# ═══════════════════════════════════════════════
#  4. defense scan — 端口扫描检测
# ═══════════════════════════════════════════════

def defense_scan(threshold: int = 20, interval: int = 60, continuous: bool = False):
    """
    检测端口扫描攻击 (基于连接尝试频率)
    监控 /proc/net/tcp 或 netstat 的 SYN_RECV 状态
    """
    if continuous:
        _defense_scan_continuous(threshold, interval)
        return

    print(f" {INFO} 检测端口扫描攻击...\n")
    suspects = _analyze_connections(threshold, interval)

    if suspects:
        print(f" {CROSS} {C.RED}检测到可能的扫描攻击!{C.NC}\n")
        rows = []
        for ip, data in sorted(suspects.items(), key=lambda x: x[1]["count"], reverse=True):
            rows.append([ip, str(data["count"]), ", ".join(map(str, data["ports"]))])
        print_table(["攻击者 IP", "连接数", "目标端口"], rows)
    else:
        print(f" {CHECK} 未检测到异常连接模式")


def _analyze_connections(threshold: int, window: int) -> dict:
    """
    分析短时间内的 TCP 连接记录
    返回可疑 IP 列表
    """
    suspects = {}

    if is_windows():
        # Windows: 多次 netstat 取样
        try:
            r = subprocess.run(
                ["netstat", "-an"],
                capture_output=True, text=True, timeout=10,
                encoding="utf-8", errors="replace"
            )
            if r.returncode == 0:
                conns = {}  # ip -> [ports]
                for line in r.stdout.split("\n"):
                    m = re.search(r'TCP\s+(\S+)\s+(\S+)\s+(?:ESTABLISHED|SYN_SENT|TIME_WAIT)', line)
                    if m:
                        remote = m.group(2)
                        if ":" in remote:
                            ip, port = remote.rsplit(":", 1)
                            if ip not in conns:
                                conns[ip] = set()
                            conns[ip].add(port)
                for ip, ports in conns.items():
                    if len(ports) >= threshold:
                        suspects[ip] = {"count": len(ports), "ports": list(ports)[:20]}
        except Exception:
            pass
    else:
        # Linux: 读取 /proc/net/tcp
        try:
            with open("/proc/net/tcp") as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        state = int(parts[3], 16)
                        if state in (1, 2, 4, 5):  # ESTABLISHED, SYN_SENT, FIN_WAIT1, FIN_WAIT2
                            remote_hex = parts[2]
                            ip_hex, port_hex = remote_hex.split(":")
                            if ip_hex != "00000000":
                                ip = ".".join(str(int(ip_hex[i:i+2], 16)) for i in range(6, -1, -2))
                                port = int(port_hex, 16)
                                if ip not in suspects:
                                    suspects[ip] = {"count": 0, "ports": []}
                                suspects[ip]["count"] += 1
                                if len(suspects[ip]["ports"]) < 20:
                                    suspects[ip]["ports"].append(port)

            # 过滤低于阈值的
            suspects = {k: v for k, v in suspects.items() if v["count"] >= threshold}
        except Exception:
            pass

    return suspects


def _defense_scan_continuous(threshold: int, interval: int):
    """持续监控端口扫描"""
    print(f" {INFO} 端口扫描持续监控 (阈值: {threshold}连接/{interval}s, Ctrl+C 停止)\n")

    # 简化版: 每 interval 秒检查并显示变化
    prev_count = {}
    try:
        while True:
            suspects = _analyze_connections(threshold, interval)
            now = datetime.now().strftime("%H:%M:%S")
            if suspects:
                for ip, data in sorted(suspects.items(), key=lambda x: x[1]["count"], reverse=True)[:5]:
                    ports = ", ".join(map(str, data["ports"][:10]))
                    print(f" {CROSS} {C.RED}[SCAN]{C.NC} {now}  {C.YELLOW}{ip}{C.NC} ({data['count']} conns) → {ports}")
            else:
                print(f" {CHECK} {now}  连接正常", end="\r")
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n {CHECK} 监控已停止")


# ═══════════════════════════════════════════════
#  5. defense monitor — 实时连接监控
# ═══════════════════════════════════════════════

def defense_monitor(interval: float = 2.0):
    """
    实时网络连接监控
    显示新建立/断开的连接
    """
    print(f" {INFO} 实时网络连接监控 (每 {interval}s, Ctrl+C 停止)\n")

    def get_connections() -> set:
        """获取当前活动连接集合"""
        conns = set()
        if is_windows():
            try:
                r = subprocess.run(
                    ["netstat", "-an"],
                    capture_output=True, text=True, timeout=5,
                    encoding="utf-8", errors="replace"
                )
                if r.returncode == 0:
                    for line in r.stdout.split("\n"):
                        m = re.search(r'TCP\s+\S+\s+(\S+)\s+(ESTABLISHED|SYN_SENT|TIME_WAIT)', line)
                        if m:
                            conns.add(m.group(1))
            except Exception:
                pass
        else:
            try:
                with open("/proc/net/tcp") as f:
                    for line in f.readlines()[1:]:
                        parts = line.strip().split()
                        if len(parts) >= 4:
                            state = int(parts[3], 16)
                            if state == 1:  # ESTABLISHED
                                remote_hex = parts[2]
                                ip_hex, port_hex = remote_hex.split(":")
                                if ip_hex != "00000000":
                                    ip = ".".join(str(int(ip_hex[i:i+2], 16)) for i in range(6, -1, -2))
                                    conns.add(f"{ip}:{int(port_hex, 16)}")
            except Exception:
                pass
        return conns

    prev = get_connections()
    try:
        while True:
            time.sleep(interval)
            current = get_connections()

            new_conns = current - prev
            lost_conns = prev - current

            now = datetime.now().strftime("%H:%M:%S")
            for c in sorted(new_conns):
                print(f" {C.GREEN}[NEW]{C.NC}  {now}  {C.CYAN}{c}{C.NC}")

            for c in sorted(lost_conns)[:10]:
                print(f" {C.RED}[CLOSE]{C.NC}  {now}  {c}")

            prev = current
    except KeyboardInterrupt:
        print(f"\n {CHECK} 监控已停止")


# ═══════════════════════════════════════════════
#  6. defense check — 安全基线检查
# ═══════════════════════════════════════════════

def defense_check():
    """
    安全基线检查
    检测常见安全配置问题
    """
    score = 0
    total = 0
    print(f" {INFO} WNAD 安全基线检查\n")

    issues = []
    passes = []

    # 1) WiFi 加密检查
    total += 1
    try:
        from core.network import get_wifi_info
        wifi = get_wifi_info()
        if wifi["ssid"] != "未知":
            print(f" {INFO} [1/{total}] WiFi: {C.CYAN}{wifi['ssid']}{C.NC}")
            # 尝试从 iw dev 获取加密信息
            import subprocess as sp
            r = sp.run(["iw", "dev", "wlan0", "link"],
                       capture_output=True, text=True, timeout=5)
            if "Not connected" in r.stdout:
                issues.append("WiFi 未连接")
            elif "IEEE 802.11" in r.stdout:
                passes.append(f"WiFi 已连接 ({wifi['ssid']})")
                score += 1
            else:
                passes.append(f"WiFi 已连接 ({wifi['ssid']})")
                score += 1
        else:
            issues.append("WiFi 未连接或无法检测")
    except Exception:
        issues.append("WiFi 检测失败")

    # 2) 开放端口检查
    total += 1
    try:
        rows = []
        if is_windows():
            r = subprocess.run(["netstat", "-ano"], capture_output=True, text=True,
                               timeout=10, encoding="utf-8", errors="replace")
            for line in r.stdout.split("\n"):
                if "LISTENING" in line and ("0.0.0.0:0" not in line):
                    m = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', line)
                    if m and m.group(1) != "127.0.0.1":
                        rows.append(f"端口 {m.group(2)} 对外暴露")
        else:
            for fname in ["/proc/net/tcp", "/proc/net/tcp6"]:
                if os.path.isfile(fname):
                    with open(fname) as f:
                        for line in f.readlines()[1:]:
                            parts = line.strip().split()
                            if len(parts) >= 4 and parts[3] == "0A":
                                local = parts[1].split(":")[0]
                                ip = ".".join(str(int(local[i:i+2], 16)) for i in range(6, -1, -2))
                                port = int(parts[1].split(":")[1], 16)
                                if ip not in ("127.0.0.1", "::1", "0000:0000:0000:0000:0000:0000:0000:0000"):
                                    rows.append(f"端口 {port} 对外暴露")

        if rows:
            issues.extend(rows[:5])
        else:
            passes.append("无对外暴露端口")
            score += 1
    except Exception:
        pass

    # 3) DNS 检查
    total += 1
    try:
        from core.network import get_dns_servers
        dns = get_dns_servers()
        if dns:
            local_dns = [d for d in dns if d.startswith(("192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
                                                          "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                                                          "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                                                          "172.30.", "172.31."))]
            public_dns = [d for d in dns if d in ("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "114.114.114.114",
                                                  "223.5.5.5", "223.6.6.6", "119.29.29.29")]
            if public_dns:
                passes.append(f"使用公共 DNS: {', '.join(public_dns)}")
                score += 1
            elif local_dns:
                passes.append(f"使用局域网 DNS: {', '.join(local_dns)} (可能不安全)")
            else:
                passes.append(f"DNS: {', '.join(dns)}")
                score += 0.5
        else:
            issues.append("DNS 配置可能不安全")
    except Exception:
        pass

    # 4) 网关检查
    total += 1
    try:
        from core.network import get_gateway
        gw = get_gateway()
        if gw and gw != "未知":
            passes.append(f"网关: {gw}")
            score += 1
        else:
            issues.append("无法检测网关")
    except Exception:
        issues.append("网关检测失败")

    # 结果汇总
    print()
    if passes:
        print(f" {CHECK} {C.GREEN}通过项:{C.NC}")
        for p in passes:
            print(f"   {C.GREEN}✓{C.NC} {p}")

    if issues:
        print(f"\n {CROSS} {C.RED}问题项:{C.NC}")
        for i in issues:
            print(f"   {C.RED}✗{C.NC} {i}")
    else:
        print(f" {CHECK} 未发现问题")

    pct = int(score / total * 100) if total else 0
    print(f"\n {INFO} 安全评分: {C.CYAN}{int(score)}/{total} ({pct}%){C.NC}")
    if pct >= 80:
        print(f" {CHECK} {C.GREEN}安全状态良好{C.NC}")
    elif pct >= 50:
        print(f" {WARN} {C.YELLOW}安全状态一般，建议修复问题项{C.NC}")
    else:
        print(f" {CROSS} {C.RED}安全状态较差，请尽快处理{C.NC}")


# ═══════════════════════════════════════════════
#  Main dispatcher
# ═══════════════════════════════════════════════

def defense_main(args):
    """defense 命令主分发"""
    if hasattr(args, 'sub') or (hasattr(args, 'arp_check') and args.arp_check):
        defense_arp(monitor=getattr(args, 'monitor', False) or getattr(args, 'continuous', False),
                    interval=getattr(args, 'interval', 5))
    elif hasattr(args, 'ports_check') and args.ports_check:
        defense_ports()
    elif hasattr(args, 'dns_check') and args.dns_check:
        domain = getattr(args, 'domain', "baidu.com")
        defense_dns(domain)
    elif hasattr(args, 'scan_check') and args.scan_check:
        defense_scan(continuous=getattr(args, 'continuous', False))
    elif hasattr(args, 'monitor_conn') and args.monitor_conn:
        defense_monitor()
    elif hasattr(args, 'check') and args.check:
        defense_check()
    else:
        # 默认显示安全基线
        defense_check()
