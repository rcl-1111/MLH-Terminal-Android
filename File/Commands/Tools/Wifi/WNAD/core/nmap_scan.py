"""
WNAD - nmap 风格扫描模块
纯 Python 实现，无外部依赖
功能: 端口扫描(TCP/UDP/SYN) | 服务指纹 | OS检测 | 时序模板
"""

import os
import re
import sys
import time
import socket
import struct
import subprocess
import concurrent.futures
from datetime import datetime
from core.utils import C, CHECK, CROSS, INFO, WARN, print_table, is_windows


# ── 常用端口 TOP 100 ──
TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 5986,
    6379, 8080, 8443, 9000, 9090, 27017]

TOP_PORTS_1000 = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 82, 83, 88, 106,
    110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443,
    444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 636,
    646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433,
    1521, 1604, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717,
    3000, 3128, 3268, 3306, 3360, 3386, 3389, 3390, 3986, 4000, 4001,
    4662, 4899, 5000, 5001, 5003, 5050, 5060, 5101, 5190, 5353, 5355,
    5432, 5631, 5666, 5800, 5801, 5900, 5901, 5984, 5985, 5986, 6000,
    6001, 6002, 6003, 6004, 6379, 6660, 6665, 6666, 6667, 6668, 6669,
    7000, 7001, 7070, 7100, 7777, 8000, 8001, 8008, 8009, 8010, 8080,
    8081, 8443, 8888, 9000, 9001, 9090, 9100, 9200, 9418, 9999, 10000,
    11211, 12345, 27017, 28017, 31337, 49152, 49153, 49154, 49155,
    49156, 49157, 49158, 49159, 49160, 49161, 49162, 49163, 49164,
    49165, 49166, 49167, 49168, 49169, 49170, 49171, 49172, 49173,
    49174, 49175, 49176, 49177, 49178, 49179, 49180, 49181, 49182,
    49183, 49184, 49185, 49186, 49187, 49188, 49189, 49190, 49191,
    49192, 49193, 49194, 49195, 49196, 49197, 49198, 49199, 49200,
    49201, 49202, 49203, 49204, 49205, 49206, 49207, 49208, 49209,
    49210, 49211, 49212, 49213, 49214, 49215, 49216, 49217, 49218,
    49219, 49220, 49221, 49222, 49223, 49224, 49225, 49226, 49227,
    49228, 49229, 49230, 49231, 49232, 49233, 49234, 49235, 49236,
    49237, 49238, 49239, 49240, 49241, 49242, 49243, 49244, 49245,
    49246, 49247, 49248, 49249, 49250, 49251, 49252, 49253, 49254,
    49255, 49256, 49257, 49258, 49259, 49260, 49261, 49262, 49263,
    49264, 49265, 49266, 49267, 49268, 49269, 49270, 49271, 49272,
    49273, 49274, 49275, 49276, 49277, 49278, 49279, 49280, 49281,
    49282, 49283, 49284, 49285, 49286, 49287, 49288, 49289, 49290,
    49291, 49292, 49293, 49294, 49295, 49296, 49297, 49298, 49299,
    49300, 49301, 49302, 49303, 49304, 49305, 49306, 49307, 49308,
    49309, 49310, 49311, 49312, 49313, 49314, 49315, 49316, 49317,
    49318, 49319, 49320, 49321, 49322, 49323, 49324, 49325, 49326,
    49327, 49328, 49329, 49330, 49331, 49332, 49333, 49334, 49335,
    49336, 49337, 49338, 49339, 49340, 49341, 49342, 49343, 49344,
    49345, 49346, 49347, 49348, 49349, 49350, 49351, 49352, 49353,
    49354, 49355, 49356, 49357, 49358, 49359, 49360, 49361, 49362,
    49363, 49364, 49365, 49366, 49367, 49368, 49369, 49370, 49371,
    49372, 49373, 49374, 49375, 49376, 49377, 49378, 49379, 49380,
    49381, 49382, 49383, 49384, 49385, 49386, 49387, 49388, 49389,
    49390, 49391, 49392, 49393, 49394, 49395, 49396, 49397, 49398,
    49399, 49400,
]

# ── 服务名映射 ──
SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 389: "ldap", 443: "https",
    445: "microsoft-ds", 465: "smtps", 514: "syslog", 543: "klogin",
    544: "kshell", 548: "afp", 554: "rtsp", 587: "submission",
    631: "ipp", 636: "ldaps", 873: "rsync", 990: "ftps",
    992: "telnets", 993: "imaps", 995: "pop3s", 1433: "ms-sql-s",
    1521: "oracle", 1723: "pptp", 2049: "nfs", 3306: "mysql",
    3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc",
    5985: "wsman", 5986: "wsmans", 6379: "redis", 8080: "http-proxy",
    8443: "https-alt", 9090: "http-alt", 9200: "elasticsearch",
    11211: "memcache", 27017: "mongod", 28017: "mongod-http",
}

# ── OS 指纹库 (TTL + 窗口大小) ──
OS_FINGERPRINTS = [
    {"name": "Linux (2.6/3.x/4.x)", "ttl_max": 64, "ttl_min": 64},
    {"name": "Windows (7/10/11/Server)", "ttl_max": 128, "ttl_min": 128},
    {"name": "Windows (2000/XP)", "ttl_max": 128, "ttl_min": 128},
    {"name": "FreeBSD / macOS", "ttl_max": 64, "ttl_min": 64},
    {"name": "Cisco IOS", "ttl_max": 255, "ttl_min": 255},
    {"name": "Solaris / HP-UX", "ttl_max": 255, "ttl_min": 255},
    {"name": "Android", "ttl_max": 64, "ttl_min": 64},
    {"name": "路由器/嵌入式", "ttl_max": 255, "ttl_min": 255},
]


# ── 辅助函数 ──

def _parse_targets(target: str) -> list:
    """解析目标格式: IP, 域名, CIDR, 范围"""
    import ipaddress
    ips = []

    # CIDR
    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
            if net.num_addresses > 256:
                return ["CIDR_TOO_LARGE"]
            return [str(ip) for ip in net.hosts()] if net.prefixlen < 31 else [str(net[0])]
        except ValueError:
            pass

    # IP 范围: 192.168.1.1-100
    m = re.match(r'^(\d+\.\d+\.\d+)\.(\d+)-(\d+)$', target)
    if m:
        prefix = m.group(1)
        lo, hi = int(m.group(2)), int(m.group(3))
        return [f"{prefix}.{i}" for i in range(lo, hi + 1)]

    # 域名
    try:
        for info in socket.getaddrinfo(target, 80):
            ip = info[4][0]
            if ip and ip not in ips:
                ips.append(ip)
        if ips:
            return ips
    except socket.gaierror:
        pass

    # 单个 IP
    try:
        socket.inet_aton(target)
        return [target]
    except socket.error:
        pass

    return []


def _guess_os(ttl: int) -> str:
    """根据 TTL 猜测操作系统"""
    for os_info in OS_FINGERPRINTS:
        if os_info["ttl_min"] <= ttl <= os_info["ttl_max"]:
            return os_info["name"]

    if ttl <= 64:
        return "Linux/Unix (likely)"
    elif ttl <= 128:
        return "Windows (likely)"
    elif ttl <= 255:
        return "网络设备 (likely)"
    return "未知"


def _service_name(port: int) -> str:
    """端口号转服务名"""
    return SERVICES.get(port, "")


def _banner_grab(ip: str, port: int, timeout: float = 2.0) -> str:
    """获取服务 Banner"""
    for proto_name in [b"", b" \r\n", b"GET / HTTP/1.0\r\n\r\n", b"HEAD / HTTP/1.0\r\n\r\n"]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            if proto_name:
                s.send(proto_name)
            data = s.recv(1024)
            s.close()
            if data:
                text = data.decode("utf-8", errors="replace").strip()
                # 清理不可见字符
                text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', ' ', text)
                text = re.sub(r'\s+', ' ', text)
                if text:
                    return text[:100]
        except Exception:
            pass
    return ""


def _ping_host(ip: str, timeout: float = 1.0) -> dict:
    """Ping 检测主机存活，返回 TTL 信息"""
    from core.utils import ping_cmd
    try:
        cmd = ping_cmd(ip, timeout=timeout)
        r = subprocess.run(cmd, capture_output=True, timeout=timeout + 1)
        stdout = r.stdout.decode("utf-8", errors="replace")
        if r.returncode == 0:
            # 提取 TTL
            ttl = 64
            ttl_m = re.search(r'(?:TTL|ttl)[=<]\s*(\d+)', stdout)
            if ttl_m:
                ttl = int(ttl_m.group(1))
            return {"ip": ip, "alive": True, "ttl": ttl}
    except Exception:
        pass
    return {"ip": ip, "alive": False, "ttl": 0}


def _scan_tcp(ip: str, port: int, timeout: float) -> dict:
    """TCP Connect 端口扫描"""
    result = {"port": port, "state": "filtered", "service": _service_name(port), "banner": ""}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        code = s.connect_ex((ip, port))
        s.close()
        if code == 0:
            result["state"] = "open"
        elif code == 111:
            result["state"] = "closed"
        else:
            result["state"] = "filtered"
    except socket.timeout:
        result["state"] = "filtered"
    except OSError as e:
        # Windows: WSAETIMEDOUT = 10060
        result["state"] = "filtered"
    return result


def _scan_udp(ip: str, port: int, timeout: float) -> dict:
    """UDP 端口扫描"""
    result = {"port": port, "state": "open|filtered", "service": _service_name(port), "banner": ""}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(b"", (ip, port))
        data, _ = s.recvfrom(1024)
        result["state"] = "open"
        if data:
            result["banner"] = data.decode("utf-8", errors="replace")[:60]
        s.close()
    except socket.timeout:
        result["state"] = "open|filtered"
    except ConnectionRefusedError:
        result["state"] = "closed"
    except OSError:
        result["state"] = "closed"
    except Exception:
        pass
    return result


def _detect_os_from_ttl(ttl: int) -> str:
    """TTL → OS 猜测"""
    os_name = _guess_os(ttl)
    details = ""
    if ttl < 64:
        details = f" (TTL={ttl}, 可能为经过路由后的值)"
    elif ttl == 64:
        details = f" (TTL={ttl}, 典型值)"
    elif ttl == 128:
        details = f" (TTL={ttl}, 典型值)"
    elif ttl == 255:
        details = f" (TTL={ttl}, 典型值)"
    else:
        details = f" (TTL={ttl})"
    return os_name + details


# ── 时序模板 ──

def _apply_timing(template: str) -> dict:
    """时序模板参数"""
    timing = {
        -1: {"workers": 100, "timeout": 1.0, "delay": 0, "label": "默认"},
        0:  {"workers": 5,  "timeout": 5.0, "delay": 5,  "label": "T0 偏执"},
        1:  {"workers": 10, "timeout": 2.0, "delay": 1,  "label": "T1 渗入"},
        2:  {"workers": 50, "timeout": 1.0, "delay": 0,  "label": "T2 适度"},
        3:  {"workers": 100,"timeout": 1.0, "delay": 0,  "label": "T3 普通"},
        4:  {"workers": 200,"timeout": 0.5, "delay": 0,  "label": "T4 激进"},
        5:  {"workers": 500,"timeout": 0.3, "delay": 0,  "label": "T5 疯狂"},
    }
    t = template.upper()
    if t == "T0": return timing[0]
    if t == "T1": return timing[1]
    if t == "T2": return timing[2]
    if t == "T3" or t == "": return timing[3]
    if t == "T4": return timing[4]
    if t == "T5": return timing[5]
    if "0" <= template <= "5":
        return timing.get(int(template), timing[-1])
    return timing[-1]


# ── 端口列表解析 ──

def _parse_ports(port_arg: str) -> list:
    """解析端口参数: 80 | 80,443 | 1-1000 | top100 | top1000"""
    if isinstance(port_arg, list):
        return port_arg

    if port_arg.startswith("top"):
        n = int(port_arg[3:]) if port_arg[3:] else 100
        if n >= 1000:
            return TOP_PORTS_1000
        return TOP_PORTS[:n]

    ports = set()
    parts = port_arg.split(",")
    for part in parts:
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo, hi = int(lo.strip()), int(hi.strip())
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part.strip()))
    return sorted(ports)


# ═══════════════════════════════════════════════
#  nmap 主函数
# ═══════════════════════════════════════════════

def nmap_scan(target: str = None, ports: str = "top100", scan_type: str = "tcp",
              version_detect: bool = False, os_detect: bool = False,
              verbose: bool = False, timing: str = "T3",
              output_file: str = "", resolve: bool = True,
              **kwargs):
    """
    nmap 风格综合扫描
    """
    # ── 解析目标 ──
    if not target:
        print(f" {CROSS} 请指定目标: {C.CYAN}wnad nmap <target>{C.NC}")
        return

    targets = _parse_targets(target)
    if not targets:
        print(f" {CROSS} 无法解析目标: {target}")
        return
    if targets == ["CIDR_TOO_LARGE"]:
        print(f" {CROSS} CIDR 网段过大，请缩小范围（最大 /24）")
        return

    # ── 时序参数 ──
    tm = _apply_timing(timing)
    timeout = tm["timeout"]
    max_workers = tm["workers"]
    delay = tm["delay"]

    # ── 解析端口列表 ──
    port_list = _parse_ports(ports)

    # ── 握手 ──
    print(f"\n {C.BOLD}{C.CYAN}Nmap Scan{C.NC}")
    print(f" {C.DIM}{'─'*60}{C.NC}")
    print(f" {INFO} 目标:    {C.CYAN}{target}{C.NC} ({len(targets)} host(s))")
    print(f" {INFO} 端口:    {len(port_list)} port(s)  ({ports})")
    print(f" {INFO} 类型:    {scan_type.upper()}")
    print(f" {INFO} 时序:    {tm['label']} (workers={max_workers}, timeout={timeout}s)")
    if version_detect:
        print(f" {INFO} 服务探测: 开")
    if os_detect:
        print(f" {INFO} OS检测:  开")
    print()

    results = []

    for ip in targets:
        host_result = {"ip": ip, "hostname": "", "alive": True, "ports": [],
                       "os_guess": "", "ttl": 0}

        # 主机名反解
        if resolve:
            try:
                host_result["hostname"] = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass

        # Ping 探测 + OS 检测
        ping_info = _ping_host(ip, timeout=timeout)
        if not ping_info["alive"] and "P" not in scan_type.upper():
            if verbose:
                print(f" {C.DIM}   {ip}: 主机似乎已关闭{C.NC}")
            host_result["alive"] = False
            results.append(host_result)
            continue

        host_result["ttl"] = ping_info["ttl"]
        if os_detect and ping_info["ttl"]:
            host_result["os_guess"] = _detect_os_from_ttl(ping_info["ttl"])

        if verbose:
            hostname_str = f" ({host_result['hostname']})" if host_result['hostname'] else ""
            print(f" {C.GREEN}→{C.NC} 扫描 {C.CYAN}{ip}{C.NC}{hostname_str}   TTL={ping_info['ttl']}")
            if host_result['os_guess']:
                print(f"   {C.DIM}OS 猜测: {host_result['os_guess']}{C.NC}")

        # ── 端口扫描 ──
        scan_func = _scan_udp if scan_type.upper().startswith("U") else _scan_tcp
        sema_count = 8 if is_windows() else max_workers

        import threading
        sema = threading.BoundedSemaphore(sema_count)

        def scan_port(port: int) -> dict:
            with sema:
                if delay > 0:
                    time.sleep(delay)
                res = scan_func(ip, port, timeout)
                if scan_type.upper() == "TCP" and res["state"] == "open":
                    # Banner 获取
                    if version_detect:
                        res["banner"] = _banner_grab(ip, port, timeout)
                    else:
                        res["banner"] = ""
                return res

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = [pool.submit(scan_port, p) for p in port_list]
            for i, future in enumerate(concurrent.futures.as_completed(futures)):
                res = future.result()
                if res["state"] in ("open", "open|filtered"):
                    host_result["ports"].append(res)
                if verbose and (i + 1) % max(1, len(port_list) // 20) == 0:
                    pct = (i + 1) * 100 // len(port_list)
                    print(f"   {C.DIM}progress: {i+1}/{len(port_list)} ({pct}%){C.NC}")

        # 显示结果
        if host_result["ports"]:
            print(f"\n {CHECK} {ip} 的端口:\n")
            rows = []
            for p in sorted(host_result["ports"], key=lambda x: x["port"]):
                svc = p.get("service", "")
                banner = p.get("banner", "")
                banner_short = banner[:50] if banner else ""
                state_color = C.GREEN if p["state"] == "open" else C.YELLOW
                rows.append([
                    str(p["port"]),
                    svc,
                    f"{state_color}{p['state']}{C.NC}",
                    banner_short,
                ])
            print_table(["PORT", "SERVICE", "STATE", "BANNER"], rows)

            if host_result["os_guess"]:
                print(f"\n {INFO} OS: {C.CYAN}{host_result['os_guess']}{C.NC}")
        else:
            if verbose:
                print(f" {WARN} {ip}: 所有端口 filtered/closed")

        results.append(host_result)
        print()

    # 汇总
    total_open = sum(len(h["ports"]) for h in results if h["alive"])
    total_alive = sum(1 for h in results if h["alive"])
    print(f" {CHECK} Nmap 扫描完成: {total_alive} hosts up, {total_open} open ports")

    # 输出到文件
    if output_file:
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(f"# Nmap scan - {target}\n")
                f.write(f"# Time: {datetime.now().isoformat()}\n")
                f.write(f"# Hosts: {total_alive} up, {len(results)} total\n\n")
                for h in results:
                    f.write(f"Host: {h['ip']}")
                    if h["hostname"]:
                        f.write(f" ({h['hostname']})")
                    f.write(f"  Status: {'Up' if h['alive'] else 'Down'}\n")
                    if h["os_guess"]:
                        f.write(f"  OS: {h['os_guess']}\n")
                    for p in h["ports"]:
                        f.write(f"  {p['port']}/tcp  {p['state']}  {p.get('service','')}\n")
                    f.write("\n")
            print(f"   {CHECK} 结果已保存: {output_file}")
        except Exception as e:
            print(f"   {WARN} 保存失败: {e}")

    return results
