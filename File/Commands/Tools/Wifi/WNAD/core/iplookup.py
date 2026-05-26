"""
WNAD - IP 查询模块
域名解析、CIDR 网段扫描、公网 IP 查询
纯 Python 实现，兼容 Android Termux
"""

import socket
import ipaddress
import subprocess
import concurrent.futures
from datetime import datetime
from core.utils import C, CHECK, CROSS, INFO, print_table, progress_bar, save_results


def resolve_domain(domain: str) -> list:
    """
    解析域名到 IP 地址（支持 IPv4 + IPv6）
    返回 [(类型, IP), ...]
    """
    results = []
    if not domain:
        print(f" {CROSS} 请输入有效的域名")
        return results

    # 移除协议前缀
    domain = domain.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

    print(f" {INFO} 正在解析域名: {C.CYAN}{domain}{C.NC}")

    # IPv4 解析
    try:
        addrs = socket.getaddrinfo(domain, 80, socket.AF_INET)
        seen = set()
        for addr in addrs:
            ip = addr[4][0]
            if ip not in seen:
                seen.add(ip)
                results.append(("IPv4", ip))
    except socket.gaierror:
        pass

    # IPv6 解析
    try:
        addrs = socket.getaddrinfo(domain, 80, socket.AF_INET6)
        seen_v6 = set()
        for addr in addrs:
            ip = addr[4][0].split("%")[0]  # 去除 scope id
            if ip not in seen_v6:
                seen_v6.add(ip)
                results.append(("IPv6", ip))
    except socket.gaierror:
        pass

    # 反向解析
    if results:
        print(f" {CHECK} 找到 {len(results)} 个记录:\n")
        headers = ["类型", "IP 地址"]
        print_table(headers, results)
    else:
        print(f" {CROSS} 域名解析失败: {domain}")

    return results


def scan_cidr(cidr: str, max_workers: int = 50, timeout: float = 1.0):
    """
    扫描 CIDR 网段存活主机
    通过 Ping 快速检测
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        print(f" {CROSS} 无效的 CIDR 网段: {e}")
        return []

    total = network.num_addresses
    if total > 65536:
        print(f" {CROSS} 网段过大 (>{total} 个地址)，请缩小范围")
        return []

    print(f" {INFO} 正在扫描网段 {C.CYAN}{cidr}{C.NC} ({total} 个地址)")
    print(f" {INFO} 使用 {max_workers} 线程，超时 {timeout}s\n")

    live_hosts = []
    processed = 0

    def ping_host(ip_str: str):
        """Ping 检测主机存活，返回 (IP, 主机名)"""
        nonlocal processed
        try:
            if subprocess.run(
                ["ping", "-c", "1", "-W", str(int(timeout)), ip_str],
                capture_output=True, timeout=timeout + 1
            ).returncode == 0:
                # 尝试反向解析主机名
                hostname = ""
                try:
                    hostname = socket.gethostbyaddr(ip_str)[0]
                except Exception:
                    pass
                return (ip_str, hostname)
        except Exception:
            pass
        finally:
            processed += 1
            if processed % 10 == 0 or processed == total:
                progress_bar(processed, total, f"扫描中 {processed}/{total}")
        return None

    # 跳过网络地址和广播地址（对 /24 以上）
    hosts_to_scan = list(network.hosts()) if network.prefixlen < 31 else [ip for ip in network]

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(ping_host, str(ip)): str(ip) for ip in hosts_to_scan}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                live_hosts.append(result)

    print()
    if live_hosts:
        print(f" {CHECK} 发现 {len(live_hosts)} 个存活主机:\n")
        rows = []
        for i, (ip, hostname) in enumerate(live_hosts):
            dev_name = hostname if hostname else "-"
            rows.append([str(i + 1), ip, dev_name])
        print_table(["#", "IP 地址", "设备名"], rows)

        # 保存结果
        save_results("cidr_scan", {
            "time": datetime.now().isoformat(),
            "cidr": cidr,
            "count": len(live_hosts),
            "hosts": [{"ip": h[0], "hostname": h[1]} for h in live_hosts],
        })
    else:
        print(f" {INFO} 未发现存活主机")

    return live_hosts


def get_public_ip() -> str:
    """查询本机公网 IP 地址"""
    services = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
        "https://ipinfo.io/ip",
    ]

    print(f" {INFO} 正在查询公网 IP...")

    for url in services:
        try:
            # 使用 subprocess 调用 curl/wget（纯 Python urllib 在 Termux 不可靠）
            for cmd in [
                ["curl", "-s", "--connect-timeout", "3", url],
                ["wget", "-qO-", "--timeout=3", url],
            ]:
                try:
                    result = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=5
                    )
                    ip = result.stdout.strip()
                    if ip and re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                        return ip
                except Exception:
                    continue
        except Exception:
            continue

    # 最后尝试 Python urllib
    try:
        from urllib.request import urlopen
        with urlopen("https://api.ipify.org", timeout=5) as resp:
            ip = resp.read().decode().strip()
            if ip:
                return ip
    except Exception:
        pass

    return ""


import re

def lookup_public():
    """显示公网 IP 信息"""
    ip = get_public_ip()
    if ip:
        print(f" {CHECK} 本机公网 IP: {C.CYAN}{C.BOLD}{ip}{C.NC}")
    else:
        print(f" {CROSS} 无法获取公网 IP（请检查网络连接）")
