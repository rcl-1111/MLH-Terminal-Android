"""
WNAD - 网络设备发现模块 (netdiscover-like)
主动扫描网段中的存活设备，显示 IP + 主机名 + MAC + 厂商
纯 Python 实现，无需 root
"""

import subprocess
import re
import concurrent.futures
import threading
from core.utils import C, CHECK, CROSS, INFO, WARN, ARROW, print_table
from core.network import get_oui_vendor, get_gateway


def _auto_detect_cidr() -> str:
    """自动检测当前网络的 CIDR"""
    from core.utils import is_windows

    # Windows: ipconfig
    if is_windows():
        try:
            result = subprocess.run(
                ["ipconfig"],
                capture_output=True, text=True, timeout=5, encoding="utf-8", errors="replace"
            )
            if result.returncode == 0:
                ip = ""
                mask = ""
                for line in result.stdout.split("\n"):
                    ip_m = re.search(r'IPv4[^:]*:\s*(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_m:
                        ip = ip_m.group(1)
                    mask_m = re.search(r'子网掩码[^:]*:\s*(\d+\.\d+\.\d+\.\d+)', line)
                    if not mask_m:
                        mask_m = re.search(r'Subnet Mask[^:]*:\s*(\d+\.\d+\.\d+\.\d+)', line)
                    if mask_m:
                        mask = mask_m.group(1)
                    if ip and mask:
                        # 掩码转前缀长度
                        prefix = sum(bin(int(b)).count("1") for b in mask.split("."))
                        parts = ip.split(".")
                        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/{prefix}"
        except Exception:
            pass

    # Linux / Termux: ip route + ip addr
    try:
        # 先找默认路由接口
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5
        )
        iface = None
        if result.returncode == 0:
            match = re.search(r'dev\s+(\S+)', result.stdout)
            if match:
                iface = match.group(1)

        # 读所有接口，找第一个非回环的 IP
        addr = subprocess.run(
            ["ip", "-4", "addr", "show"],
            capture_output=True, text=True, timeout=5
        )
        if addr.returncode == 0:
            # 按接口分组解析
            blocks = addr.stdout.strip().split("\n\n")
            for block in blocks:
                lines = block.strip().split("\n")
                iface_name = ""
                for line in lines:
                    m = re.match(r'\d+:\s+(\S+):', line)
                    if m:
                        iface_name = m.group(1).split("@")[0]
                    ip_m = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', line)
                    if ip_m and iface_name != "lo":
                        ip = ip_m.group(1)
                        prefix = ip_m.group(2)
                        parts = ip.split(".")
                        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/{prefix}"
    except Exception:
        pass

    # 方法2: 获取网关地址推断网段
    gw = get_gateway()
    if gw and gw != "未知":
        parts = gw.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

    return ""


def _ping_host(ip_str: str, timeout: float = 1.0):
    """
    Ping 检测主机存活
    返回 (IP, hostname, mac, vendor) 或 None
    """
    try:
        from core.utils import ping_cmd
        cmd = ping_cmd(ip_str, timeout=timeout)
        if subprocess.run(
            cmd,
            capture_output=True, timeout=timeout + 1
        ).returncode == 0:
            hostname = ""
            mac = ""
            vendor = ""

            # 设备名解析 (DNS反解 → mDNS → NetBIOS → DHCP)
            from core.network import resolve_device_name, get_neighbor_table
            hostname = resolve_device_name(ip_str)

            # 从 ARP 表获取 MAC
            neigh = get_neighbor_table()
            if ip_str in neigh:
                mac = neigh[ip_str]["mac"]
                vendor = get_oui_vendor(mac)

            return (ip_str, hostname, mac, vendor)
    except Exception:
        pass
    return None


def discover(cidr: str = None, max_workers: int = None, timeout: float = 1.0, force: bool = False):
    """
    网络设备发现
    类似 Kali Linux 的 netdiscover
    - ping 扫描 + 反向 DNS + MAC/厂商查询
    - 实时逐行输出
    """
    # Windows 默认使用较少线程
    if max_workers is None:
        from core.utils import is_windows
        max_workers = 30 if is_windows() else 80
    # 自动检测 CIDR
    if not cidr:
        cidr = _auto_detect_cidr()
        if not cidr:
            print(f" {CROSS} 无法自动检测网段")
            print(f" {INFO} 请手动指定: {C.CYAN}wnad discover --cidr 192.168.1.0/24{C.NC}")
            return

    try:
        import ipaddress
        network = ipaddress.ip_network(cidr, strict=False)
    except Exception as e:
        print(f" {CROSS} 无效网段: {e}")
        return

    total = network.num_addresses
    if total > 65536:
        print(f" {WARN} 网段较大: {total} 个地址")
        if not force:
            try:
                ans = input(f" {ARROW} 确认扫描？(y/n): ").strip().lower()
                if ans not in ("y", "yes"):
                    print(f" {INFO} 已取消")
                    return
            except (EOFError, KeyboardInterrupt):
                print()
                return

    print(f"\n {C.BOLD}{C.CYAN}Net Discovery{C.NC}  —  {C.YELLOW}scanning{C.NC} {C.CYAN}{cidr}{C.NC}  ({total} hosts)\n")

    # 输出表头
    header = (
        f" {C.BOLD}{'IP':<18}{'Hostname':<35}{'MAC':<20}{'Vendor'}{C.NC}"
    )
    print(header)
    print(f" {C.DIM}{'─'*90}{C.NC}")

    hosts = []
    processed = 0
    found = 0

    hosts_to_scan = list(network.hosts()) if network.prefixlen < 31 else [ip for ip in network]

    # 用信号量限制并发子进程数，防止 Windows ping.exe 崩溃
    from core.utils import is_windows
    ping_limit = 8 if is_windows() else max_workers
    ping_sema = threading.BoundedSemaphore(ping_limit)

    def _ping_host_safe(ip_str: str) -> tuple:
        with ping_sema:
            return _ping_host(ip_str, timeout)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_ping_host_safe, str(ip)): str(ip) for ip in hosts_to_scan}

        for future in concurrent.futures.as_completed(futures):
            processed += 1
            result = future.result()
            if result:
                ip, hostname, mac, vendor = result
                hosts.append(result)
                found += 1

                # 实时输出
                disp_name = hostname if hostname else (vendor[:32] if vendor and vendor != "未知" else "-")
                hostname_short = (disp_name[:32] + "..") if len(disp_name) > 34 else disp_name
                mac_display = mac if mac else "-"
                vendor_display = vendor[:18] if vendor else ""
                print(
                    f" {C.GREEN}[+]{C.NC}  {ip:<18}"
                    f"{hostname_short:<35}"
                    f"{mac_display:<20}"
                    f"{C.DIM}{vendor_display}{C.NC}"
                )

            # 进度提示
            if processed % 50 == 0:
                print(f" {INFO}  {C.DIM}progress: {processed}/{total}  |  found: {found}{C.NC}", end="\r")

    print(f"\n {C.DIM}{'─'*90}{C.NC}")
    print()

    # 总结
    if hosts:
        print(f" {CHECK} Discovery complete: {C.CYAN}{found}{C.NC} devices found on {C.CYAN}{cidr}{C.NC}\n")

        # 表格展示
        rows = []
        for i, (ip, hostname, mac, vendor) in enumerate(hosts):
            dev_name = hostname if hostname else (vendor if vendor else "-")
            rows.append([
                str(i + 1),
                ip,
                dev_name,
                mac if mac else "-",
                vendor if vendor else "-",
            ])

        print_table(["#", "IP", "Hostname", "MAC", "Vendor"], rows)
    else:
        print(f" {INFO} No devices found on {cidr}")
