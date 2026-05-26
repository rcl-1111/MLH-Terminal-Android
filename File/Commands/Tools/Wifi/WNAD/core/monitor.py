"""
WNAD - WiFi 监控模式模块 [需要 ROOT 权限]
控制 RT3070L 网卡的 Monitor Mode
基于 iw / iwconfig 命令
"""

import subprocess
import re
import os
import time
import signal
from core.utils import C, CHECK, CROSS, INFO, ROOT, WARN, print_table, save_results
from core.root_check import require_root_graceful
from core.network import get_wifi_info


def _run_cmd(cmd: list, timeout: int = 10) -> tuple:
    """运行系统命令，返回 (retcode, stdout, stderr)"""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return -1, "", "命令不存在"
    except subprocess.TimeoutExpired:
        return -1, "", "超时"
    except Exception as e:
        return -1, "", str(e)


def _get_wifi_interfaces() -> list:
    """获取 WiFi 接口列表（支持监控模式）"""
    ifaces = []
    sys_path = "/sys/class/net"
    if os.path.isdir(sys_path):
        for iface in sorted(os.listdir(sys_path)):
            type_path = f"{sys_path}/{iface}/type"
            if os.path.isfile(type_path):
                with open(type_path) as f:
                    try:
                        iface_type = int(f.read().strip())
                        if iface_type == 772:  # WiFi/WLAN
                            ifaces.append(iface)
                    except ValueError:
                        pass

    # 备用: 通过 iwconfig 检测
    if not ifaces:
        rc, out, _ = _run_cmd(["iwconfig"])
        if rc == 0:
            for line in out.split("\n"):
                match = re.match(r'^(\S+)\s+', line)
                if match:
                    ifname = match.group(1)
                    if ifname != "lo" and ifname not in ifaces:
                        ifaces.append(ifname)

    return ifaces


def monitor_enable(iface: str = None):
    """开启监控模式"""
    root = require_root_graceful("开启监控模式", "退化为 WiFi 信息查看")
    if root is True:
        _monitor_enable_root(iface)
    elif root is False:
        wifi_scan_info()
    # None = 取消


def _monitor_enable_root(iface: str = None):

    if not iface:
        ifaces = _get_wifi_interfaces()
        if not ifaces:
            print(f" {CROSS} 未检测到 WiFi 网卡")
            return
        iface = ifaces[0]
        print(f" {INFO} 自动选择接口: {C.CYAN}{iface}{C.NC}")

    print(f" {ROOT} 开启 {C.CYAN}{iface}{C.NC} 监控模式...\n")

    # 方法1: iw 命令
    print(f" {INFO} 方法1: 使用 iw 命令...")
    rc, out, err = _run_cmd(["iw", iface, "set", "monitor", "control"])
    if rc == 0:
        print(f" {CHECK} 监控模式已开启 (iw)")
    else:
        print(f" {WARN} iw 命令失败: {err}")
        # 方法2: iwconfig
        print(f" {INFO} 方法2: 使用 iwconfig 命令...")
        rc2, out2, err2 = _run_cmd(["iwconfig", iface, "mode", "monitor"])
        if rc2 == 0:
            print(f" {CHECK} 监控模式已开启 (iwconfig)")
        else:
            print(f" {CROSS} iwconfig 也失败: {err2}")
            print(f" {INFO} 可能原因: 网卡不支持、驱动未加载、或需要卸载后重载驱动")
            print(f" {INFO} 尝试: {C.YELLOW}ip link set {iface} down{C.NC}")
            print(f" {INFO} 然后重试本命令")
            return

    # 验证
    time.sleep(1)
    rc, out, _ = _run_cmd(["iwconfig", iface])
    if rc == 0 and "Mode:Monitor" in out:
        print(f"\n {CHECK} 验证成功: {iface} 已处于监控模式")
        mode = re.search(r'Mode:(\S+)', out)
        print(f"   模式: {mode.group(1) if mode else 'Monitor'}")
    else:
        print(f"\n {INFO} 状态未知，请手动检查: {C.YELLOW}iwconfig{C.NC}")


def monitor_disable(iface: str = None):
    """关闭监控模式，恢复 managed 模式"""
    root = require_root_graceful("关闭监控模式", "非 root 下无需关闭监控模式")
    if root is not True:
        return

    if not iface:
        ifaces = _get_wifi_interfaces()
        if not ifaces:
            print(f" {CROSS} 未检测到 WiFi 网卡")
            return
        iface = ifaces[0]

    print(f" {ROOT} 关闭 {C.CYAN}{iface}{C.NC} 监控模式...\n")

    # 先关 interface
    _run_cmd(["ip", "link", "set", iface, "down"])

    # 方法1: iw
    rc, _, err = _run_cmd(["iw", iface, "set", "type", "managed"])
    if rc == 0:
        print(f" {CHECK} 已恢复为 Managed 模式 (iw)")
    else:
        # 方法2: iwconfig
        rc2, _, err2 = _run_cmd(["iwconfig", iface, "mode", "managed"])
        if rc2 == 0:
            print(f" {CHECK} 已恢复为 Managed 模式 (iwconfig)")
        else:
            print(f" {CROSS} 恢复失败: {err2}")

    # 重新启用
    _run_cmd(["ip", "link", "set", iface, "up"])
    print(f" {CHECK} 接口 {iface} 已重新启用")


def monitor_scan(iface: str = None):
    """扫描周围 WiFi AP"""
    root = require_root_graceful("扫描 WiFi AP", "退化为 WiFi 信息查看")
    if root is True:
        _monitor_scan_root(iface)
    elif root is False:
        wifi_scan_info(iface)
    # None = 取消


def _monitor_scan_root(iface: str = None):

    if not iface:
        ifaces = _get_wifi_interfaces()
        if not ifaces:
            print(f" {CROSS} 未检测到 WiFi 网卡")
            return
        iface = ifaces[0]

    print(f" {ROOT} 扫描周围 WiFi AP (接口: {C.CYAN}{iface}{C.NC})")
    print(f" {INFO} 扫描需要 5-10 秒，请稍候...\n")

    # iw scan (需要在 managed 模式)
    rc, out, err = _run_cmd(["iw", iface, "scan"], timeout=15)

    if rc != 0 or not out:
        # 备用: iwlist
        print(f" {INFO} iw scan 失败，尝试 iwlist...")
        rc, out, err = _run_cmd(["iwlist", iface, "scan"], timeout=15)

    if rc != 0 or not out:
        print(f" {CROSS} 扫描失败: {err}")
        print(f" {INFO} 确保接口已启用: {C.YELLOW}ip link set {iface} up{C.NC}")
        return

    # 解析结果
    aps = []
    current_ap = {}

    for line in out.split("\n"):
        # iw 格式
        bssid_match = re.search(r'BSS\s+([0-9a-fA-F:]{17})', line)
        if bssid_match:
            if current_ap:
                aps.append(current_ap)
            current_ap = {"bssid": bssid_match.group(1), "ssid": "?", "signal": "?", "channel": "?", "enc": "?"}
            continue

        ssid_match = re.search(r'SSID:\s*(.+)', line)
        if ssid_match and current_ap:
            current_ap["ssid"] = ssid_match.group(1).strip()

        # iwlist 格式
        essid_match = re.search(r'ESSID:"([^"]*)"', line)
        if essid_match:
            current_ap["ssid"] = essid_match.group(1)
            continue

        bssid2 = re.search(r'Cell\s+\d+.*Address:\s*([0-9a-fA-F:]{17})', line)
        if bssid2:
            if current_ap:
                aps.append(current_ap)
            current_ap = {"bssid": bssid2.group(1), "ssid": "?", "signal": "?", "channel": "?", "enc": "?"}
            continue

        # 信号强度
        sig_match = re.search(r'signal:\s*(-?\d+)', line) or re.search(r'Quality[=:]\S+\s+Signal level[=:](-?\d+)', line)
        if sig_match and current_ap:
            dbm = int(sig_match.group(1))
            if dbm < 0:
                current_ap["signal"] = f"{dbm} dBm"
            continue

        # 频道
        freq_match = re.search(r'freq:\s*(\d+)', line) or re.search(r'Channel\s*(\d+)', line)
        if freq_match and current_ap:
            current_ap["channel"] = freq_match.group(1)
            continue

        # 加密
        enc_match = re.search(r'Encryption key:(\S+)', line)
        if enc_match and current_ap:
            current_ap["enc"] = "开" if "on" in enc_match.group(1).lower() else "关"
            continue

        # WPA/802.11w 等
        if "WPA" in line and current_ap:
            if current_ap["enc"] == "?" or current_ap["enc"] == "关":
                current_ap["enc"] = "WPA"
            continue

    if current_ap:
        aps.append(current_ap)

    if aps:
        print(f" {CHECK} 发现 {len(aps)} 个 AP:\n")
        headers = ["BSSID", "SSID", "信号", "信道", "加密"]
        rows = []
        for ap in aps[:30]:
            rows.append([
                ap["bssid"],
                ap["ssid"][:25],
                ap["signal"],
                ap["channel"],
                ap["enc"],
            ])
        print_table(headers, rows)
        if len(aps) > 30:
            print(f"\n {INFO} 显示前 30 个，共 {len(aps)} 个 AP")
    else:
        print(f" {INFO} 未发现 WiFi AP")


def monitor_capture(iface: str = None, count: int = 50):
    """抓取 802.11 数据包"""
    root = require_root_graceful("抓取 802.11 数据包", "无非 root 替代方案")
    if root is not True:
        return

    if not iface:
        ifaces = _get_wifi_interfaces()
        if not ifaces:
            print(f" {CROSS} 未检测到 WiFi 网卡")
            return
        iface = ifaces[0]

    print(f" {ROOT} 抓取 802.11 数据包 (接口: {C.CYAN}{iface}{C.NC})")
    print(f" {INFO} 使用 tcpdump，抓取 {count} 个包\n")

    # 检查 tcpdump 是否可用
    rc, _, _ = _run_cmd(["which", "tcpdump"])
    if rc != 0:
        print(f" {CROSS} tcpdump 未安装")
        print(f" {INFO} 在 Termux 中安装: {C.YELLOW}pkg install tcpdump{C.NC}")
        return

    print(f" {INFO} 开始抓包 (按 Ctrl+C 停止)...\n")
    try:
        proc = subprocess.Popen(
            ["tcpdump", "-i", iface, "-c", str(count), "-nn", "-e"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True
        )
        for line in proc.stdout:
            print(f"  {line.rstrip()}")
        proc.wait()
        print(f"\n {CHECK} 抓包完成")
    except KeyboardInterrupt:
        print(f"\n {INFO} 用户中断")
    except Exception as e:
        print(f" {CROSS} 抓包失败: {e}")


def wifi_scan_info(iface: str = None):
    """
    WiFi 信息查看（非 root 阉割版）
    扫描周围 WiFi AP 并显示基本信息
    使用 iw scan 或读取系统信息
    """
    print(f" {INFO} 扫描周围 WiFi 信息 (非 root 模式)...\n")

    # 获取当前连接的 WiFi 信息
    wifi_info = get_wifi_info()
    if wifi_info["ssid"] != "未知":
        print(f" {CHECK} 当前连接: {C.CYAN}{wifi_info['ssid']}{C.NC}")
        print(f"   信号强度: {wifi_info['signal']}")
        print(f"   频率: {wifi_info['frequency']}")
        print()

    # 尝试 iw dev scan（部分 Android 系统可用）
    if not iface:
        ifaces = _get_wifi_interfaces()
        if ifaces:
            iface = ifaces[0]

    if iface:
        print(f" {INFO} 尝试扫描 AP (接口: {iface})...")
        rc, out, err = _run_cmd(["iw", "dev", iface, "scan"], timeout=15)

        if rc == 0 and out:
            aps = []
            current_ap = {}
            for line in out.split("\n"):
                bssid_match = re.search(r'BSS\s+([0-9a-fA-F:]{17})', line)
                if bssid_match:
                    if current_ap:
                        aps.append(current_ap)
                    current_ap = {"bssid": bssid_match.group(1), "ssid": "?", "signal": "?"}
                    continue
                ssid_match = re.search(r'SSID:\s*(.+)', line)
                if ssid_match and current_ap:
                    current_ap["ssid"] = ssid_match.group(1).strip()
                sig_match = re.search(r'signal:\s*(-?\d+)', line)
                if sig_match and current_ap:
                    current_ap["signal"] = f"{sig_match.group(1)} dBm"

            if current_ap:
                aps.append(current_ap)

            if aps:
                print(f"\n {CHECK} 发现 {len(aps)} 个 AP:\n")
                headers = ["BSSID", "SSID", "信号"]
                rows = []
                for ap in aps[:20]:
                    rows.append([ap["bssid"], ap["ssid"][:25], ap["signal"]])
                print_table(headers, rows)
                if len(aps) > 20:
                    print(f"\n {INFO} 显示前 20 个，共 {len(aps)} 个 AP")

                # 保存结果
                from datetime import datetime
                save_results("wifi_scan", {
                    "time": datetime.now().isoformat(),
                    "current_ssid": wifi_info["ssid"],
                    "current_signal": wifi_info["signal"],
                    "aps": [{"bssid": a["bssid"], "ssid": a["ssid"], "signal": a["signal"]} for a in aps],
                })
            else:
                print(f" {INFO} 未发现 AP")
        else:
            print(f" {WARN} iw scan 不可用（部分 Android 系统限制）")
            print(f" {INFO} 可尝试: {C.YELLOW}tsu{C.NC} 提权后使用 {C.CYAN}monitor --scan{C.NC}")
    else:
        print(f" {WARN} 未检测到 WiFi 接口")
