"""
WNAD - ARP 监视器模块 (类 arpwatch)
监控局域网新设备加入/离开
轮询 /proc/net/arp，无需 root
"""

import os
import time
from datetime import datetime
from core.utils import C, CHECK, CROSS, INFO, ROOT, WARN, print_table
from core.network import get_oui_vendor, get_neighbor_table


def _read_arp_table() -> dict:
    """读取邻居设备表，返回 {ip: {mac, iface}}"""
    return get_neighbor_table()


def arpwatch(interval: int = 5, count: int = 0):
    """
    ARP 监视器 - 监控局域网设备变化
    - 轮询 /proc/net/arp，检测新设备/离开设备
    - interval: 轮询间隔（秒）
    - count: 轮询次数（0=无限）
    """
    table = get_neighbor_table()
    if not table:
        print(f" {CROSS} 无法访问 ARP 表")
        print(f" {INFO} 尝试使用: {C.CYAN}wnad discover{C.NC} 替代")
        return

    print(f" {INFO} ARP 监视器已启动")
    print(f"   Interval: {interval}s, 次数: {'无限' if count == 0 else count}")
    print(f"   {C.CYAN}[+]{C.NC} 新设备   {C.RED}[-]{C.NC} 设备离开   {C.YELLOW}[~]{C.NC} 接口变化")
    print(f" {INFO} 按 Ctrl+C 停止\n")

    prev = _read_arp_table()
    print(f" {CHECK} 初始发现 {len(prev)} 个设备\n")
    for ip, info in prev.items():
        vendor = get_oui_vendor(info["mac"])
        print(f"   {C.CYAN}[BASE]{C.NC}  {ip:<16}  {info['mac']:<20}  {vendor}")

    iteration = 0

    try:
        while count == 0 or iteration < count:
            iteration += 1
            time.sleep(interval)

            current = _read_arp_table()

            # 新设备
            for ip, info in current.items():
                if ip not in prev:
                    vendor = get_oui_vendor(info["mac"])
                    ts = datetime.now().strftime("%H:%M:%S")
                    print(f"   {C.GREEN}[+]{C.NC}  {ts}  {ip:<16}  {info['mac']:<20}  {vendor}")

            # 离开设备
            for ip, info in prev.items():
                if ip not in current:
                    vendor = get_oui_vendor(info["mac"])
                    ts = datetime.now().strftime("%H:%M:%S")
                    print(f"   {C.RED}[-]{C.NC}  {ts}  {ip:<16}  {info['mac']:<20}  {vendor}")

            # 接口变化
            for ip, info in current.items():
                if ip in prev and info["mac"] != prev[ip]["mac"]:
                    ts = datetime.now().strftime("%H:%M:%S")
                    print(f"   {C.YELLOW}[~]{C.NC}  {ts}  {ip:<16}  MAC: {prev[ip]['mac']} -> {info['mac']}")

            prev = current

            # 设备数量变化时显示摘要
            diff = len(current) - len(prev)
            if diff != 0:
                print(f"   {INFO} 设备数: {len(current)} ({'+' if diff > 0 else ''}{diff})")

    except KeyboardInterrupt:
        print(f"\n {INFO} 用户中断")

    final = _read_arp_table()
    print(f"\n {CHECK} 监视结束. 当前设备数: {len(final)}")
