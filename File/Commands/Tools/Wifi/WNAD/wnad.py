#!/usr/bin/env python3
"""
WNAD - Wireless Network Attack and Defense
MLH-Terminal 无线网络攻防工具
仿 SQLMap 命令行风格 | Pure Python | No Extra Dependencies
"""

import sys
import os

# 添加项目根到 path
_WNAD_ROOT = os.path.dirname(os.path.abspath(__file__))
if _WNAD_ROOT not in sys.path:
    sys.path.insert(0, _WNAD_ROOT)

# Data 目录
WNAD_DATA = os.path.join(_WNAD_ROOT, "Data")
os.makedirs(WNAD_DATA, exist_ok=True)
os.environ["WNAD_DATA"] = WNAD_DATA

import argparse
from core.utils import C, CHECK, CROSS, INFO, ROOT, ARROW, setup_console
from core.banner import BANNER, USAGE, VERSION
from core.network import show_info
from core.iplookup import resolve_domain, scan_cidr, lookup_public
from core.scanner import scan_arp, scan_ping, scan_ports, scan_service
from core.trace import traceroute
from core.speedtest import speedtest
from core.arp_spoof import arp_spoof
from core.flood import syn_flood
from core.monitor import monitor_enable, monitor_disable, monitor_scan, monitor_capture


def main():
    # 启用 Windows 控制台 ANSI 颜色支持
    setup_console()

    parser = argparse.ArgumentParser(
        description="WNAD - Wireless Network Attack and Defense",
        add_help=False,
        usage=argparse.SUPPRESS,
    )

    # 全局选项
    parser.add_argument("-h", "--help", action="store_true", dest="show_help",
                        help="显示帮助")
    parser.add_argument("-v", "--version", action="store_true", dest="show_version",
                        help="显示版本")

    # 子命令
    subparsers = parser.add_subparsers(dest="command", metavar="")

    # ── info ──
    p_info = subparsers.add_parser("info", help="查看本机网络信息")

    # ── lookup ──
    p_lookup = subparsers.add_parser("lookup", help="IP 查询")
    p_lookup.add_argument("--domain", type=str, help="域名解析到 IP")
    p_lookup.add_argument("--cidr", type=str, help="扫描 CIDR 网段 (如 192.168.1.0/24)")
    p_lookup.add_argument("--public", action="store_true", help="查询本机公网 IP")

    # ── scan ──
    p_scan = subparsers.add_parser("scan", help="网络扫描")
    p_scan.add_argument("--arp", action="store_true", help="ARP 扫描局域网设备")
    p_scan.add_argument("--ping", type=str, default="", help="Ping 存活探测 (CIDR)")
    p_scan.add_argument("--port", type=str, default="", help="TCP 端口扫描 (如 22,80,443 或 1-1000)")
    p_scan.add_argument("--service", type=str, default="", help="服务 Banner 指纹识别 (目标 IP)")
    p_scan.add_argument("--target", type=str, default="", help="扫描目标 IP")

    # ── trace ──
    p_trace = subparsers.add_parser("trace", help="路由追踪")
    p_trace.add_argument("target", type=str, nargs="?", default="", help="目标主机或 IP")

    # ── speedtest ──
    subparsers.add_parser("speedtest", help="网速测试")

    # ── arp ──
    p_arp = subparsers.add_parser("arp", help="[ROOT] ARP 操作")
    p_arp.add_argument("--spoof", nargs=2, metavar=("TARGET_IP", "GATEWAY_IP"),
                       help="ARP 欺骗目标 IP 和网关 IP")
    p_arp.add_argument("--iface", type=str, default="", help="网络接口")

    # ── flood ──
    p_flood = subparsers.add_parser("flood", help="[ROOT] 压力测试")
    p_flood.add_argument("--syn", type=str, default="", help="SYN Flood 目标 IP")
    p_flood.add_argument("--port", type=int, default=80, help="目标端口 (默认 80)")
    p_flood.add_argument("--threads", type=int, default=4, help="并发线程数 (默认 4)")
    p_flood.add_argument("--count", type=int, default=10000, help="发包数 (默认 10000, 0=无限)")

    # ── monitor ──
    p_mon = subparsers.add_parser("monitor", help="[ROOT] WiFi 监控模式")
    p_mon.add_argument("--enable", type=str, nargs="?", const="", help="开启监控模式")
    p_mon.add_argument("--disable", type=str, nargs="?", const="", help="关闭监控模式")
    p_mon.add_argument("--scan", type=str, nargs="?", const="", help="扫描 WiFi AP")
    p_mon.add_argument("--capture", type=int, nargs="?", const=50, help="抓取 802.11 包")

    args = parser.parse_args()

    # 显示横幅
    print(BANNER)

    # ── help / version ──
    if args.show_help or len(sys.argv) == 1:
        print(USAGE)
        return

    if args.show_version:
        print(f" {INFO} {VERSION}")
        return

    # ── info ──
    if args.command == "info":
        show_info()
        return

    # ── lookup ──
    if args.command == "lookup":
        if args.domain:
            resolve_domain(args.domain)
        elif args.cidr:
            scan_cidr(args.cidr)
        elif args.public:
            lookup_public()
        else:
            print(f" {CROSS} 请指定 --domain, --cidr 或 --public")
        return

    # ── scan ──
    if args.command == "scan":
        if args.arp:
            scan_arp()
        elif args.ping:
            scan_ping(args.ping)
        elif args.port:
            target = args.target if args.target else input(f" {ARROW} 请输入目标 IP: ").strip()
            if not target:
                print(f" {CROSS} 请指定目标 IP")
                return
            scan_ports(target, args.port)
        elif args.service:
            target = args.service if args.service != "" else (args.target if args.target else "")
            if not target:
                target = input(f" {ARROW} 请输入目标 IP: ").strip()
            if not target:
                print(f" {CROSS} 请指定目标 IP")
                return
            scan_service(target)
        else:
            print(f" {CROSS} 请指定扫描类型: --arp, --ping, --port, --service")
        return

    # ── trace ──
    if args.command == "trace":
        target = args.target if args.target else input(f" {ARROW} 请输入目标: ").strip()
        if not target:
            print(f" {CROSS} 请指定目标")
            return
        traceroute(target)
        return

    # ── speedtest ──
    if args.command == "speedtest":
        speedtest()
        return

    # ── arp ──
    if args.command == "arp":
        if args.spoof:
            target_ip, gateway_ip = args.spoof
            iface = args.iface if args.iface else None
            arp_spoof(target_ip, gateway_ip, iface)
        else:
            print(f" {CROSS} 请指定 --spoof 参数")
        return

    # ── flood ──
    if args.command == "flood":
        if args.syn:
            syn_flood(args.syn, args.port, threads=args.threads, count=args.count)
        else:
            print(f" {CROSS} 请指定 --syn 目标 IP")
        return

    # ── monitor ──
    if args.command == "monitor":
        if args.enable is not None:
            iface = args.enable if args.enable else None
            monitor_enable(iface)
        elif args.disable is not None:
            iface = args.disable if args.disable else None
            monitor_disable(iface)
        elif args.scan is not None:
            iface = args.scan if args.scan else None
            monitor_scan(iface)
        elif args.capture is not None:
            iface = None
            monitor_capture(None, args.capture)
        else:
            print(f" {CROSS} 请指定 --enable, --disable, --scan 或 --capture")
        return

    # 未知命令
    print(f" {CROSS} 未知命令: {args.command}")
    print(f" {INFO} 使用 {C.CYAN}wnad -h{C.NC} 查看帮助")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n {INFO} 用户中断")
    except Exception as e:
        print(f"\n {CROSS} 错误: {e}")
