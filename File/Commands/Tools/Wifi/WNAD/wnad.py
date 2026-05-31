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
from core.discover import discover
from core.dns_lookup import dns_enum
from core.geoip import geoip_lookup
from core.mac_lookup import mac_lookup
from core.subnet_calc import subnet_calc
from core.ping_monitor import ping_monitor
from core.proxy import run_proxy
from core.netstat import netstat
from core.arpwatch import arpwatch
from core.httpd import run_httpd
from core.wifi_tool import wifi_main
from core.nmap_scan import nmap_scan
from core.defense import defense_main
from core.usb_tool import usb_main
from core.crack_tool import crack_main
from core.aircrack import air_main, wifite_main


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

    # ── discover ──
    p_discover = subparsers.add_parser("discover", help="网络设备发现 (netdiscover-like)")
    p_discover.add_argument("--cidr", type=str, default="", help="扫描网段 (默认自动检测)")
    p_discover.add_argument("--force", action="store_true", help="跳过确认直接扫描大网段")

    # ── dns ──
    p_dns = subparsers.add_parser("dns", help="DNS 记录枚举")
    p_dns.add_argument("domain", type=str, nargs="?", default="", help="目标域名")
    p_dns.add_argument("--types", type=str, default="A,AAAA,MX,NS,TXT,CNAME,SOA",
                       help="查询类型 (逗号分隔)")

    # ── geoip ──
    p_geoip = subparsers.add_parser("geoip", help="IP 地理位置查询")
    p_geoip.add_argument("ip", type=str, nargs="?", default="", help="IP 地址或域名")

    # ── mac ──
    p_mac = subparsers.add_parser("mac", help="MAC 地址厂商查询")
    p_mac.add_argument("mac", type=str, nargs="?", default="", help="MAC 地址 (XX:XX:XX:XX:XX:XX)")

    # ── subnet ──
    p_subnet = subparsers.add_parser("subnet", help="子网计算器")
    p_subnet.add_argument("cidr", type=str, nargs="?", default="", help="CIDR 网段 (如 192.168.1.0/24)")

    # ── ping ──
    p_ping = subparsers.add_parser("ping", help="持续 Ping 监控")
    p_ping.add_argument("target", type=str, nargs="?", default="", help="目标 IP 或域名")
    p_ping.add_argument("--count", type=int, default=0, help="Ping 次数 (0=无限)")
    p_ping.add_argument("--interval", type=float, default=1.0, help="Ping 间隔秒数")

    # ── proxy ──
    p_proxy = subparsers.add_parser("proxy", help="HTTP 代理服务器")
    p_proxy.add_argument("--port", type=int, default=8080, help="监听端口 (默认 8080)")
    p_proxy.add_argument("--bind", type=str, default="127.0.0.1", help="绑定地址")

    # ── netstat ──
    p_netstat = subparsers.add_parser("netstat", help="网络连接查看")
    p_netstat.add_argument("--all", action="store_true", dest="show_all", help="显示所有连接")

    # ── arpwatch ──
    p_arpw = subparsers.add_parser("arpwatch", help="ARP 设备监视器")
    p_arpw.add_argument("--interval", type=int, default=5, help="轮询间隔秒数")
    p_arpw.add_argument("--count", type=int, default=0, help="轮询次数 (0=无限)")

    # ── wifi ──
    p_wifi = subparsers.add_parser("wifi", help="WiFi 工具集 (扫描/信息/攻击/破解)")
    p_wifi.add_argument("-l", "--list", action="store_true", dest="list_networks",
                        help="列出周围 WiFi 网络")
    p_wifi.add_argument("-m", "--monitor", action="store_true",
                        help="实时监控模式 (类 airodump-ng)")
    p_wifi.add_argument("--interval", type=float, default=3.0,
                        help="监控刷新间隔秒数 (默认 3)")
    p_wifi.add_argument("--name", type=str, default="", help="目标 WiFi 名称")
    p_wifi.add_argument("--info", action="store_true", help="显示网络详情")
    p_wifi.add_argument("--ip", action="store_true", help="显示网络 IP 信息")
    p_wifi.add_argument("--deauth", type=str, default="", metavar="BSSID",
                        help="[ROOT] Deauth 攻击")
    p_wifi.add_argument("--handshake", action="store_true", help="[ROOT] 捕获 WPA 握手包")
    p_wifi.add_argument("--crack", type=str, default="", metavar="CAP_FILE",
                        help="[ROOT] 破解握手包 (.cap)")
    p_wifi.add_argument("--dict", type=str, default="common.txt", help="字典文件名")
    p_wifi.add_argument("--wps", action="store_true", help="[ROOT] WPS 扫描")
    p_wifi.add_argument("--dict-list", action="store_true", dest="dict_list",
                        help="列出可用字典")
    p_wifi.add_argument("--bssid", type=str, default="", help="目标 BSSID")
    p_wifi.add_argument("--channel", type=str, default="", help="WiFi 信道")

    # ── nmap ──
    p_nmap = subparsers.add_parser("nmap", help="类 nmap 端口扫描")
    p_nmap.add_argument("target", type=str, nargs="?", default="", help="目标 (IP/域名/CIDR)")
    p_nmap.add_argument("-p", "--ports", type=str, default="top100",
                        help="端口范围 (如 80,443 / 1-1000 / top1000)")
    p_nmap.add_argument("-sT", "--tcp", action="store_true", help="TCP Connect 扫描")
    p_nmap.add_argument("-sU", "--udp", action="store_true", help="UDP 扫描")
    p_nmap.add_argument("-sV", "--version", action="store_true", dest="version_detect",
                        help="探测服务版本")
    p_nmap.add_argument("-O", "--os", action="store_true", dest="os_detect",
                        help="检测操作系统 (基于 TTL)")
    p_nmap.add_argument("-v", "--verbose", action="store_true", help="详细输出")
    p_nmap.add_argument("-T", "--timing", type=str, default="T3",
                        help="时序模板: T0-T5 (默认 T3)")
    p_nmap.add_argument("-oN", "--output", type=str, default="",
                        help="输出到文件")
    p_nmap.add_argument("--no-resolve", action="store_true", dest="no_resolve",
                        help="不解析主机名")

    # ── defense ──
    p_def = subparsers.add_parser("defense", help="网络安全防御")
    p_def.add_argument("check", type=str, nargs="?", default="check",
                       choices=["arp", "ports", "dns", "scan", "monitor", "check"],
                       help="检查类型")
    p_def.add_argument("--domain", type=str, default="baidu.com", help="DNS 检测目标域名")
    p_def.add_argument("--monitor", action="store_true", help="持续监控模式")
    p_def.add_argument("--interval", type=float, default=5.0, help="监控间隔秒数")
    p_def.add_argument("--count", type=int, default=20, help="扫描检测触发阈值")

    # ── usb ──
    p_usb = subparsers.add_parser("usb", help="USB 设备检测")
    p_usb.add_argument("-l", "--list", action="store_true", dest="list_usb",
                        help="列出所有 USB 设备")
    p_usb.add_argument("-ED", "--external-devices", action="store_true", dest="ext_devices",
                        help="列出外部网卡设备")
    p_usb.add_argument("-m", "--monitor", action="store_true", dest="usb_monitor",
                        help="USB 插拔监控")
    p_usb.add_argument("--info", type=str, default="", dest="usb_info",
                        help="查看指定设备详情")
    p_usb.add_argument("--security", action="store_true", dest="usb_security",
                        help="USB 安全检测 (BadUSB 等)")
    p_usb.add_argument("--connect", action="store_true",
                        help="交互式网卡选择器")

    # ── crack ──
    p_crack = subparsers.add_parser("crack", help="密码破解 (类 Kali Linux)")
    p_crack.add_argument("sub", type=str, nargs="?", default="",
                         choices=["identify", "hash", "hydra", "wordlist"],
                         help="子命令")
    p_crack.add_argument("hash_value", type=str, nargs="?", default="",
                         help="哈希值")
    p_crack.add_argument("target", type=str, nargs="?", default="",
                         help="目标主机")
    p_crack.add_argument("--service", type=str, default="ftp",
                         help="服务类型 (ftp/telnet/http/https/http-post/ssh/mysql)")
    p_crack.add_argument("--user", type=str, default="root", help="用户名")
    p_crack.add_argument("--dict", type=str, default="", help="字典文件路径")
    p_crack.add_argument("--type", type=str, default="md5", dest="hash_type",
                         help="哈希类型 (md5/sha1/sha256/sha512/ntlm)")
    p_crack.add_argument("--threads", type=int, default=5, help="线程数")
    p_crack.add_argument("--ssl", action="store_true", help="启用 SSL")
    p_crack.add_argument("--output", type=str, default="", help="输出文件")
    p_crack.add_argument("--charset", type=str, default="num",
                         help="字符集 (num/lower/upper/alpha/alnum/full)")
    p_crack.add_argument("--min", type=int, default=1, help="最小长度")
    p_crack.add_argument("--max", type=int, default=4, help="最大长度")
    p_crack.add_argument("--pattern", type=str, default="", help="模式 (如 @@@%%)")
    p_crack.add_argument("--limit", type=int, default=0, help="限制条数")

    # ── air (airmon-ng + airodump-ng + aireplay-ng) ──
    p_air = subparsers.add_parser("air", help="Aircrack-ng 套件 (airmon/airodump/aireplay)")
    p_air.add_argument("-c", "--check", action="store_true", dest="air_check",
                        help="检查接口和干扰进程 (airmon-ng check)")
    p_air.add_argument("--start", type=str, nargs="?", const="", dest="air_start",
                        help="开启监控模式 (airmon-ng start)")
    p_air.add_argument("--stop", type=str, nargs="?", const="", dest="air_stop",
                        help="关闭监控模式 (airmon-ng stop)")
    p_air.add_argument("-d", "--dump", action="store_true", dest="air_dump",
                        help="实时抓包 (airodump-ng)")
    p_air.add_argument("-i", "--iface", type=str, default="", dest="air_iface",
                        help="网络接口")
    p_air.add_argument("--channel", type=str, default="", dest="air_channel",
                        help="锁定信道")
    p_air.add_argument("-o", "--output", type=str, default="", dest="air_output",
                        help="输出文件前缀")
    p_air.add_argument("--deauth", type=str, default="", dest="air_deauth",
                        help="Deauth 攻击 BSSID (aireplay-ng -0)")
    p_air.add_argument("--client", type=str, default="", dest="air_client",
                        help="Deauth 目标客户端 MAC")
    p_air.add_argument("--count", type=int, default=5, dest="air_count",
                        help="Deauth 轮次 (默认 5)")

    # ── wifite ──
    p_wifite = subparsers.add_parser("wifite", help="自动化 WiFi 审计 (类 wifite)")
    p_wifite.add_argument("-i", "--iface", type=str, default="", dest="air_iface",
                          help="网络接口")

    # ── httpd ──
    p_httpd = subparsers.add_parser("httpd", help="HTTP 文件服务器")
    p_httpd.add_argument("--port", type=int, default=8888, help="监听端口 (默认 8888)")
    p_httpd.add_argument("--dir", type=str, default="", help="根目录")
    p_httpd.add_argument("--bind", type=str, default="0.0.0.0", help="绑定地址")

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

    # ── dns ──
    if args.command == "dns":
        domain = args.domain if args.domain else input(f" {ARROW} 请输入域名: ").strip()
        if domain:
            types = [t.strip() for t in args.types.split(",")]
            dns_enum(domain, types)
        else:
            print(f" {CROSS} 请指定域名")
        return

    # ── geoip ──
    if args.command == "geoip":
        ip = args.ip if args.ip else input(f" {ARROW} 请输入 IP: ").strip()
        if ip:
            geoip_lookup(ip)
        else:
            print(f" {CROSS} 请指定 IP")
        return

    # ── mac ──
    if args.command == "mac":
        mac = args.mac if args.mac else input(f" {ARROW} 请输入 MAC: ").strip()
        if mac:
            mac_lookup(mac)
        else:
            print(f" {CROSS} 请指定 MAC 地址")
        return

    # ── subnet ──
    if args.command == "subnet":
        cidr = args.cidr if args.cidr else input(f" {ARROW} 请输入 CIDR: ").strip()
        if cidr:
            subnet_calc(cidr)
        else:
            print(f" {CROSS} 请指定 CIDR 网段")
        return

    # ── ping ──
    if args.command == "ping":
        target = args.target if args.target else input(f" {ARROW} 请输入目标: ").strip()
        if target:
            ping_monitor(target, count=args.count, interval=args.interval)
        else:
            print(f" {CROSS} 请指定目标")
        return

    # ── proxy ──
    if args.command == "proxy":
        print(f" {CROSS} 代理服务器将在当前终端前台运行")
        print(f" {INFO} 启动: {C.CYAN}http://{args.bind}:{args.port}{C.NC}")
        run_proxy(args.bind, args.port)
        return

    # ── nmap ──
    if args.command == "nmap":
        scan_type = "tcp"
        if args.udp:
            scan_type = "udp"
        nmap_scan(
            target=args.target,
            ports=args.ports,
            scan_type=scan_type,
            version_detect=args.version_detect,
            os_detect=args.os_detect,
            verbose=args.verbose,
            timing=args.timing,
            output_file=args.output,
            resolve=not args.no_resolve,
        )
        return

    # ── defense ──
    if args.command == "defense":
        # 将子命令映射到 defense_main
        args.arp_check = args.check == "arp"
        args.ports_check = args.check == "ports"
        args.dns_check = args.check == "dns"
        args.scan_check = args.check == "scan"
        args.monitor_conn = args.check == "monitor"
        args.check_baseline = args.check == "check"
        defense_main(args)
        return

    # ── crack ──
    if args.command == "crack":
        crack_main(args)
        return

    # ── air (airmon-ng / airodump-ng / aireplay-ng) ──
    if args.command == "air":
        air_main(args)
        return

    # ── wifite ──
    if args.command == "wifite":
        wifite_main(args)
        return

    # ── usb ──
    if args.command == "usb":
        usb_main(args)
        return

    # ── netstat ──
    if args.command == "netstat":
        netstat(show_all=getattr(args, 'show_all', False))
        return

    # ── arpwatch ──
    if args.command == "arpwatch":
        arpwatch(interval=args.interval, count=args.count)
        return

    # ── httpd ──
    if args.command == "httpd":
        directory = args.dir if args.dir else None
        if directory:
            os.chdir(directory)
        run_httpd(args.port, directory, args.bind)
        return

    # ── wifi ──
    if args.command == "wifi":
        wifi_main(args)
        return

    # ── discover ──
    if args.command == "discover":
        cidr = args.cidr if args.cidr else None
        discover(cidr, force=getattr(args, 'force', False))
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
