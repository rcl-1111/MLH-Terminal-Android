"""
WNAD - 路由追踪模块
基于 TTL 递增的 traceroute 实现
纯 Python 实现
"""

import socket
import struct
import time
import os
import subprocess
import re
from core.utils import C, CHECK, CROSS, INFO, ARROW


def traceroute(target: str, max_hops: int = 30, timeout: float = 2.0):
    """
    路由追踪 - 使用 UDP + TTL 探测
    兼容 Android Termux (无 root) 环境
    """
    # 解析目标地址
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f" {CROSS} 无法解析目标: {target}")
        return

    print(f" {INFO} 路由追踪到 {C.CYAN}{target}{C.NC} ({target_ip})")
    print(f" {INFO} 最大跳数: {max_hops}, 超时: {timeout}s\n")
    print(f" {C.BOLD}{'跳数':<6}{'IP 地址':<20}{'延迟':<10}{'主机名'}{C.NC}")
    print(f" {'─'*56}")

    # 优先使用系统 traceroute 命令（更准确）
    if _system_traceroute(target, max_hops):
        return

    # 纯 Python 实现
    _python_traceroute(target_ip, max_hops, timeout)


def _system_traceroute(target: str, max_hops: int) -> bool:
    """使用系统 traceroute 命令（如果可用）"""
    for cmd in [
        ["traceroute", "-n", "-m", str(max_hops), target],
        ["tracepath", "-n", target],
    ]:
        try:
            name = cmd[0]
            # 检查命令是否存在（Termux 可能需要 root）
            if os.system(f"which {name} >/dev/null 2>&1") != 0:
                if os.system(f"command -v {name} >/dev/null 2>&1") != 0:
                    continue

            print(f" {INFO} 使用系统 {name} 命令\n")
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0 or result.returncode == 2:
                # 格式化输出
                for line in result.stdout.split("\n"):
                    if line.strip() and not line.startswith(" " * 10):
                        print(f"  {line}")
                if result.stderr:
                    for line in result.stderr.split("\n"):
                        if "Cannot handle" in line or "not permitted" in line:
                            print(f" {WARN} 系统 traceroute 需要特定权限")
                            return False
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        except Exception:
            continue
    return False


def _python_traceroute(target_ip: str, max_hops: int, timeout: float):
    """纯 Python TTL 递增 traceroute"""
    print(f" {INFO} 使用 Python 内置 traceroute\n")

    for ttl in range(1, max_hops + 1):
        # 创建 UDP socket
        try:
            rx_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            rx_sock.settimeout(timeout)
            rx_sock.bind(("", 0))
        except PermissionError:
            # 无 raw socket 权限，放弃
            print(f" {CROSS} 需要 root 权限进行 traceroute")
            print(f" {INFO} 请使用 {C.YELLOW}sudo{C.NC} 或 {C.YELLOW}tsu{C.NC} 提权")
            return
        except Exception as e:
            print(f" {CROSS} 无法创建 socket: {e}")
            return

        tx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        tx_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        tx_sock.settimeout(timeout)

        # 使用高端口号避免冲突
        dst_port = 33434 + ttl

        start = time.time()
        tx_sock.sendto(b"", (target_ip, dst_port))
        got_response = False
        hop_ip = "*"
        hop_time = timeout

        try:
            data, addr = rx_sock.recvfrom(512)
            elapsed = time.time() - start
            # ICMP Time Exceeded 表示中间路由
            hop_ip = addr[0]
            hop_time = elapsed * 1000  # ms
            got_response = True
        except socket.timeout:
            pass
        except Exception:
            pass
        finally:
            tx_sock.close()
            rx_sock.close()

        # 尝试解析主机名
        hostname = ""
        if hop_ip != "*":
            try:
                hostname = socket.gethostbyaddr(hop_ip)[0][:30]
            except Exception:
                hostname = ""

        # 显示结果
        time_str = f"{hop_time:.1f}ms" if got_response else "*"
        print(f"  {ttl:<5} {hop_ip:<18} {time_str:<10} {hostname}")

        if hop_ip == target_ip:
            print(f"\n {CHECK} 到达目标 {target_ip}")
            break
