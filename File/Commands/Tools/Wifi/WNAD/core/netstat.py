"""
WNAD - 网络连接查看模块 (类 netstat/ss)
读取 /proc/net/{tcp,udp,tcp6,udp6} 显示活动连接
纯 Python，无需 root
"""

import os
import socket
from core.utils import C, CHECK, CROSS, INFO, print_table


TCP_STATES = {
    1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV",
    4: "FIN_WAIT1", 5: "FIN_WAIT2", 6: "TIME_WAIT",
    7: "CLOSE", 8: "CLOSE_WAIT", 9: "LAST_ACK",
    10: "LISTEN", 11: "CLOSING",
}


def _hex_ip_port(hex_str: str) -> tuple:
    """将 /proc/net 中的 8 位十六进制 IP:端口 转换为可读格式"""
    ip_hex = hex_str[:8]
    port_hex = hex_str[8:]

    # IP: 小端序 4 字节
    ip = ".".join(str(int(ip_hex[i:i+2], 16)) for i in range(6, -1, -2))
    port = int(port_hex, 16)
    return ip, port


def _try_resolve(ip: str) -> str:
    """尝试反向解析 IP"""
    try:
        name = socket.gethostbyaddr(ip)[0]
        if len(name) > 40:
            name = name[:37] + "..."
        return name
    except Exception:
        return ""


def netstat(show_all: bool = False):
    """
    显示网络连接状态
    读取 /proc/net/tcp, /proc/net/udp
    """
    tables = [
        ("/proc/net/tcp", "TCP"),
        ("/proc/net/udp", "UDP"),
    ]

    all_rows = []

    for proc_path, proto in tables:
        if not os.path.isfile(proc_path):
            continue

        with open(proc_path) as f:
            lines = f.readlines()

        if len(lines) <= 1:
            continue

        for line in lines[1:]:
            parts = line.strip().split()
            if len(parts) < 10:
                continue

            try:
                local_ip, local_port = _hex_ip_port(parts[1])
                remote_ip, remote_port = _hex_ip_port(parts[2])
                state_code = int(parts[3], 16)
                state = TCP_STATES.get(state_code, f"UNKNOWN({state_code})")
                uid = parts[7]

                # 过滤 LISTEN（除非 show_all）
                if not show_all and state == "LISTEN":
                    continue

                # 过滤空闲状态
                if not show_all and state in ("TIME_WAIT", "CLOSE_WAIT", "FIN_WAIT2"):
                    continue

                # 过滤全零远程
                if remote_ip == "0.0.0.0" and remote_port == 0:
                    remote_str = "*:*"
                else:
                    remote_str = f"{remote_ip}:{remote_port}"

                # 尝试解析远程主机名
                hostname = ""
                if remote_ip != "0.0.0.0" and remote_ip != "127.0.0.1":
                    hostname = _try_resolve(remote_ip)

                all_rows.append((
                    proto,
                    f"{local_ip}:{local_port}",
                    remote_str,
                    state,
                    uid,
                    hostname,
                ))
            except (ValueError, IndexError):
                continue

    if all_rows:
        headers = ["Proto", "Local", "Remote", "State", "UID", "Hostname"]
        print_table(headers, all_rows)
        print(f"\n {CHECK} 共 {len(all_rows)} 个连接（{C.YELLOW}--all{C.NC} 显示所有）")
        print(f" {INFO} 提示: 使用 {C.CYAN}--all{C.NC} 查看包括 LISTEN/TIME_WAIT 的全部连接")
    else:
        print(f" {CROSS} 无法读取连接信息（非 Linux 系统或无权限）")
