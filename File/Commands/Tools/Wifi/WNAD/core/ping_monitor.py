"""
WNAD - 持续 Ping 监控模块
连续 Ping 目标并显示实时统计
"""

import subprocess
import time
import re
import signal
from core.utils import C, CHECK, CROSS, INFO, ARROW


def ping_monitor(target: str, count: int = 0, interval: float = 1.0, timeout: float = 2.0):
    """
    持续 Ping 监控
    - target: 目标 IP 或域名
    - count: Ping 次数 (0 = 无限)
    - interval: Ping 间隔 (秒)
    """
    if not target:
        print(f" {CROSS} 请输入目标")
        return

    print(f" {INFO} 持续 Ping 监控: {C.CYAN}{target}{C.NC}")
    print(f" {INFO} 次数: {'无限' if count == 0 else count}, 间隔: {interval}s\n")

    success = 0
    failed = 0
    rtts = []
    iteration = 0

    try:
        while count == 0 or iteration < count:
            iteration += 1
            start = time.time()

            try:
                from core.utils import ping_cmd, is_windows
                cmd = ping_cmd(target, timeout=timeout)
                result = subprocess.run(
                    cmd,
                    capture_output=True, text=True, timeout=timeout + 1
                )
                elapsed = time.time() - start

                if result.returncode == 0:
                    success += 1
                    rtt = elapsed * 1000
                    rtts.append(rtt)

                    # 提取系统 ping 的 RTT
                    rtt_match = re.search(r'time[=<]\s*([\d.]+)\s*ms', result.stdout)
                    if not rtt_match:
                        # Windows 格式: 时间=XXms
                        rtt_match = re.search(r'[时时间间][=]\s*([\d.]+)\s*ms', result.stdout)
                    if not rtt_match:
                        # Windows 英文: time<XXms
                        rtt_match = re.search(r'time[<=]\s*([\d.]+)', result.stdout)
                    if rtt_match:
                        rtt = float(rtt_match.group(1))

                    # 颜色：<50ms 绿，<150ms 黄，>=150ms 红
                    color = C.GREEN if rtt < 50 else (C.YELLOW if rtt < 150 else C.RED)
                    print(f" {color}[{C.NC}{color}PING{C.NC}{color}]{C.NC}  seq={iteration}  rtt={color}{rtt:.1f}ms{C.NC}  {C.DIM}({success}/{success+failed}){C.NC}")
                else:
                    failed += 1
                    print(f" {C.RED}[TIMEOUT]{C.NC}  seq={iteration}  no reply  {C.DIM}({success}/{success+failed}){C.NC}")

            except subprocess.TimeoutExpired:
                failed += 1
                print(f" {C.RED}[TIMEOUT]{C.NC}  seq={iteration}  timeout  {C.DIM}({success}/{success+failed}){C.NC}")

            if count > 0 and iteration >= count:
                break

            if iteration < count or count == 0:
                time.sleep(max(0, interval - (time.time() - start)))

    except KeyboardInterrupt:
        print()

    # 统计汇总
    total = success + failed
    if total > 0:
        loss_rate = failed / total * 100
        print(f"\n {CHECK} Ping 统计:\n")
        print(f"   目标:     {C.CYAN}{target}{C.NC}")
        print(f"   已发送:   {total}")
        print(f"   成功:     {C.GREEN}{success}{C.NC}")
        print(f"   失败:     {C.RED if failed > 0 else ''}{failed}{C.NC}")
        print(f"   丢包率:   {C.RED if loss_rate > 0 else C.GREEN}{loss_rate:.1f}%{C.NC}")
        if rtts:
            print(f"   最小 RTT: {min(rtts):.1f}ms")
            print(f"   最大 RTT: {max(rtts):.1f}ms")
            print(f"   平均 RTT: {sum(rtts)/len(rtts):.1f}ms")
