"""
WNAD - 工具模块
颜色输出、表格格式化、进度条
"""

import sys
import re
import time
import os
import platform
import shutil
from datetime import datetime


# ── 平台检测 ──
def is_windows() -> bool:
    return platform.system() == "Windows"


def ping_cmd(target: str, timeout: float = 2.0, count: int = 1) -> list:
    """
    返回跨平台的 ping 命令参数列表
    用法: subprocess.run(ping_cmd("8.8.8.8"), ...)
    """
    if is_windows():
        # Windows: ping -n <count> -w <timeout_ms> <target>
        return ["ping", "-n", str(count), "-w", str(int(timeout * 1000)), target]
    else:
        # Linux: ping -c <count> -W <timeout_s> <target>
        if count > 1:
            return ["ping", "-c", str(count), "-W", str(int(timeout)), target]
        return ["ping", "-c", "1", "-W", str(int(timeout)), target]


# ── Windows 控制台 ANSI 支持 ──
def setup_console():
    """
    启用 Windows 控制台的 ANSI 转义序列支持（Win10+）
    在其他系统上无操作
    """
    if sys.platform != "win32":
        return

    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        STD_OUTPUT_HANDLE = -11
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        ENABLE_VT = 0x0004

        handle = kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | ENABLE_VT)
    except Exception:
        pass  # 非 Windows 或旧版本 Windows 静默忽略


# ── ANSI 颜色 ──
class C:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    NC = '\033[0m'  # No Color

# ── 符号 ──
CHECK   = f"{C.GREEN}[√]{C.NC}"
CROSS   = f"{C.RED}[×]{C.NC}"
INFO    = f"{C.YELLOW}[*]{C.NC}"
WARN    = f"{C.RED}[!]{C.NC}"
ROOT    = f"{C.RED}{C.BOLD}[!ROOT]{C.NC}"
ARROW   = f"{C.CYAN}[>]{C.NC}"


def print_banner(text: str, color: str = C.CYAN):
    """打印带颜色的横幅"""
    width = 60
    print(f"{color}{'═' * width}{C.NC}")
    print(f"{color}{C.BOLD}{text:^{width}}{C.NC}")
    print(f"{color}{'═' * width}{C.NC}")


def _strip_ansi(text: str) -> str:
    """去掉 ANSI 转义码，得到纯文本"""
    return re.sub(r'\033\[[0-9;]*m', '', text)

def _vis_width(text: str) -> int:
    """计算字符串在终端的可见宽度（CJK 字符算 2，ANSI 码不计）"""
    clean = _strip_ansi(str(text))
    width = 0
    for ch in clean:
        if '\u4e00' <= ch <= '\u9fff' or '\u3000' <= ch <= '\u303f' \
                or '\uff00' <= ch <= '\uffef':
            width += 2
        else:
            width += 1
    return width

def _ljust_vis(text: str, width: int) -> str:
    """按可见宽度左对齐（保留 ANSI 颜色）"""
    raw = str(text)
    vis = _vis_width(raw)
    if vis >= width:
        return raw
    return raw + ' ' * (width - vis)

def _rjust_vis(text: str, width: int) -> str:
    """按可见宽度右对齐（保留 ANSI 颜色）"""
    raw = str(text)
    vis = _vis_width(raw)
    if vis >= width:
        return raw
    return ' ' * (width - vis) + raw


def _trunc_vis(text: str, max_vis: int) -> str:
    """按可见宽度截断文本，保留 ANSI 颜色，末尾加…"""
    raw = str(text)
    clean = _strip_ansi(raw)
    width = 0
    result_chars = []
    in_ansi = False
    ansi_buf = ""
    chars_used = 0

    for ch in raw:
        if ch == '\033':
            in_ansi = True
            ansi_buf = ch
        elif in_ansi:
            ansi_buf += ch
            if ch == 'm':
                result_chars.append(ansi_buf)
                in_ansi = False
                ansi_buf = ""
        else:
            cw = 2 if ('\u4e00' <= ch <= '\u9fff' or '\u3000' <= ch <= '\u303f'
                        or '\uff00' <= ch <= '\uffef') else 1
            if width + cw > max_vis:
                result_chars.append('…')
                break
            result_chars.append(ch)
            width += cw
            chars_used += 1

    if in_ansi and ansi_buf:
        result_chars.append(ansi_buf)
    return ''.join(result_chars)


def print_table(headers: list, rows: list, padding: int = 2):
    """打印格式化表格（自动对齐中英文混排 + ANSI 颜色 + 手机小屏适配）"""
    if not rows:
        print(f" {INFO} 无数据")
        return

    # 计算每列可见宽度
    col_widths = [_vis_width(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], _vis_width(cell))

    ncols = len(headers)
    total_inner = sum(col_widths) + padding * 2 * ncols + ncols + 1

    # ── 手机小屏适配：检测终端宽度，超出时自动截断 ──
    try:
        term_width = shutil.get_terminal_size().columns
    except Exception:
        term_width = 80

    if total_inner > term_width:
        overflow = total_inner - term_width + 2  # +2 缓和
        # 找到最宽的列来截断
        widest_idx = max(range(ncols), key=lambda i: col_widths[i])
        old_w = col_widths[widest_idx]
        col_widths[widest_idx] = max(col_widths[widest_idx] - overflow - 3, 4)
        # 确保列不低于表头宽度
        hw = _vis_width(headers[widest_idx])
        if col_widths[widest_idx] < hw:
            col_widths[widest_idx] = hw
        # 重新算总宽
        total_inner = sum(col_widths) + padding * 2 * ncols + ncols + 1
        # 标记截断
        _truncated_col = widest_idx
    else:
        _truncated_col = -1

    # > 顶部
    print(f"┌{'─' * max(total_inner - 2, 0)}┐")

    # > 表头
    header_line = "│"
    for i, h in enumerate(headers):
        styled = f"{C.BOLD}{h}{C.NC}"
        disp = _trunc_vis(styled, col_widths[i]) if _truncated_col == i else styled
        padded = ' ' * padding + disp + ' ' * padding
        header_line += _ljust_vis(padded, col_widths[i] + padding * 2) + "│"
    print(header_line)

    # > 分隔线
    print(f"├{'─' * max(total_inner - 2, 0)}┤")

    # > 数据行
    for row in rows:
        row_line = "│"
        for i, cell in enumerate(row):
            cell_str = str(cell)
            disp = _trunc_vis(cell_str, col_widths[i]) if _truncated_col == i else cell_str
            padded = ' ' * padding + disp + ' ' * padding
            row_line += _ljust_vis(padded, col_widths[i] + padding * 2) + "│"
        print(row_line)

    # > 底部
    print(f"└{'─' * max(total_inner - 2, 0)}┘")

    # 被截断时提示
    if _truncated_col >= 0:
        print(f" {C.DIM}提示: 终端太窄，第 {_truncated_col+1} 列已截断（…）{C.NC}")


def print_column(items: list, color: str = C.NC, indent: int = 0):
    """打印纵向列表"""
    prefix = " " * indent
    for item in items:
        print(f"{prefix} {color}•{C.NC} {item}")


def progress_bar(current: int, total: int, prefix: str = "", bar_len: int = 30):
    """显示进度条"""
    if total == 0:
        return
    ratio = current / total
    filled = int(bar_len * ratio)
    bar = f"{C.GREEN}{'█' * filled}{C.DIM}{'░' * (bar_len - filled)}{C.NC}"
    pct = f"{ratio * 100:.0f}%"
    sys.stdout.write(f"\r{INFO} {prefix} [{bar}] {pct}")
    sys.stdout.flush()
    if current == total:
        print()


class Spinner:
    """旋转等待动画"""

    def __init__(self, message: str = "处理中"):
        self.message = message
        self.chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        self.running = False

    def start(self):
        self.running = True
        self._spin()

    def _spin(self):
        if not self.running:
            return
        for c in self.chars:
            if not self.running:
                break
            sys.stdout.write(f"\r{C.CYAN}{c}{C.NC} {self.message}...")
            sys.stdout.flush()
            time.sleep(0.08)

    def stop(self, success: bool = True):
        self.running = False
        icon = CHECK if success else CROSS
        sys.stdout.write(f"\r{icon} {self.message}   \n")
        sys.stdout.flush()
