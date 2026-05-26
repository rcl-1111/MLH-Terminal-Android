"""
WNAD - 工具模块
颜色输出、表格格式化、进度条
"""

import sys
import time
import json
import os
from datetime import datetime


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


def print_table(headers: list, rows: list, padding: int = 2):
    """打印格式化表格"""
    if not rows:
        print(f" {INFO} 无数据")
        return

    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))

    separator = "─" * (sum(col_widths) + padding * len(col_widths) + len(col_widths) + 1)

    # header
    print(f"┌{separator}┐")
    header_line = "│"
    for i, h in enumerate(headers):
        header_line += f"{' ' * padding}{C.BOLD}{h:<{col_widths[i]}}{C.NC}{' ' * padding}│"
    print(header_line)
    print(f"├{separator}┤")

    # rows
    for row in rows:
        row_line = "│"
        for i, cell in enumerate(row):
            cell_str = str(cell)
            row_line += f"{' ' * padding}{cell_str:<{col_widths[i]}}{' ' * padding}│"
        print(row_line)

    print(f"└{separator}┘")


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


def save_results(prefix: str, data: dict, data_dir: str = None):
    """
    将扫描结果保存到 Data/ 目录
    - prefix: 文件名前缀 (如 "arp_scan", "cidr_scan")
    - data: 要保存的字典数据
    - data_dir: 数据目录，默认从 os.environ['WNAD_DATA'] 获取
    """
    if not data_dir:
        data_dir = os.environ.get("WNAD_DATA", "")
    if not data_dir or not os.path.isdir(data_dir):
        return  # 静默跳过，Data 目录不存在时不影响功能

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{prefix}_{timestamp}.json"
    filepath = os.path.join(data_dir, filename)

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        print(f"   {CHECK} 结果已保存: {C.CYAN}{filename}{C.NC}")
    except Exception as e:
        print(f"   {WARN} 保存结果失败: {e}")
