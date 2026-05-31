"""
WNAD - Root 权限检测模块
在 Android/Termux 环境下检测是否拥有 root 权限
"""

import os
import subprocess
from core.utils import C, ROOT, CROSS, INFO


def is_root() -> bool:
    """
    检测当前是否拥有 root 权限
    兼容 Android Termux 环境
    Windows 上直接返回 True（不限制）
    """
    # Windows 无 root 概念，直接放行
    try:
        from core.utils import is_windows
        if is_windows():
            return True
    except Exception:
        pass

    # 方法1: os.geteuid()
    try:
        if os.geteuid() == 0:
            return True
    except AttributeError:
        pass

    # 方法2: id 命令
    try:
        result = subprocess.run(
            ["id", "-u"], capture_output=True, text=True, timeout=3
        )
        if result.returncode == 0 and result.stdout.strip() == "0":
            return True
    except Exception:
        pass

    # 方法3: whoami
    try:
        result = subprocess.run(
            ["whoami"], capture_output=True, text=True, timeout=3
        )
        if result.stdout.strip() == "root":
            return True
    except Exception:
        pass

    return False


def require_root(command_name: str = "此操作") -> bool:
    """
    检查 root 权限，无权限时打印提示并返回 False
    有权限时返回 True
    """
    if is_root():
        return True

    print(f" {CROSS} {command_name} {C.RED}{C.BOLD}需要 ROOT 权限{C.NC}")
    print(f" {INFO} 请使用 {C.YELLOW}sudo{C.NC} 或 {C.YELLOW}tsu{C.NC} 提权后重试")
    print(f" {INFO} 在 Termux 中: {C.YELLOW}tsu{C.NC} 然后重新运行命令")
    return False


def require_root_graceful(command_name: str = "此操作",
                          fallback_desc: str = "使用阉割版") -> bool:
    """
    检查 root 权限。
    - root → 返回 True
    - 非 root → 询问用户是否使用阉割版，是则返回 False (调用方执行 fallback)
    """
    if is_root():
        return True

    print(f" {ROOT} {C.RED}{command_name} 需要 ROOT 权限{C.NC}")
    print(f" {INFO} 检测到非 root 环境")
    print(f" {INFO} {C.YELLOW}{fallback_desc}{C.NC}")

    try:
        choice = input(f" {C.CYAN}[?]{C.NC} 是否使用阉割版？(y/n): ").strip().lower()
        if choice in ("y", "yes"):
            print()
            return False  # 调用方执行 fallback
        else:
            print(f" {INFO} 已取消")
            return None  # 取消操作
    except (EOFError, KeyboardInterrupt):
        print()
        return None
