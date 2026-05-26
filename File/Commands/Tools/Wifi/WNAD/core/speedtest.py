"""
WNAD - 网速测试模块
基于 HTTP 下载测速
纯 Python 实现
"""

import time
import subprocess
from core.utils import C, CHECK, CROSS, INFO


# 测试文件 URL (可靠的小文件)
TEST_URLS = [
    "http://speedtest.tele2.net/1MB.zip",
    "http://speedtest.tele2.net/512KB.zip",
    "http://speedtest.tele2.net/100KB.zip",
]

SIZE_MAP = {
    "1MB.zip": 1_048_576,
    "512KB.zip": 524_288,
    "100KB.zip": 104_857,
}


def _format_speed(bytes_per_sec: float) -> str:
    """格式化速度"""
    if bytes_per_sec >= 1_048_576:
        return f"{bytes_per_sec / 1_048_576:.2f} MB/s"
    elif bytes_per_sec >= 1024:
        return f"{bytes_per_sec / 1024:.2f} KB/s"
    else:
        return f"{bytes_per_sec:.1f} B/s"


def speedtest(timeout: int = 15):
    """
    网速测试
    通过 HTTP 下载测试文件测量速度
    """
    print(f" {INFO} 网速测试开始...\n")

    # 尝试使用 curl/wget
    for cmd_template, url in [(f, u) for u in TEST_URLS for f in [
        ["curl", "-s", "-o", "/dev/null", "-w", "%{speed_download}", "--max-time", str(timeout)],
    ]]:
        url_name = url.split("/")[-1]
        expected_size = SIZE_MAP.get(url_name, 0)

        try:
            cmd = cmd_template + [url]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)

            if result.returncode == 0 and result.stdout.strip():
                try:
                    # curl 返回速度 byte/s
                    speed = float(result.stdout.strip())
                    print(f" {CHECK} 下载速度: {C.CYAN}{_format_speed(speed)}{C.NC}")
                    print(f"   URL: {url}")
                    return speed
                except ValueError:
                    pass
        except Exception:
            continue

    # 备用: 纯 Python 实现
    print(f" {INFO} 使用 Python 内置下载测速...")
    for url in TEST_URLS:
        try:
            from urllib.request import urlopen
            url_name = url.split("/")[-1]

            start = time.time()
            with urlopen(url, timeout=timeout) as resp:
                total = 0
                chunk_size = 8192
                while True:
                    chunk = resp.read(chunk_size)
                    if not chunk:
                        break
                    total += len(chunk)
                    elapsed = time.time() - start
                    if elapsed > 0:
                        current_speed = total / elapsed
                        print(f"\r {INFO} 已下载: {total / 1024:.0f} KB | 速度: {_format_speed(current_speed)}", end="")

            elapsed = time.time() - start
            if elapsed > 0:
                speed = total / elapsed
                print(f"\n\n {CHECK} 下载速度: {C.CYAN}{_format_speed(speed)}{C.NC}")
                print(f"   数据量: {total / 1024:.0f} KB, 耗时: {elapsed:.1f}s")
                return speed
        except Exception as e:
            print(f"\n {WARN} 测试 {url} 失败: {e}")
            continue

    print(f"\n {CROSS} 所有测速 URL 均失败，请检查网络连接")
    return None
