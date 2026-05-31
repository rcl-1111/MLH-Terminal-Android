"""
WNAD - GeoIP 地理位置查询模块
通过免费 API 查询 IP 地址的地理位置信息
"""

import json
import socket
import re
import subprocess
from core.utils import C, CHECK, CROSS, INFO, print_table


def _http_get(url: str, timeout: int = 5) -> str:
    """HTTP GET 请求，尝试 curl/wget/urllib"""
    for cmd in [
        ["curl", "-s", "--connect-timeout", str(timeout), url],
        ["wget", "-qO-", "--timeout=" + str(timeout), url],
    ]:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except Exception:
            continue

    try:
        from urllib.request import urlopen
        with urlopen(url, timeout=timeout) as resp:
            return resp.read().decode()
    except Exception:
        pass

    return ""


def geoip_lookup(ip_or_domain: str):
    """查询 IP 地理位置"""
    if not ip_or_domain:
        print(f" {CROSS} 请输入 IP 地址或域名")
        return

    ip = ip_or_domain
    if not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
        try:
            ip = socket.gethostbyname(ip)
        except Exception:
            print(f" {CROSS} 无法解析: {ip_or_domain}")
            return

    print(f" {INFO} 查询地理位置: {C.CYAN}{ip}{C.NC}\n")

    # 方法1: ip-api.com (免费，无需 API key)
    data = _http_get(f"http://ip-api.com/json/{ip}?fields=16777215")
    if data:
        try:
            info = json.loads(data)
            if info.get("status") == "success":
                rows = [
                    ("国家", info.get("country", "?"), ""),
                    ("地区", info.get("regionName", "?"), ""),
                    ("城市", info.get("city", "?"), ""),
                    ("ISP", info.get("isp", "?"), ""),
                    ("组织", info.get("org", "?"), ""),
                    ("AS", info.get("as", "?"), ""),
                    ("时区", info.get("timezone", "?"), ""),
                    ("经纬度", f'{info.get("lat", "?")}, {info.get("lon", "?")}', ""),
                ]
                print_table(["字段", "值", ""], rows)
                return
        except Exception:
            pass

    # 方法2: ipinfo.io (备用)
    data = _http_get(f"https://ipinfo.io/{ip}/json")
    if data:
        try:
            info = json.loads(data)
            if info.get("ip"):
                loc = info.get("loc", "").split(",")
                rows = [
                    ("IP", info.get("ip", "?"), ""),
                    ("国家", info.get("country", "?"), ""),
                    ("地区", info.get("region", "?"), ""),
                    ("城市", info.get("city", "?"), ""),
                    ("组织", info.get("org", "?"), ""),
                    ("邮编", info.get("postal", "?"), ""),
                    ("时区", info.get("timezone", "?"), ""),
                    ("经纬度", f'{loc[0] if len(loc)>0 else "?"}, {loc[1] if len(loc)>1 else "?"}', ""),
                ]
                print_table(["字段", "值", ""], rows)
                return
        except Exception:
            pass

    print(f" {CROSS} 无法获取地理位置信息（请检查网络连接）")
