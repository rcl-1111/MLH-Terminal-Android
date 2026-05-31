"""
WNAD - MAC 地址厂商查询模块
通过 OUI 数据库查询 MAC 地址对应的设备厂商
"""

import re
from core.utils import C, CHECK, CROSS, INFO, ARROW
from core.network import get_oui_vendor


def mac_lookup(mac: str):
    """查询 MAC 地址厂商"""
    if not mac:
        print(f" {CROSS} 请输入 MAC 地址")
        return

    # 格式化 MAC: 去除分隔符，统一格式
    mac_clean = re.sub(r'[:\-\.\s]', '', mac).upper()
    if len(mac_clean) != 12:
        print(f" {CROSS} 无效的 MAC 地址: {mac}")
        print(f" {INFO} 正确格式: {C.CYAN}XX:XX:XX:XX:XX:XX{C.NC}")
        return

    # 格式化输出
    mac_formatted = ":".join(mac_clean[i:i+2] for i in range(0, 12, 2))
    vendor = get_oui_vendor(mac_formatted)
    oui = mac_clean[:6]

    print(f" {INFO} MAC 地址查询:\n")
    print(f"   MAC:    {C.CYAN}{mac_formatted}{C.NC}")
    print(f"   OUI:    {oui}")
    print(f"   厂商:   {C.GREEN}{vendor if vendor != '未知' else '未知/未收录'}{C.NC}")
    print(f"   类型:   {'多播' if int(mac_clean[1], 16) & 1 else '单播'}")
    print(f"   全球:   {'本地管理' if int(mac_clean[1], 16) & 2 else '全球唯一'}")
