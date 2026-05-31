"""
WNAD - 子网计算器模块
计算 CIDR 网段的网络地址/广播地址/可用IP范围等
"""

import ipaddress
from core.utils import C, CHECK, CROSS, INFO, print_table


def subnet_calc(cidr: str):
    """子网计算"""
    if not cidr:
        print(f" {CROSS} 请输入 CIDR 网段")
        print(f" {INFO} 示例: {C.CYAN}192.168.1.0/24{C.NC}")
        return

    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        print(f" {CROSS} 无效网段: {e}")
        return

    hosts = list(net.hosts())
    wildcard = ".".join(str(255 - int(b)) for b in str(net.netmask).split("."))

    print(f" {INFO} 子网计算: {C.CYAN}{cidr}{C.NC}\n")

    info = [
        ("网段", str(net)),
        ("网络地址", str(net.network_address)),
        ("广播地址", str(net.broadcast_address)),
        ("子网掩码", str(net.netmask)),
        ("通配符掩码", wildcard),
        ("前缀长度", f"/{net.prefixlen}"),
        ("IP 总数", str(net.num_addresses)),
        ("可用主机数", str(len(hosts))),
        ("首个可用 IP", str(hosts[0]) if hosts else "-"),
        ("最后可用 IP", str(hosts[-1]) if hosts else "-"),
        ("网络类型", "私有" if net.is_private else "公有" if net.is_global else "其他"),
    ]

    print_table(["属性", "值"], [(k, v) for k, v in info])

    # 显示 IP 范围
    print(f"\n {CHECK} 可用 IP 范围:")
    if hosts:
        print(f"   {C.CYAN}{hosts[0]}{C.NC}  →  {C.CYAN}{hosts[-1]}{C.NC}  ({len(hosts)} 个)")
    else:
        print(f"   /31 或 /32 网段无可用主机地址")
