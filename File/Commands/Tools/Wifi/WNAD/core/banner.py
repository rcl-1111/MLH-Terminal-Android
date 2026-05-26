"""
WNAD - Banner 横幅 & 帮助信息
仿 SQLMap 风格的 ASCII 艺术字 + 彩色输出
"""

from core.utils import C


BANNER = f"""
{C.RED}{C.BOLD}
  __      __ _   _    _    ____
  \\ \\    / // \\ | \\  / \\  |  _ \\
   \\ \\  / // _ \\|  \\/ _ \\ | | | |
    \\ \\/ // ___ \\ |  ___ \\| |_| |
     \\__//_/   \\_\\_| /_  \\_\\____/
{C.CYAN}
  Wireless Network Attack & Defense
  {C.YELLOW}v1.0  |  Pure Python  |  MLH-Terminal Edition{C.NC}
"""


USAGE = f"""
{C.BOLD}{C.CYAN}╔{'═'*58}╗{C.NC}
{C.BOLD}{C.CYAN}║{C.NC}  {C.GREEN}WNAD  -  无线网络攻防工具{C.NC}  {C.CYAN}║{C.NC}
{C.BOLD}{C.CYAN}╚{'═'*58}╝{C.NC}

{C.BOLD}用法:{C.NC}  wnad <命令> [参数]

{C.BOLD}{C.GREEN}[ 信息查询 ]{C.NC}
  {C.CYAN}info{C.NC}                    查看本机网络信息(接口/IP/MAC/网关/DNS)
  {C.CYAN}lookup --domain <域名>{C.NC}   解析域名到公网 IP
  {C.CYAN}lookup --cidr <网段>{C.NC}     扫描 CIDR 网段(如 192.168.1.0/24)
  {C.CYAN}lookup --public{C.NC}          查询本机公网 IP 地址

{C.BOLD}{C.GREEN}[ 网络扫描 ]{C.NC}
  {C.CYAN}scan --arp{C.NC}                ARP 扫描局域网设备
  {C.CYAN}scan --ping{C.NC}               Ping 存活探测
  {C.CYAN}scan --port <范围>{C.NC}        TCP 端口扫描(如 1-1000)
  {C.CYAN}scan --service{C.NC}            服务 Banner 指纹识别

{C.BOLD}{C.GREEN}[ 路由 & 测速 ]{C.NC}
  {C.CYAN}trace <目标>{C.NC}              路由追踪
  {C.CYAN}speedtest{C.NC}                 网速测试(HTTP下载)

{C.BOLD}{C.RED}[ 攻击模块 - 需要 ROOT 权限 ]{C.NC}
  {C.RED}arp --spoof <目标IP> <网关IP>{C.NC}  ARP 欺骗中间人
  {C.RED}flood --syn <目标> --port <端口>{C.NC}  SYN Flood 压力测试
  {C.RED}monitor --enable{C.NC}            开启 WiFi 监控模式(RT3070L)
  {C.RED}monitor --disable{C.NC}           关闭监控模式
  {C.RED}monitor --scan{C.NC}              扫描周围 WiFi AP
  {C.RED}monitor --capture{C.NC}           抓取 802.11 数据包

{C.BOLD}{C.YELLOW}[ 通用选项 ]{C.NC}
  -h, --help               显示帮助
  -v, --version            显示版本

{C.BOLD}示例:{C.NC}
  wnad info
  wnad lookup --domain example.com
  wnad lookup --cidr 192.168.1.0/24
  wnad scan --arp
  wnad scan --port 22,80,443
  wnad trace 8.8.8.8
  wnad speedtest
  {C.RED}wnad arp --spoof 192.168.1.100 192.168.1.1{C.NC}
  {C.RED}wnad monitor --enable{C.NC}
"""

VERSION = "WNAD v1.0 (MLH-Terminal Edition)"
