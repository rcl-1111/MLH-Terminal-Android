"""
WNAD - Banner 横幅 & 帮助信息
仿 SQLMap 风格的 ASCII 艺术字 + 彩色输出
"""

from core.utils import C


BANNER = f"""
{C.RED}{C.BOLD}
  ██╗    ██╗███╗   ██╗ █████╗ ██████╗
  ██║    ██║████╗  ██║██╔══██╗██╔══██╗
  ██║ █╗ ██║██╔██╗ ██║███████║██║  ██║
  ██║███╗██║██║╚██╗██║██╔══██║██║  ██║
  ╚███╔███╔╝██║ ╚████║██║  ██║██████╔╝
   ╚══╝╚══╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═════╝
{C.CYAN}
  Wireless Network Attack & Defense
  {C.YELLOW}v1.0  |  Pure Python  |  MLH-Terminal Edition{C.NC}
{C.YELLOW}Github：https://www.github.com/rcl-1111/Wireless-Network-Attack-Defense
        https://www.github.com/rcl-1111/MLH-Terminal{C.NC}
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

{C.BOLD}{C.GREEN}[ 网络发现 ]{C.NC}
  {C.CYAN}discover{C.NC}                 网络设备发现 (类似 netdiscover)
  {C.CYAN}discover --cidr <网段>{C.NC}   指定网段扫描
  {C.CYAN}ping <目标>{C.NC}              持续 Ping 监控 (Ctrl+C 停止)
  {C.CYAN}ping <目标> --count 10{C.NC}   指定次数

{C.BOLD}{C.GREEN}[ DNS & 查询 ]{C.NC}
  {C.CYAN}dns <域名>{C.NC}               DNS 记录枚举 (A/AAAA/MX/NS/TXT/...)
  {C.CYAN}geoip <IP>{C.NC}               IP 地理位置查询
  {C.CYAN}mac <MAC>{C.NC}                MAC 地址厂商查询
  {C.CYAN}subnet <CIDR>{C.NC}            子网计算器

{C.BOLD}{C.GREEN}[ 网络扫描 ]{C.NC}
  {C.CYAN}scan --arp{C.NC}                ARP 扫描局域网设备
  {C.CYAN}scan --ping{C.NC}               Ping 存活探测
  {C.CYAN}scan --port <范围>{C.NC}        TCP 端口扫描(如 1-1000)
  {C.CYAN}scan --service{C.NC}            服务 Banner 指纹识别

{C.BOLD}{C.GREEN}[ 路由 & 测速 ]{C.NC}
  {C.CYAN}trace <目标>{C.NC}              路由追踪
  {C.CYAN}speedtest{C.NC}                 网速测试(HTTP下载)

{C.BOLD}{C.GREEN}[ 高级工具 - 无 root ]{C.NC}
  {C.CYAN}proxy --port 8080{C.NC}         启动 HTTP 代理服务器
  {C.CYAN}netstat{C.NC}                   查看网络连接状态
  {C.CYAN}arpwatch{C.NC}                  ARP 设备监视器 (轮询)
  {C.CYAN}httpd --port 8888{C.NC}         HTTP 文件服务器 (上传/浏览)

{C.BOLD}{C.GREEN}[ Nmap 风格扫描 ]{C.NC}
  {C.CYAN}nmap <目标>{C.NC}                  综合扫描 (top100 端口)
  {C.CYAN}nmap <目标> -p 22,80,443{C.NC}     指定端口
  {C.CYAN}nmap <目标> -p 1-1000{C.NC}        端口范围
  {C.CYAN}nmap <目标> --top-ports 1000{C.NC}  TOP 1000 端口
  {C.CYAN}nmap <目标> -sU{C.NC}              UDP 扫描
  {C.CYAN}nmap <目标> -sV{C.NC}              服务版本探测
  {C.CYAN}nmap <目标> -O{C.NC}               OS 检测 (基于 TTL)
  {C.CYAN}nmap <目标> -T4{C.NC}              激进模式
  {C.CYAN}nmap <目标> -v{C.NC}               详细输出
  {C.CYAN}nmap <目标> -oN result.txt{C.NC}  输出到文件

{C.BOLD}{C.GREEN}[ 网络安全防御 ]{C.NC}
  {C.CYAN}defense check{C.NC}               安全基线检查 (WiFi/端口/DNS)
  {C.CYAN}defense arp{C.NC}                  ARP 欺骗检测
  {C.CYAN}defense arp --monitor{C.NC}        ARP 欺骗持续监控
  {C.CYAN}defense ports{C.NC}                本地端口监听监控
  {C.CYAN}defense dns{C.NC}                  DNS 劫持检测
  {C.CYAN}defense dns --domain baidu.com{C.NC}  指定检测域名
  {C.CYAN}defense scan{C.NC}                 端口扫描攻击检测
  {C.CYAN}defense monitor{C.NC}              实时连接监控

{C.BOLD}{C.GREEN}[ USB 设备检测 ]{C.NC}
  {C.CYAN}usb -l{C.NC}                     列出所有 USB 设备
  {C.CYAN}usb -ED{C.NC}                    列出外部网卡设备 (RT3070L 等)
  {C.CYAN}usb -m{C.NC}                     USB 插拔实时监控
  {C.CYAN}usb --info <名称/ID>{C.NC}       查看 USB 设备详情
  {C.CYAN}usb --security{C.NC}             USB 安全检测 (BadUSB)
  {C.CYAN}usb --connect{C.NC}               交互式网卡选择器

{C.BOLD}{C.GREEN}[ Aircrack-ng 套件 ]{C.NC}
  {C.CYAN}air{C.NC}                        检查接口+干扰进程 (airmon-ng check)
  {C.CYAN}air --start{C.NC}                开启监控模式 (airmon-ng start)
  {C.CYAN}air --stop{C.NC}                 关闭监控模式 (airmon-ng stop)
  {C.CYAN}air -d{C.NC}                     实时抓包显示 (airodump-ng)
  {C.CYAN}air -d -i wlan0{C.NC}            指定接口抓包
  {C.CYAN}air -d --channel 6{C.NC}         锁定信道抓包
  {C.CYAN}air -d -o output{C.NC}           保存到文件 (.csv)
  {C.CYAN}air --deauth <BSSID>{C.NC}       Deauth 攻击 (aireplay-ng -0)

{C.BOLD}{C.GREEN}[ 自动化 WiFi 审计 ]{C.NC}
  {C.CYAN}wifite{C.NC}                     交互式 WiFi 审计向导 (类 wifite)

{C.BOLD}{C.GREEN}[ 密码破解 (类 Kali Linux) ]{C.NC}
  {C.CYAN}crack identify <hash>{C.NC}          识别哈希类型 (hash-identifier)
  {C.CYAN}crack hash <hash> --dict <文件>{C.NC}     字典破解哈希 (John/Hashcat)
  {C.CYAN}crack hydra <host> --service ftp{C.NC}    在线暴力破解 (Hydra)
  {C.CYAN}crack wordlist --charset num{C.NC}        生成密码字典 (Crunch)

{C.BOLD}{C.GREEN}[ WiFi 工具 ]{C.NC}
  {C.CYAN}wifi -l{C.NC}                    列出周围网络 (含加密/信号)
  {C.CYAN}wifi -m{C.NC}                    实时监控模式 (类 airodump-ng)
  {C.CYAN}wifi --name <SSID> --info{C.NC}  网络详情
  {C.CYAN}wifi --name <SSID> --ip{C.NC}    网络 IP 信息
  {C.CYAN}wifi --dict-list{C.NC}            列出可用破解字典
  {C.RED}wifi --deauth <BSSID>{C.NC}       [ROOT] Deauth 攻击
  {C.RED}wifi --handshake --name <SSID>{C.NC}  [ROOT] 捕获 WPA 握手包
  {C.RED}wifi --crack <文件.cap> --dict 字典名{C.NC}  [ROOT] WPA 破解
  {C.RED}wifi --wps{C.NC}                   [ROOT] WPS 扫描

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
  wnad air                          检查 WiFi 接口和干扰进程
  wnad air --start                  开启监控模式
  wnad air --stop                   关闭监控模式
  wnad air -d                       实时抓包 (airodump-ng)
  wnad air -d -i wlan0 --channel 6  锁定信道 6 抓包
  wnad air -d -o /sdcard/capture    保存抓包结果
  wnad air --deauth AA:BB:CC:DD:EE:FF  Deauth 攻击
  wnad wifite                       交互式 WiFi 审计
  wnad crack identify e10adc3949ba59abbe56e057f20f883e
  wnad crack hash e10adc3949ba59abbe56e057f20f883e --dict rockyou.txt
  wnad crack hydra 192.168.1.1 --service ftp --user admin --dict passwords.txt
  wnad crack wordlist --charset alnum --min 4 --max 6 --limit 100
  wnad crack wordlist --pattern @@@% --output words.txt
  wnad nmap 192.168.1.1 -p 22,80,443 -sV -O
  wnad nmap 192.168.1.1 -p 1-1000 -T4 -v
  wnad nmap scanme.nmap.org -p top1000
  wnad wifi -l
  wnad wifi -m
  {C.RED}wnad wifi --deauth XX:XX:XX:XX:XX:XX{C.NC}
  {C.RED}wnad wifi --handshake --name MyWiFi{C.NC}
  {C.RED}wnad wifi --crack handshake.cap --dict common.txt{C.NC}
  wnad proxy --port 8080
  wnad geoip 8.8.8.8
  wnad mac 00:11:22:AA:BB:CC
  wnad subnet 192.168.1.0/24
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
