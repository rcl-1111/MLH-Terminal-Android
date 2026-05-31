# Wireless-Network-Attack-Defense / WNAD

A wireless network tool written in Python, integrating multiple network tools such as Nmap, wifite, etc.
一个基于 Python 书写的无线网络工具，集成了多个网络工具，如 Nmap、wifite 等。

---

## 使用方式 / How to use this tool

You can download the zip file or use the following command to download:
您可以下载 zip 文件或使用以下命令下载：

```
git clone https://www.github.com/rcl-1111/Wireless-Network-Attack-Defense.git
```

**Windows:**
```
wnad info
wnad wifi -l
wnad nmap 192.168.1.1 -p 80,443 -sV
```

**Linux/Android (Termux):**
```
python WNAD/wnad.py info
python WNAD/wnad.py wifi -l
```

You can run it in the MLH-Terminal, or open cmd in the current directory and use the command `python ./wnad.py`. (Note: Make sure Python is installed on your computer.)
您可以在 MLH-Terminal 中运行，或是在当前目录打开 cmd 后通过 `python ./wnad.py` 命令使用。（注意：请确保你的电脑上安装了 Python）

## 主要功能 / Features

| 命令 / Command | 功能 / Function |
|------|------|
| `info` | 网络信息 / Network info |
| `lookup --cidr 192.168.1.0/24` | CIDR 网段扫描 / CIDR scan |
| `scan --port 1-1000` | 端口扫描 / Port scan |
| `nmap <target> -sV -O` | 类 nmap 扫描 / Nmap-like scan |
| `wifi -l` | WiFi 列表 / WiFi list |
| `wifi -m` | 实时 WiFi 监控 / WiFi monitor |
| `air -c` | airmon-ng 检查 / Interface check |
| `air -d` | airodump-ng 抓包 / Packet capture |
| `air --deauth <BSSID>` | Deauth 攻击 / Deauth attack |
| `wifite` | 交互式 WiFi 审计 / WiFi auditor |
| `crack hydra <host> --service ftp` | 在线破解 / Online crack |
| `crack identify <hash>` | 哈希识别 / Hash identify |
| `defense check` | 安全基线 / Security baseline |
| `defense arp` | ARP 检测 / ARP detection |
| `usb -l` | USB 设备列表 / USB devices |
| `usb -ED` | 外部网卡 / External NICs |
| `geoip <IP>` | IP 地理位置 / IP geolocation |
| `mac <MAC>` | MAC 厂商查询 / MAC lookup |
| `subnet 192.168.1.0/24` | 子网计算 / Subnet calc |
| `speedtest` | 网速测试 / Speed test |

## 目录结构 / Directory Structure

```
Wireless-Network-Attack-Defense/
├── README.md
├── wnad.cmd              # Windows 启动器 / Windows launcher
├── wnad.py               # Linux/Android 入口 / Linux entry point
└── WNAD/
    ├── wnad.py           # 主入口 / Main entry
    ├── core/             # 所有模块 / All modules
    └── data/             # 字典和 MAC 数据库 / Dicts & OUI data
```

## 问题/意见反馈 / Questions/Feedback

If you find any problems or have any comments while using it, please feel free to contact.
如果你在使用时发现问题或是有什么意见，可以随时联系。

QQ: 1175464873
Email: 1175464873@qq.com

## 解语 / Understand

I hope this is helpful to everyone.
希望对各位有所帮助。

Thank you for your use.
感谢您的使用。

The above content was written by rcl-1111.
以上内容由 rcl-1111 书写。
