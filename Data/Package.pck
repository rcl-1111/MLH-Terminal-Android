# MLH-Terminal 依赖包


# 1. 系统基础工具 (必须)
curl
# 用于网络下载、API请求
git
# 用于代码和工具库克隆
vim
# 文本编辑器 (或 nano，二选一)
wget
# 备用下载工具
file
# 文件类型检测 (file-detection命令依赖)
bc
# 数学计算 (网速计算等依赖)
unzip
# 解压工具
p7zip
# 压缩/解压工具
procps
# ps, top等进程工具

# 2. 网络诊断工具 (netcheck 命令依赖)
iproute2
# ip 命令 (替代 ifconfig，更现代)
iputils-ping
# ping 命令
net-tools
# ifconfig, netstat, arp 命令 (部分旧脚本需要)
nmap
# 网络扫描
dnsutils
# dig, nslookup 命令

# 3. MLH-Terminal 自身命令依
aapt
# file-detection 的 APK 分析功能需要
binutils
# file-detection 的加壳分析需要 objdump, readelf
upx
# file-detection 的加壳/脱壳功能需要
termux-api
# netcheck 的 WiFi 深度扫描需要


python
clang
make

# Conversion 命令所需包

ffmpeg
imagemagick
sox
bc