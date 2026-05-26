#!/bin/bash
# MLH-Terminal 主启动脚本
# 版本: 2.0.0
# 位置: File/Home/MLH-Terminal.sh

# 颜色定义
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
MAGENTA='\033[1;35m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

# 符号定义
CHECK="${GREEN}[√]${NC}"
CROSS="${RED}[×]${NC}"
INFO="${YELLOW}[*]${NC}"
WARN="${YELLOW}[!]${NC}"
PLUS="${GREEN}[+]${NC}"
MINUS="${RED}[-]${NC}"

# 路径定义
MLH_ROOT="/data/data/com.termux/files/home/MLH-Terminal"
MLH_DATA="$MLH_ROOT/Data"
MLH_COMMANDS="$MLH_ROOT/File/Commands"
MLH_HOME="$MLH_ROOT/File/Home"

# 内置命令：help
help() {
    echo "================================================"
    echo "        MLH-Terminal 帮助系统        "
    echo "================================================"
    echo ""
    echo "基本命令:"
    echo "  help             显示此帮助信息"
    echo "  update           更新 MLH-Terminal"
    echo "  config           查看配置文件"
    echo "  info             显示系统信息"
    echo "  clean            清理缓存和临时文件"
    echo "  backup           备份配置文件和数据"
    echo ""
    echo "SQLMap 工具命令:"
    echo "  sqlmap           SQL 注入工具"
    echo "  sqlmap-install   安装 SQLMap"
    echo "  sqlmap-update    更新 SQLMap"
    echo "  sqlmap-remove    移除 SQLMap"
    echo "  sqlmap-check     检查 SQLMap 状态"
    echo ""
    echo "文件工具:"
    echo "  file-detection   文件安全检测工具"
    echo "  netcheck         网络检测工具"
    echo ""
    echo "网络攻防工具:"
    echo "  wnad           WNAD 无线网络攻防工具"
    echo ""
    echo "快捷操作:"
    echo "  cd $MLH_ROOT     进入 MLH-Terminal 目录"
    echo "  ls $MLH_COMMANDS 查看可用命令"
    echo ""
    echo "配置文件:"
    echo "  数据目录: $MLH_DATA"
    echo "  命令目录: $MLH_COMMANDS"
    echo "  主程序: $MLH_HOME/MLH-Terminal.sh"
    echo ""
    echo "提示: 输入 'exit' 退出终端"
    echo ""
}

# 内置命令：update
update() {
    echo "正在检查 MLH-Terminal 更新..."
    cd "$MLH_ROOT"
    
    if [[ -d ".git" ]]; then
        echo "检测到 Git 仓库，正在更新..."
        git pull
        if [ $? -eq 0 ]; then
            echo "更新成功"
        else
            echo "更新失败"
        fi
    else
        echo "未找到 Git 仓库，无法自动更新"
        echo ""
        echo "手动更新方法:"
        echo "1. 备份当前版本: cp -r $MLH_ROOT $MLH_ROOT.backup"
        echo "2. 下载最新版本"
        echo "3. 替换文件"
    fi
}

# 内置命令：config
config() {
    echo "MLH-Terminal 配置信息"
    echo "================================================"
    echo ""
    echo "数据目录: $MLH_DATA"
    ls -la "$MLH_DATA" 2>/dev/null || echo "目录为空"
    echo ""
    echo "命令目录: $MLH_COMMANDS"
    ls -la "$MLH_COMMANDS" 2>/dev/null | head -20
    echo ""
    echo "主程序: $MLH_HOME/MLH-Terminal.sh"
    echo ""
}

# 内置命令：info
info() {
    echo "========== 系统信息 =========="
    echo ""
    echo "操作系统:"
    uname -a
    echo ""
    echo "Termux版本:"
    cat /data/data/com.termux/files/usr/etc/apt/sources.list 2>/dev/null | head -1 || echo "未知"
    echo ""
    echo "Android信息:"
    getprop ro.build.version.release 2>/dev/null || echo "未知"
    getprop ro.product.model 2>/dev/null || echo "未知"
    echo ""
    echo "MLH-Terminal信息:"
    echo "版本: 2.0.0"
    echo "路径: $MLH_ROOT"
    echo "命令目录: $MLH_COMMANDS"
    echo ""
    echo "已安装工具:"
    which curl 2>/dev/null && echo "  curl: 已安装" || echo "  curl: 未安装"
    which git 2>/dev/null && echo "  git: 已安装" || echo "  git: 未安装"
    which wget 2>/dev/null && echo "  wget: 已安装" || echo "  wget: 未安装"
    which vim 2>/dev/null && echo "  vim: 已安装" || echo "  vim: 未安装"
}

# 内置命令：clean
clean() {
    echo "正在清理缓存和临时文件..."
    echo ""
    
    # 清理 Termux 缓存
    echo "清理 Termux 缓存..."
    rm -rf /data/data/com.termux/files/usr/tmp/* 2>/dev/null && echo "  [√] 已清理" || echo "  [×] 清理失败"
    rm -rf /data/data/com.termux/files/home/.cache/* 2>/dev/null && echo "  [√] 已清理" || echo "  [×] 清理失败"
    
    # 清理 MLH-Terminal 临时文件
    if [[ -d "$MLH_DATA/tmp" ]]; then
        echo "清理 MLH-Terminal 临时文件..."
        rm -rf "$MLH_DATA/tmp"/* 2>/dev/null && echo "  [√] 已清理" || echo "  [×] 清理失败"
    fi
    
    echo ""
    echo "清理完成"
}

# 内置命令：backup
backup() {
    BACKUP_DIR="/data/data/com.termux/files/home/storage/downloads/MLH-Backup"
    BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
    BACKUP_FILE="mlh-backup-$BACKUP_DATE.tar.gz"
    
    echo "开始备份 MLH-Terminal..."
    echo ""
    
    # 创建备份目录
    mkdir -p "$BACKUP_DIR"
    
    # 备份配置文件
    echo "备份配置文件..."
    if tar -czf "$BACKUP_DIR/$BACKUP_FILE" \
        -C "$MLH_ROOT" \
        Data \
        File/Commands \
        File/Home/MLH-Terminal.sh 2>/dev/null; then
        echo "备份成功: $BACKUP_DIR/$BACKUP_FILE"
        echo "文件大小: $(du -h "$BACKUP_DIR/$BACKUP_FILE" 2>/dev/null | cut -f1 || echo "未知")"
    else
        echo "备份失败"
    fi
}

# 检查是否首次运行
check_first_run() {
    if [[ ! -f "$MLH_DATA/.first_run_complete" ]]; then
        echo -e "${PLUS} 检测到首次运行 MLH-Terminal"
        first_run_setup
    fi
}

# 首次运行设置
first_run_setup() {
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}        MLH-Terminal 首次运行配置         ${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e ""
    
    # 创建目录
    echo -e "${INFO} 创建目录结构..."
    mkdir -p "$MLH_DATA"
    mkdir -p "$MLH_COMMANDS"
    mkdir -p "$MLH_COMMANDS/Tools"
    mkdir -p "$MLH_HOME"
    
    # 检查 Package.pck 文件
    if [[ -f "$MLH_DATA/Package.pck" ]]; then
        echo -e "${INFO} 发现 Package.pck 文件，开始安装依赖包..."
        install_packages_from_file
    else
        echo -e "${WARN} 未找到 Package.pck 文件，跳过自动安装"
        echo -e "${INFO} 将在 $MLH_DATA 目录中创建示例 Package.pck 文件"
        
        # 创建示例 Package 文件
        cat > "$MLH_DATA/Package.pck" << 'EOF'
# MLH-Terminal 首次运行依赖包列表
# 这些包将在首次运行时自动安装

# 基础工具
curl
git
vim
wget
nano

# 网络工具
nmap
net-tools
iproute2
EOF
        
        echo -e "${CHECK} 已创建示例 Package.pck 文件"
    fi
    
    # 创建标记文件
    touch "$MLH_DATA/.first_run_complete"
    echo -e "${CHECK} 首次运行配置完成"
    echo -e ""
}

# 从 Package.pck 安装包
install_packages_from_file() {
    echo -e "${INFO} 读取包列表..."
    local packages=()
    local total_count=0
    
    while IFS= read -r line; do
        # 跳过空行和注释
        if [[ -n "$line" ]] && [[ ! "$line" =~ ^[[:space:]]*# ]]; then
            # 清理行，移除可能的版本号
            local pkg_name=$(echo "$line" | awk '{print $1}' | xargs)
            if [[ -n "$pkg_name" ]]; then
                packages+=("$pkg_name")
                total_count=$((total_count + 1))
            fi
        fi
    done < "$MLH_DATA/Package.pck"
    
    if [[ $total_count -eq 0 ]]; then
        echo -e "${WARN} Package.pck 文件中没有找到可安装的包"
        return
    fi
    
    echo -e "${CHECK} 找到 $total_count 个需要安装的包"
    echo -e ""
    
    # 安装包
    local success_count=0
    local fail_count=0
    
    for pkg in "${packages[@]}"; do
        echo -e "${INFO} 正在安装 $pkg ..."
        if pkg install -y "$pkg" >/dev/null 2>&1; then
            echo -e "  ${CHECK} 已安装 $pkg"
            success_count=$((success_count + 1))
        else
            echo -e "  ${CROSS} 安装失败 $pkg"
            fail_count=$((fail_count + 1))
        fi
    done
    
    echo -e ""
    echo -e "${CHECK} 安装完成: 成功 $success_count, 失败 $fail_count"
    echo -e ""
}

# 显示启动横幅
show_banner() {
    clear
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}            MLH-Terminal 终端环境             ${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e ""
    echo -e "${INFO} 版本: 2.0.0"
    echo -e "${INFO} 作者: MLH Terminal 团队"
    echo -e "${INFO} 路径: $MLH_ROOT"
    echo -e ""
}

# 加载自定义命令
load_commands() {
    echo -e "${INFO} 加载自定义命令..."
    
    # 检查命令目录
    if [[ ! -d "$MLH_COMMANDS" ]]; then
        echo -e "${WARN} 命令目录不存在: $MLH_COMMANDS"
        return 1
    fi
    
    # 添加到 PATH
    if [[ ":$PATH:" != *":$MLH_COMMANDS:"* ]]; then
        export PATH="$MLH_COMMANDS:$PATH"
        echo -e "${CHECK} 已添加命令目录到 PATH"
    fi
    
    # 统计命令数量
    local command_count=0
    for cmd in "$MLH_COMMANDS"/*; do
        if [[ -f "$cmd" ]] && [[ -x "$cmd" ]]; then
            command_count=$((command_count + 1))
        fi
    done
    
    if [[ $command_count -eq 0 ]]; then
        echo -e "${WARN} 未找到可执行命令"
    else
        echo -e "${CHECK} 发现 $command_count 个内置命令"
    fi
}

# 显示系统信息
show_system_info() {
    echo -e ""
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}              系统信息概览               ${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e ""
    
    # 获取系统信息
    local termux_version=$(cat /data/data/com.termux/files/usr/etc/apt/sources.list 2>/dev/null | head -1 | grep -o "termux.*" || echo "未知")
    local android_version=$(getprop ro.build.version.release 2>/dev/null || echo "未知")
    local device_model=$(getprop ro.product.model 2>/dev/null || echo "未知")
    local cpu_arch=$(uname -m)
    local kernel_version=$(uname -r)
    
    echo -e "${INFO} Termux版本: $termux_version"
    echo -e "${INFO} Android版本: $android_version"
    echo -e "${INFO} 设备型号: $device_model"
    echo -e "${INFO} CPU架构: $cpu_arch"
    echo -e "${INFO} 内核版本: $kernel_version"
    echo -e ""
    echo -e "${INFO} MLH-Terminal路径: $MLH_ROOT"
    echo -e "${INFO} 数据目录: $MLH_DATA"
    echo -e "${INFO} 命令目录: $MLH_COMMANDS"
    echo -e ""
}

# 显示欢迎信息
show_welcome() {
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}        欢迎使用 MLH-Terminal 终端环境         ${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e ""
    echo -e "${INFO} 内置命令:"
    echo -e "  • help          显示帮助信息"
    echo -e "  • update        更新 MLH-Terminal"
    echo -e "  • config        查看配置文件"
    echo -e "  • info          显示系统信息"
    echo -e "  • clean         清理缓存和临时文件"
    echo -e "  • backup        备份配置文件和数据"
    echo -e ""
    echo -e "${INFO} SQLMap 工具:"
    echo -e "  • sqlmap         SQL 注入工具"
    echo -e "  • sqlmap-install 安装 SQLMap"
    echo -e "  • sqlmap-update  更新 SQLMap"
    echo -e "  • sqlmap-remove  移除 SQLMap"
    echo -e "  • sqlmap-check   检查 SQLMap 状态"
    echo -e ""
    echo -e "${INFO} 其他工具:"
    echo -e "  • file-detection 文件安全检测工具"
    echo -e "  • netcheck       网络检测工具"
    echo -e ""
    echo -e "${INFO} 网络攻防工具:"
    echo -e "  • wnad           WNAD 无线网络攻防工具"
    echo -e ""
    echo -e "${YELLOW}提示: 输入 'exit' 退出终端${NC}"
    echo -e ""
}

# 主函数
main() {
    # 显示启动横幅
    show_banner
    
    # 检查是否首次运行
    check_first_run
    
    # 检查系统环境
    echo -e "${INFO} 检查系统环境..."
    if [[ ! -d "/data/data/com.termux" ]]; then
        echo -e "${CROSS} 错误: 此脚本需要在 Termux 环境中运行"
        exit 1
    fi
    echo -e "${CHECK} 系统环境正常"
    
    # 设置工作目录
    cd "$MLH_ROOT" || {
        echo -e "${CROSS} 无法切换到工作目录"
        exit 1
    }
    
    # 加载自定义命令
    load_commands
    
    # 显示系统信息
    show_system_info
    
    # 显示欢迎信息
    show_welcome
    
    # 设置环境变量
    export MLH_ROOT
    export MLH_DATA
    export MLH_COMMANDS
    export MLH_HOME
    
    # 设置别名
    alias mlh='cd $MLH_ROOT'
    alias mlh-cmds='cd $MLH_COMMANDS'
    alias mlh-home='cd $MLH_HOME'
    alias mlh-data='cd $MLH_DATA'
    
    # 设置 PS1 提示符
    export PS1="\[${GREEN}\]\u@\h\[${NC}\]:\[${BLUE}\]\w\[${NC}\]\\$ "
    
    # 启动完成
    echo -e "${GREEN}MLH-Terminal 已启动！${NC}"
    echo -e ""
    
    # 在启动后执行命令（如果提供了参数）
    if [[ $# -gt 0 ]]; then
        case "$1" in
            help)
                help
                ;;
            update)
                update
                ;;
            config)
                config
                ;;
            info)
                info
                ;;
            clean)
                clean
                ;;
            backup)
                backup
                ;;
            *)
                echo "未知命令: $1"
                echo "使用 'help' 查看可用命令"
                ;;
        esac
    fi
}

# 运行主函数
main "$@"

# 启动交互式 shell
exec bash
