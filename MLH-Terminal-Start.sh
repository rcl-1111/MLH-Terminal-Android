#!/bin/bash
# MLH-Terminal 启动脚本
# 放在 Termux 主目录，用于启动 MLH-Terminal

MLH_HOME="./File/Home"

if [[ -f "$MLH_HOME/MLH-Terminal.sh" ]]; then
    bash "$MLH_HOME/MLH-Terminal.sh" "$@"
else
    echo "错误: MLH-Terminal 主程序不存在"
    echo "请检查: $MLH_HOME/MLH-Terminal.sh"
    exit 1
fi
