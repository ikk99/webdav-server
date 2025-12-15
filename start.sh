#!/bin/bash

# WebDAV 服务器启动脚本

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}正在启动 WebDAV 服务器...${NC}"

# 检查 Python 版本
python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
if [[ $(echo "$python_version < 3.8" | bc) -eq 1 ]]; then
    echo -e "${RED}错误: 需要 Python 3.8 或更高版本${NC}"
    exit 1
fi

# 检查依赖
if ! command -v mysql &> /dev/null; then
    echo -e "${YELLOW}警告: MySQL 客户端未安装，但服务器仍可运行${NC}"
fi

# 激活虚拟环境（如果存在）
if [ -d "venv" ]; then
    echo "激活虚拟环境..."
    source venv/bin/activate
fi

# 检查是否已安装依赖
if [ ! -f "requirements.txt" ]; then
    echo -e "${RED}错误: requirements.txt 未找到${NC}"
    exit 1
fi

# 安装依赖
echo "安装 Python 依赖..."
pip install -r requirements.txt

# 运行数据库初始化
echo "初始化数据库..."
python setup.py --init-db

# 设置环境变量
if [ -f ".env" ]; then
    echo "加载环境变量..."
    export $(cat .env | xargs)
fi

# 创建数据目录
mkdir -p data
mkdir -p logs

# 启动服务器
echo -e "${GREEN}启动服务器...${NC}"
echo -e "${YELLOW}WebDAV 服务: http://localhost:8080${NC}"
echo -e "${YELLOW}Web 管理界面: http://localhost:5000${NC}"
echo -e "${YELLOW}按 Ctrl+C 停止服务器${NC}"

python app.py