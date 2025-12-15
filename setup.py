#!/usr/bin/env python3
"""
安装和配置脚本
"""

import os
import sys
import argparse
from pathlib import Path
from config import Config
from models import Database, User
import bcrypt

def init_database():
    """初始化数据库"""
    print("正在初始化数据库...")
    
    # 创建数据库连接
    conn = Database.get_connection()
    cursor = conn.cursor()
    
    # 读取 SQL 文件
    sql_file = Path(__file__).parent / "init.sql"
    if sql_file.exists():
        with open(sql_file, 'r', encoding='utf-8') as f:
            sql_commands = f.read().split(';')
        
        for command in sql_commands:
            command = command.strip()
            if command:
                try:
                    cursor.execute(command)
                except Exception as e:
                    print(f"执行 SQL 命令时出错: {e}")
    
    conn.commit()
    cursor.close()
    conn.close()
    
    print("数据库初始化完成！")

def create_admin_user(username, password, email=None):
    """创建管理员用户"""
    print(f"正在创建管理员用户: {username}")
    
    password_hash = bcrypt.hashpw(
        password.encode('utf-8'),
        bcrypt.gensalt()
    ).decode('utf-8')
    
    try:
        conn = Database.get_connection()
        cursor = conn.cursor()
        
        # 检查用户是否已存在
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            print(f"用户 {username} 已存在，跳过创建")
            return
        
        # 创建用户
        cursor.execute("""
            INSERT INTO users (username, password_hash, display_name, email, is_admin)
            VALUES (%s, %s, %s, %s, TRUE)
        """, (username, password_hash, f"{username} (管理员)", email or f"{username}@example.com"))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        print(f"管理员用户 {username} 创建成功！")
        
    except Exception as e:
        print(f"创建管理员用户失败: {e}")

def setup_environment():
    """设置环境"""
    print("正在设置环境...")
    
    # 创建必要的目录
    Config.init_directories()
    
    # 创建配置文件示例
    env_example = """# WebDAV 服务器配置
DEBUG=false

# WebDAV 服务配置
WEBDAV_HOST=0.0.0.0
WEBDAV_PORT=8080
WEBDAV_ROOT=/data

# Web 界面配置
WEB_HOST=0.0.0.0
WEB_PORT=5000
SECRET_KEY=your-secret-key-change-this

# 数据库配置
DB_HOST=localhost
DB_PORT=3306
DB_USER=webdav
DB_PASSWORD=password
DB_NAME=webdav_server

# 权限配置
DEFAULT_GLOBAL_PERMISSIONS=read,upload
ANONYMOUS_ACCESS=false

# 日志配置
LOG_LEVEL=INFO
LOG_FILE=/app/logs/webdav.log

# 上传限制
MAX_UPLOAD_SIZE=104857600
ALLOWED_EXTENSIONS=
"""
    
    env_file = Path(__file__).parent / ".env.example"
    with open(env_file, 'w') as f:
        f.write(env_example)
    
    print("环境设置完成！")
    print(f"请复制 .env.example 为 .env 并根据需要修改配置")

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="WebDAV 服务器安装脚本")
    parser.add_argument("--init-db", action="store_true", help="初始化数据库")
    parser.add_argument("--create-admin", nargs=2, metavar=("USERNAME", "PASSWORD"), 
                       help="创建管理员用户")
    parser.add_argument("--setup", action="store_true", help="运行完整设置")
    
    args = parser.parse_args()
    
    if args.setup:
        setup_environment()
        init_database()
        if not args.create_admin:
            create_admin_user("admin", "admin123")
    elif args.init_db:
        init_database()
    elif args.create_admin:
        create_admin_user(args.create_admin[0], args.create_admin[1])
    else:
        parser.print_help()

if __name__ == "__main__":
    main()