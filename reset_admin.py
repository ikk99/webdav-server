#!/usr/bin/env python3
"""重置管理员密码脚本"""

import sys
import os
from pathlib import Path

# 添加当前目录到 Python 路径
sys.path.append(str(Path(__file__).parent))

from models import Database, User
import bcrypt

def reset_admin_password():
    """重置管理员密码"""
    try:
        # 删除现有管理员用户
        conn = Database.get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE username = 'admin'")
        conn.commit()
        cursor.close()
        conn.close()
        
        # 创建新的管理员用户
        admin_user = User.create(
            username="admin",
            password="admin123",
            display_name="系统管理员",
            email="admin@example.com",
            is_admin=True
        )
        
        if admin_user:
            print("管理员账户重置成功！")
            print("用户名: admin")
            print("密码: admin123")
        else:
            print("创建管理员账户失败")
            
    except Exception as e:
        print(f"重置管理员密码失败: {e}")

if __name__ == "__main__":
    reset_admin_password()
