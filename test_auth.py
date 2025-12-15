#!/usr/bin/env python3
"""测试认证"""

import sys
import os
from pathlib import Path

# 添加当前目录到 Python 路径
sys.path.append(str(Path(__file__).parent))

from models import User

def test_authentication():
    """测试认证"""
    print("测试用户认证...")
    
    # 测试管理员认证
    admin_user = User.authenticate("admin", "admin123")
    if admin_user:
        print("✓ 管理员认证成功")
        print(f"  用户名: {admin_user.username}")
        print(f"  显示名: {admin_user.display_name}")
        print(f"  是管理员: {admin_user.is_admin}")
    else:
        print("✗ 管理员认证失败")
    
    # 测试错误密码
    wrong_user = User.authenticate("admin", "wrongpassword")
    if not wrong_user:
        print("✓ 错误密码测试通过")
    else:
        print("✗ 错误密码测试失败")

if __name__ == "__main__":
    test_authentication()
