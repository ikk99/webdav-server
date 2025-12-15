#!/usr/bin/env python3
"""
检查数据库状态
"""

import mysql.connector
import os

def check_database():
    """检查数据库状态"""
    print("检查数据库状态...")
    
    db_config = {
        'host': os.getenv('DB_HOST', 'localhost'),
        'port': int(os.getenv('DB_PORT', 3306)),
        'user': os.getenv('DB_USER', 'webdav'),
        'password': os.getenv('DB_PASSWORD', 'Ddzhzx+135'),
        'database': os.getenv('DB_NAME', 'webdav_server')
    }
    
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        
        # 检查表
        cursor.execute("SHOW TABLES")
        tables = cursor.fetchall()
        print(f"✓ 数据库中有 {len(tables)} 个表:")
        for table in tables:
            print(f"  - {table[0]}")
        
        # 检查用户
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        print(f"✓ 用户数量: {user_count}")
        
        # 检查权限
        cursor.execute("SELECT name, description FROM permissions")
        permissions = cursor.fetchall()
        print(f"✓ 权限定义: {len(permissions)} 个")
        for perm in permissions:
            print(f"  - {perm[0]}: {perm[1]}")
        
        cursor.close()
        conn.close()
        
        print("\n✅ 数据库状态正常！")
        
    except Exception as e:
        print(f"❌ 检查数据库时出错: {e}")

if __name__ == "__main__":
    check_database()
