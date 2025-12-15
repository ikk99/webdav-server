#!/usr/bin/env python3
"""
修复数据库表结构
"""

import mysql.connector
import os
from pathlib import Path

def fix_database():
    """修复数据库表结构"""
    print("正在修复数据库表结构...")
    
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
        
        # 修复 user_folder_permissions 表
        print("修复 user_folder_permissions 表...")
        
        # 先删除现有的表（如果存在）
        cursor.execute("DROP TABLE IF EXISTS user_folder_permissions")
        
        # 重新创建表
        cursor.execute("""
            CREATE TABLE user_folder_permissions (
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INT NOT NULL,
                folder_path VARCHAR(768) NOT NULL,
                permission_id INT NOT NULL,
                granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE,
                UNIQUE KEY unique_user_folder_perm (user_id, folder_path(255), permission_id)
            )
        """)
        
        print("✓ user_folder_permissions 表修复完成")
        
        conn.commit()
        cursor.close()
        conn.close()
        
        print("数据库修复完成！")
        
    except Exception as e:
        print(f"修复数据库时出错: {e}")

if __name__ == "__main__":
    fix_database()
