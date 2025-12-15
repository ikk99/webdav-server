"""
简化的数据库初始化脚本
"""

import mysql.connector
import os
from pathlib import Path

def init_database_simple():
    """简化版数据库初始化"""
    print("正在初始化数据库...")
    
    try:
        # 直接使用环境变量
        db_config = {
            'host': os.getenv('DB_HOST', 'localhost'),
            'port': int(os.getenv('DB_PORT', 3306)),
            'user': os.getenv('DB_USER', 'webdav'),
            'password': os.getenv('DB_PASSWORD', 'Ddzhzx+135'),
            'database': os.getenv('DB_NAME', 'webdav_server')
        }
        
        print(f"尝试连接数据库: {db_config['user']}@{db_config['host']}:{db_config['port']}")
        
        # 连接数据库
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        
        print("数据库连接成功！")
        
        # 读取并执行 init.sql 文件
        sql_file = Path(__file__).parent / "init.sql"
        if sql_file.exists():
            with open(sql_file, 'r', encoding='utf-8') as f:
                sql_content = f.read()
            
            # 分割 SQL 语句并执行
            sql_statements = [stmt.strip() for stmt in sql_content.split(';') if stmt.strip()]
            
            for statement in sql_statements:
                if statement:
                    try:
                        cursor.execute(statement)
                        print(f"✓ 执行成功: {statement[:60]}...")
                    except Exception as e:
                        print(f"✗ 执行语句时出错: {e}")
                        print(f"  问题语句: {statement[:100]}")
            
            conn.commit()
            print("数据库初始化完成！")
        else:
            print(f"错误: 未找到 {sql_file}")
        
        cursor.close()
        conn.close()
        
    except mysql.connector.Error as e:
        print(f"数据库连接错误: {e}")
        print("请检查以下配置:")
        print(f"  主机: {db_config['host']}")
        print(f"  端口: {db_config['port']}")
        print(f"  用户: {db_config['user']}")
        print(f"  数据库: {db_config['database']}")
        print("可能的解决方案:")
        print("1. 检查MySQL服务是否运行: brew services start mysql")
        print("2. 检查用户权限是否正确")
        print("3. 尝试使用root用户初始化")

if __name__ == "__main__":
    init_database_simple()