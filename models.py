from datetime import datetime, timedelta
import bcrypt
import mysql.connector
from mysql.connector import pooling, Error
from typing import Optional, List, Dict, Any, Tuple
import logging
from config import Config

logger = logging.getLogger(__name__)

class Database:
    """数据库连接池"""
    _pool = None
    
    @classmethod
    def initialize_pool(cls) -> None:
        """初始化连接池"""
        if cls._pool is None:
            try:
                cls._pool = pooling.MySQLConnectionPool(
                    pool_name="webdav_pool",
                    pool_size=10,
                    pool_reset_session=True,
                    **Config.DB_CONFIG
                )
                logger.info("Database connection pool initialized successfully")
            except Error as e:
                logger.error(f"Failed to initialize database pool: {e}")
                raise
    
    @classmethod
    def get_pool(cls) -> pooling.MySQLConnectionPool:
        """获取连接池"""
        if cls._pool is None:
            cls.initialize_pool()
        return cls._pool
    
    @classmethod
    def get_connection(cls) -> mysql.connector.connection.MySQLConnection:
        """获取数据库连接"""
        try:
            return cls.get_pool().get_connection()
        except Error as e:
            logger.error(f"Failed to get database connection: {e}")
            raise
    
    @classmethod
    def execute_query(cls, query: str, params: Tuple = None, 
                     fetch: bool = False) -> Optional[List[Dict]]:
        """执行查询的便捷方法"""
        conn = None
        cursor = None
        try:
            conn = cls.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute(query, params or ())
            
            if fetch:
                result = cursor.fetchall()
            else:
                conn.commit()
                result = None
            
            return result
            
        except Error as e:
            logger.error(f"Query execution error: {e}")
            if conn:
                conn.rollback()
            return None
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    @classmethod
    def health_check(cls) -> bool:
        """数据库健康检查"""
        try:
            conn = cls.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.close()
            conn.close()
            return True
        except Error as e:
            logger.error(f"Database health check failed: {e}")
            return False

class User:
    """用户模型"""
    
    def __init__(self, user_data: Dict[str, Any]):
        self.id = user_data['id']
        self.username = user_data['username']
        self.password_hash = user_data['password_hash']
        self.display_name = user_data.get('display_name', '')
        self.email = user_data.get('email', '')
        self.is_active = user_data.get('is_active', True)
        self.is_admin = user_data.get('is_admin', False)
        self.created_at = user_data.get('created_at')
        self.updated_at = user_data.get('updated_at')
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'id': self.id,
            'username': self.username,
            'display_name': self.display_name,
            'email': self.email,
            'is_active': self.is_active,
            'is_admin': self.is_admin,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }
    
    @classmethod
    def authenticate(cls, username: str, password: str) -> Optional['User']:
        """用户认证"""
        if not username or not password:
            return None
            
        try:
            conn = Database.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute(
                "SELECT * FROM users WHERE username = %s AND is_active = TRUE",
                (username,)
            )
            user_data = cursor.fetchone()
            
            if user_data and bcrypt.checkpw(
                password.encode('utf-8'),
                user_data['password_hash'].encode('utf-8')
            ):
                logger.info(f"User authenticated successfully: {username}")
                return cls(user_data)
            else:
                logger.warning(f"Authentication failed for user: {username}")
                
        except Exception as e:
            logger.error(f"Authentication error for user {username}: {e}")
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
        return None
    
    @classmethod
    def get_by_id(cls, user_id: int) -> Optional['User']:
        """通过ID获取用户"""
        try:
            conn = Database.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute(
                "SELECT * FROM users WHERE id = %s",
                (user_id,)
            )
            user_data = cursor.fetchone()
            
            if user_data:
                return cls(user_data)
                
        except Exception as e:
            logger.error(f"Get user by ID error: {e}")
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
        return None
    
    @classmethod
    def get_by_username(cls, username: str) -> Optional['User']:
        """通过用户名获取用户"""
        try:
            conn = Database.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute(
                "SELECT * FROM users WHERE username = %s",
                (username,)
            )
            user_data = cursor.fetchone()
            
            if user_data:
                return cls(user_data)
                
        except Exception as e:
            logger.error(f"Get user by username error: {e}")
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
        return None
    
    @classmethod
    def get_all(cls, active_only: bool = True) -> List['User']:
        """获取所有用户"""
        users = []
        try:
            conn = Database.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            if active_only:
                cursor.execute("SELECT * FROM users WHERE is_active = TRUE")
            else:
                cursor.execute("SELECT * FROM users")
            
            for row in cursor.fetchall():
                users.append(cls(row))
                
        except Exception as e:
            logger.error(f"Get all users error: {e}")
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
        return users
    
    @classmethod
    def create(cls, username: str, password: str, **kwargs) -> Optional['User']:
        """创建新用户"""
        if not username or not password:
            return None
            
        # 检查用户名是否已存在
        if cls.get_by_username(username):
            logger.warning(f"Username already exists: {username}")
            return None
            
        try:
            password_hash = bcrypt.hashpw(
                password.encode('utf-8'),
                bcrypt.gensalt()
            ).decode('utf-8')
            
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO users (username, password_hash, display_name, email, is_admin, created_at)
                VALUES (%s, %s, %s, %s, %s, NOW())
            """, (
                username,
                password_hash,
                kwargs.get('display_name', ''),
                kwargs.get('email', ''),
                kwargs.get('is_admin', False)
            ))
            
            conn.commit()
            user_id = cursor.lastrowid
            
            cursor.close()
            conn.close()
            
            logger.info(f"User created successfully: {username}")
            return cls.get_by_id(user_id)
            
        except Exception as e:
            logger.error(f"Create user error: {e}")
            return None
    
    def update_password(self, new_password: str) -> bool:
        """更新用户密码"""
        try:
            new_password_hash = bcrypt.hashpw(
                new_password.encode('utf-8'),
                bcrypt.gensalt()
            ).decode('utf-8')
            
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE users 
                SET password_hash = %s, updated_at = NOW()
                WHERE id = %s
            """, (new_password_hash, self.id))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            self.password_hash = new_password_hash
            logger.info(f"Password updated for user: {self.username}")
            return True
            
        except Exception as e:
            logger.error(f"Update password error for user {self.username}: {e}")
            return False
    
    def update_profile(self, display_name: str = None, email: str = None) -> bool:
        """更新用户资料"""
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            update_fields = []
            params = []
            
            if display_name is not None:
                update_fields.append("display_name = %s")
                params.append(display_name)
                self.display_name = display_name
                
            if email is not None:
                update_fields.append("email = %s")
                params.append(email)
                self.email = email
                
            if not update_fields:
                return True
                
            params.append(self.id)
            
            cursor.execute(f"""
                UPDATE users 
                SET {', '.join(update_fields)}, updated_at = NOW()
                WHERE id = %s
            """, params)
            
            conn.commit()
            cursor.close()
            conn.close()
            
            logger.info(f"Profile updated for user: {self.username}")
            return True
            
        except Exception as e:
            logger.error(f"Update profile error for user {self.username}: {e}")
            return False
    
    def deactivate(self) -> bool:
        """停用用户"""
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE users 
                SET is_active = FALSE, updated_at = NOW()
                WHERE id = %s
            """, (self.id,))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            self.is_active = False
            logger.info(f"User deactivated: {self.username}")
            return True
            
        except Exception as e:
            logger.error(f"Deactivate user error: {e}")
            return False
    
    def get_permissions(self, path: str = "/") -> List[str]:
        """获取用户在指定路径的权限"""
        permissions = []
        
        # 首先添加全局默认权限
        if path == "/":
            permissions.extend(getattr(Config, 'DEFAULT_GLOBAL_PERMISSIONS', ['read']))
        
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            # 获取用户在该路径的权限
            cursor.execute("""
                SELECT p.name 
                FROM permissions p
                JOIN user_folder_permissions ufp ON p.id = ufp.permission_id
                WHERE ufp.user_id = %s AND ufp.folder_path = %s
            """, (self.id, path))
            
            for row in cursor.fetchall():
                permissions.append(row[0])
            
            cursor.close()
            conn.close()
            
        except Exception as e:
            logger.error(f"Get permissions error for user {self.username}: {e}")
        
        return list(set(permissions))  # 去重
    
    def has_permission(self, path: str, permission: str) -> bool:
        """检查用户是否有指定路径的特定权限"""
        return permission in self.get_permissions(path)
    
    def get_accessible_folders(self) -> List[Dict[str, Any]]:
        """获取用户可以访问的所有文件夹及其权限"""
        folders = []
        
        try:
            conn = Database.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("""
                SELECT ufp.folder_path as path, p.name as permission
                FROM user_folder_permissions ufp
                JOIN permissions p ON ufp.permission_id = p.id
                WHERE ufp.user_id = %s
                ORDER BY ufp.folder_path
            """, (self.id,))
            
            # 按路径分组权限
            folder_permissions = {}
            for row in cursor.fetchall():
                path = row['path']
                permission = row['permission']
                
                if path not in folder_permissions:
                    folder_permissions[path] = []
                folder_permissions[path].append(permission)
            
            # 转换为返回格式
            for path, permissions in folder_permissions.items():
                folders.append({
                    'path': path,
                    'permissions': permissions
                })
            
            cursor.close()
            conn.close()
            
        except Exception as e:
            logger.error(f"Get accessible folders error for user {self.username}: {e}")
        
        return folders
    
    def add_folder_permission(self, folder_path: str, permission: str) -> bool:
        """为用户添加文件夹权限"""
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            # 首先获取权限ID
            cursor.execute("SELECT id FROM permissions WHERE name = %s", (permission,))
            permission_row = cursor.fetchone()
            
            if not permission_row:
                logger.error(f"Permission not found: {permission}")
                return False
            
            permission_id = permission_row[0]
            
            # 检查是否已存在该权限
            cursor.execute("""
                SELECT 1 FROM user_folder_permissions 
                WHERE user_id = %s AND folder_path = %s AND permission_id = %s
            """, (self.id, folder_path, permission_id))
            
            if cursor.fetchone():
                logger.warning(f"Permission already exists: {permission} for path {folder_path}")
                return True
            
            # 添加权限
            cursor.execute("""
                INSERT INTO user_folder_permissions (user_id, folder_path, permission_id)
                VALUES (%s, %s, %s)
            """, (self.id, folder_path, permission_id))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            logger.info(f"Permission {permission} added for path {folder_path} to user {self.username}")
            return True
            
        except Exception as e:
            logger.error(f"Add folder permission error: {e}")
            return False

# 初始化数据库连接池
Database.initialize_pool()