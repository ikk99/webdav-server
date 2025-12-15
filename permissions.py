from typing import List, Dict, Any, Set
import logging
from pathlib import Path
from models import Database, User
from config import Config

logger = logging.getLogger(__name__)

class PermissionManager:
    """权限管理器"""
    
    PERMISSION_MAP = {
        'read': {'GET', 'HEAD', 'PROPFIND'},
        'upload': {'PUT', 'MKCOL', 'COPY', 'MOVE'},
        'delete': {'DELETE'},
        'modify': {'POST', 'PROPPATCH'},
        'list': {'PROPFIND'}
    }
    
    @classmethod
    def check_permission(cls, user: User, path: str, method: str) -> bool:
        """检查用户对指定路径的HTTP方法权限"""
        
        # 匿名用户拒绝访问
        if Config.ANONYMOUS_ACCESS is False and not user:
            return False
        
        # 管理员拥有所有权限
        if user and user.is_admin:
            return True
        
        # 获取路径对应的文件夹权限
        folder_path = cls._get_folder_path(path)
        
        # 检查用户在该文件夹的权限
        user_permissions = user.get_permissions(folder_path) if user else []
        
        # 特殊处理：根目录的默认权限
        if folder_path == "/" and user:
            user_permissions.extend(Config.DEFAULT_GLOBAL_PERMISSIONS)
        
        # 检查方法对应的权限
        for perm, methods in cls.PERMISSION_MAP.items():
            if method in methods and perm in user_permissions:
                return True
        
        return False
    
    @staticmethod
    def _get_folder_path(file_path: str) -> str:
        """从文件路径获取文件夹路径"""
        if file_path == "/":
            return "/"
        
        path = Path(file_path)
        if path.is_file():
            return str(path.parent)
        return str(path)
    
    @classmethod
    def get_user_permissions(cls, user_id: int) -> Dict[str, List[str]]:
        """获取用户所有权限"""
        permissions = {}
        
        try:
            conn = Database.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("""
                SELECT ufp.folder_path, GROUP_CONCAT(p.name) as perms
                FROM user_folder_permissions ufp
                JOIN permissions p ON ufp.permission_id = p.id
                WHERE ufp.user_id = %s
                GROUP BY ufp.folder_path
            """, (user_id,))
            
            for row in cursor.fetchall():
                permissions[row['folder_path']] = row['perms'].split(',')
            
            cursor.close()
            conn.close()
            
        except Exception as e:
            logger.error(f"Get user permissions error: {e}")
        
        return permissions
    
    @classmethod
    def set_user_permissions(cls, user_id: int, folder_path: str, 
                           permission_names: List[str]) -> bool:
        """设置用户对文件夹的权限"""
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            # 删除现有权限
            cursor.execute("""
                DELETE FROM user_folder_permissions 
                WHERE user_id = %s AND folder_path = %s
            """, (user_id, folder_path))
            
            # 添加新权限
            for perm_name in permission_names:
                cursor.execute("""
                    INSERT INTO user_folder_permissions (user_id, folder_path, permission_id)
                    SELECT %s, %s, id FROM permissions WHERE name = %s
                """, (user_id, folder_path, perm_name))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return True
            
        except Exception as e:
            logger.error(f"Set user permissions error: {e}")
            return False