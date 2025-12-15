# storage/filesystem.py 的简化版本
from wsgidav.fs_dav_provider import FilesystemProvider
from wsgidav.dav_error import DAVError, HTTP_FORBIDDEN
from typing import Optional
import logging
from permissions import PermissionManager
from models import User

logger = logging.getLogger(__name__)

class PermissionFilesystemProvider(FilesystemProvider):
    """支持权限控制的文件系统提供者"""
    
    def __init__(self, root_path, readonly=False):
        # 简化构造函数
        super().__init__(root_path)
        self.readonly = readonly
        self.current_user = None
    
    def set_current_user(self, user: Optional[User]):
        """设置当前用户"""
        self.current_user = user
    
    def _check_permission(self, path: str, method: str) -> bool:
        """检查权限"""
        if not PermissionManager.check_permission(self.current_user, path, method):
            username = self.current_user.username if self.current_user else 'Anonymous'
            logger.warning(f"Permission denied: {username} tried to {method} {path}")
            return False
        return True
    
    def get_resource_inst(self, path: str, environ: dict):
        """获取资源实例，检查权限"""
        method = environ.get('REQUEST_METHOD', 'GET')
        
        if not self._check_permission(path, method):
            raise DAVError(HTTP_FORBIDDEN, f"Permission denied for {method} on {path}")
        
        return super().get_resource_inst(path, environ)