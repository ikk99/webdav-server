import os
from pathlib import Path
from typing import Dict, Any

class Config:
    # 基础配置
    BASE_DIR = Path(__file__).parent
    DEBUG = os.getenv("DEBUG", "false").lower() == "true"
    
    # WebDAV 配置
    WEBDAV_HOST = os.getenv("WEBDAV_HOST", "0.0.0.0")
    WEBDAV_PORT = int(os.getenv("WEBDAV_PORT", "8080"))
    WEBDAV_ROOT = Path(os.getenv("WEBDAV_ROOT", BASE_DIR / "data"))
    WEBDAV_SSL_CERT = os.getenv("WEBDAV_SSL_CERT", None)
    WEBDAV_SSL_KEY = os.getenv("WEBDAV_SSL_KEY", None)
    
    # Web 界面配置
    WEB_HOST = os.getenv("WEB_HOST", "0.0.0.0")
    WEB_PORT = int(os.getenv("WEB_PORT", "5000"))
    SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-this")
    
    # 数据库配置
    DB_CONFIG = {
        'host': os.getenv("DB_HOST", "localhost"),
        'port': int(os.getenv("DB_PORT", "3306")),
        'user': os.getenv("DB_USER", "webdav"),
        'password': os.getenv("DB_PASSWORD", "password"),
        'database': os.getenv("DB_NAME", "webdav_server"),
        'charset': 'utf8mb4'
    }
    
    # 权限配置
    DEFAULT_GLOBAL_PERMISSIONS = ['read', 'upload']
    ANONYMOUS_ACCESS = False
    
    # 日志配置
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE = os.getenv("LOG_FILE", BASE_DIR / "webdav.log")
    
    # 上传限制
    MAX_UPLOAD_SIZE = int(os.getenv("MAX_UPLOAD_SIZE", 1024 * 1024 * 100))  # 100MB
    ALLOWED_EXTENSIONS = set(os.getenv("ALLOWED_EXTENSIONS", "").split(",")) or None
    
    @classmethod
    def init_directories(cls):
        """初始化必要的目录"""
        cls.WEBDAV_ROOT.mkdir(parents=True, exist_ok=True)
        (cls.BASE_DIR / "logs").mkdir(exist_ok=True)