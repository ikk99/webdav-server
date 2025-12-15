#!/usr/bin/env python3
"""
WebDAV 服务器主程序
"""

import os
import sys
import logging
from logging.handlers import RotatingFileHandler
from wsgidav.wsgidav_app import WsgiDAVApp
from cheroot import wsgi
from auth import Authenticator
from storage.filesystem import PermissionFilesystemProvider
from models import Database, User
from web_interface import create_web_app
from config import Config
import threading

# 配置日志
def setup_logging():
    """配置日志系统"""
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # 控制台日志
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter(log_format))
    
    # 文件日志
    file_handler = RotatingFileHandler(
        Config.LOG_FILE,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(getattr(logging, Config.LOG_LEVEL))
    file_handler.setFormatter(logging.Formatter(log_format))
    
    # 配置根日志记录器
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)
    
    # 设置第三方库的日志级别
    logging.getLogger('wsgidav').setLevel(logging.WARNING)
    logging.getLogger('cheroot').setLevel(logging.WARNING)

class WebDAVServer:
    """WebDAV 服务器类"""
    
    def __init__(self):
        self.config = Config
        self.config.init_directories()
        self.authenticator = Authenticator()
        self.web_app = None
        self.webdav_app = None
        
    def create_webdav_app(self):
        """创建 WebDAV 应用"""
        
        # 创建自定义文件系统提供者
        provider = PermissionFilesystemProvider(
            root_path=str(Config.WEBDAV_ROOT),
            readonly=False,
        )
        
        # 配置 WebDAV - 直接使用 provider，不需要 DAVProvider 包装
        config = {
            "host": Config.WEBDAV_HOST,
            "port": Config.WEBDAV_PORT,
            "provider_mapping": {
                "/": provider,  # 直接使用 provider
            },
            "verbose": 1 if Config.DEBUG else 0,
            "logging": {
                "enable": True,
                "logger": logging.getLogger("wsgidav"),
            },
            "property_manager": True,
            "lock_storage": True,
            "http_authenticator": {
                "domain_controller": self.authenticator.get_domain_controller(),
            },
            "middleware_stack": [
                # 自定义中间件，用于设置当前用户
                self._create_user_middleware,
            ],
        }
        
        # 启用 SSL（如果配置了证书）
        if Config.WEBDAV_SSL_CERT and Config.WEBDAV_SSL_KEY:
            config["ssl_certificate"] = Config.WEBDAV_SSL_CERT
            config["ssl_private_key"] = Config.WEBDAV_SSL_KEY
        
        self.webdav_app = WsgiDAVApp(config)
        return self.webdav_app
    
    def _create_user_middleware(self, app, config):
        """创建用户中间件"""
        def user_middleware(environ, start_response):
            # 从认证信息中获取用户
            auth_user = environ.get("wsgidav.auth.user")
            if auth_user and "user" in auth_user:
                # 设置当前用户到提供者
                for provider in config.get("provider_mapping", {}).values():
                    if hasattr(provider, "set_current_user"):
                        provider.set_current_user(auth_user["user"])
            return app(environ, start_response)
        return user_middleware
    
    def create_web_interface(self):
        """创建 Web 管理界面"""
        self.web_app = create_web_app()
        return self.web_app
    
    def run_webdav_server(self):
        """启动 WebDAV 服务器"""
        logger = logging.getLogger(__name__)
        
        # 创建服务器配置
        bind_addr = (Config.WEBDAV_HOST, Config.WEBDAV_PORT)
        server_args = {
            'bind_addr': bind_addr,
            'wsgi_app': self.webdav_app,
        }
        
        # 添加 SSL 配置（如果存在）
        if hasattr(Config, 'WEBDAV_SSL_CERT') and Config.WEBDAV_SSL_CERT and hasattr(Config, 'WEBDAV_SSL_KEY') and Config.WEBDAV_SSL_KEY:
            server_args['ssl_certificate'] = Config.WEBDAV_SSL_CERT
            server_args['ssl_private_key'] = Config.WEBDAV_SSL_KEY
        
        # 创建并启动服务器
        server = wsgi.Server(**server_args)
        
        try:
            logger.info(f"WebDAV 服务器启动在 {Config.WEBDAV_HOST}:{Config.WEBDAV_PORT}")
            server.start()
        except KeyboardInterrupt:
            logger.info("收到中断信号，正在关闭 WebDAV 服务器...")
            server.stop()
        except Exception as e:
            logger.error(f"WebDAV 服务器运行错误: {e}")
            raise
    
    def run(self):
        """启动服务器"""
        # 初始化日志
        setup_logging()
        logger = logging.getLogger(__name__)
        
        logger.info("正在启动 WebDAV 服务器...")
        logger.info(f"数据目录: {Config.WEBDAV_ROOT}")
        logger.info(f"WebDAV 服务地址: {Config.WEBDAV_HOST}:{Config.WEBDAV_PORT}")
        logger.info(f"Web 管理界面地址: {Config.WEB_HOST}:{Config.WEB_PORT}")
        
        # 启动 Web 界面
        web_thread = threading.Thread(
            target=lambda: self.web_app.run(
                host=Config.WEB_HOST,
                port=Config.WEB_PORT,
                debug=Config.DEBUG,
                use_reloader=False
            )
        )
        web_thread.daemon = True
        web_thread.start()
        
        # 启动 WebDAV 服务器
        self.run_webdav_server()
    
    def initialize_database(self):
        """初始化数据库"""
        try:
            # 测试数据库连接
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            # 创建初始管理员（如果不存在）
            cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
            if cursor.fetchone()[0] == 0:
                from models import User
                admin_user = User.create(
                    username="admin",
                    password="admin123",
                    display_name="系统管理员",
                    is_admin=True
                )
                if admin_user:
                    print("已创建默认管理员账户:")
                    print("用户名: admin")
                    print("密码: admin123")
            
            cursor.close()
            conn.close()
            
            print("数据库初始化完成！")
            
        except Exception as e:
            print(f"数据库初始化失败: {e}")
            sys.exit(1)

def main():
    """主函数"""
    server = WebDAVServer()
    
    # 创建应用
    server.create_web_interface()
    server.create_webdav_app()
    
    # 初始化数据库
    server.initialize_database()
    
    # 启动服务器
    try:
        server.run()
    except KeyboardInterrupt:
        print("\n服务器正在关闭...")
    except Exception as e:
        print(f"服务器启动失败: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()