import hashlib
import secrets
import base64
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Callable
import logging
from models import Database, User

logger = logging.getLogger(__name__)

class Authenticator:
    """WebDAV 认证器"""
    
    def __init__(self, realm: str = "WebDAV Server"):
        self.realm = realm
    
    def authenticate(self, username: str, password: str) -> Optional[User]:
        """基础认证"""
        try:
            return User.authenticate(username, password)
        except Exception as e:
            logger.error(f"Authentication error for user {username}: {e}")
            return None
    
    def get_domain_controller(self) -> Callable:
        """返回域控制器用于 wsgidav"""
        def domain_controller(username: str, password: str, realm: str) -> Optional[Dict[str, Any]]:
            user = self.authenticate(username, password)
            if user:
                return {"username": user.username, "user": user}
            return None
        return domain_controller
    
    def require_auth(self, request_handler: Any) -> Callable:
        """HTTP 基础认证装饰器"""
        def wrapper(*args, **kwargs):
            # 获取请求处理器实例
            handler = args[0] if args else None
            
            auth_header = handler.headers.get('Authorization') if handler else None
            
            if not auth_header or not auth_header.startswith('Basic '):
                if handler:
                    handler.send_auth_required()
                return None
            
            try:
                auth_decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
                username, password = auth_decoded.split(':', 1)
                
                user = self.authenticate(username, password)
                if not user:
                    if handler:
                        handler.send_auth_required()
                    return None
                
                # 将用户对象传递给被装饰的函数
                if handler:
                    handler.current_user = user
                return user
                
            except Exception as e:
                logger.error(f"Auth header parsing error: {e}")
                if handler:
                    handler.send_auth_required()
                return None
        
        return wrapper

    def digest_authenticate(self, username: str, realm: str, nonce: str, 
                           uri: str, response: str) -> Optional[User]:
        """摘要认证（待实现）"""
        # TODO: 实现摘要认证逻辑
        logger.warning("Digest authentication not yet implemented")
        return None

class SessionManager:
    """会话管理器（用于Web界面）"""
    
    def __init__(self, session_timeout_hours: int = 24):
        self.session_timeout = timedelta(hours=session_timeout_hours)
        self.cleanup_interval = timedelta(hours=1)
        self.last_cleanup = datetime.now()
    
    def _cleanup_expired_sessions(self) -> None:
        """清理过期会话"""
        try:
            if datetime.now() - self.last_cleanup < self.cleanup_interval:
                return
                
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM user_sessions WHERE expires_at <= NOW()")
            
            conn.commit()
            cursor.close()
            conn.close()
            
            self.last_cleanup = datetime.now()
            logger.info("Expired sessions cleanup completed")
            
        except Exception as e:
            logger.error(f"Session cleanup error: {e}")
    
    def create_session(self, user_id: int) -> Optional[str]:
        """创建新会话"""
        try:
            self._cleanup_expired_sessions()
            
            session_token = secrets.token_urlsafe(32)
            expires_at = datetime.now() + self.session_timeout
            
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            # 先使该用户的其他会话失效
            cursor.execute(
                "DELETE FROM user_sessions WHERE user_id = %s",
                (user_id,)
            )
            
            # 创建新会话
            cursor.execute("""
                INSERT INTO user_sessions (user_id, session_token, expires_at, created_at)
                VALUES (%s, %s, %s, NOW())
            """, (user_id, session_token, expires_at))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            logger.info(f"Session created for user {user_id}")
            return session_token
            
        except Exception as e:
            logger.error(f"Create session error: {e}")
            return None
    
    def validate_session(self, session_token: str) -> Optional[User]:
        """验证会话令牌"""
        if not session_token:
            return None
            
        try:
            self._cleanup_expired_sessions()
            
            conn = Database.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("""
                SELECT u.*, s.expires_at
                FROM user_sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.session_token = %s 
                AND s.expires_at > NOW()
                AND u.is_active = TRUE
            """, (session_token,))
            
            session_data = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if session_data:
                # 更新会话过期时间（滑动过期）
                self._refresh_session(session_token)
                return User(session_data)
                
        except Exception as e:
            logger.error(f"Validate session error: {e}")
        return None
    
    def _refresh_session(self, session_token: str) -> bool:
        """刷新会话过期时间"""
        try:
            new_expires = datetime.now() + self.session_timeout
            
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                "UPDATE user_sessions SET expires_at = %s WHERE session_token = %s",
                (new_expires, session_token)
            )
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return True
            
        except Exception as e:
            logger.error(f"Refresh session error: {e}")
            return False
    
    def invalidate_session(self, session_token: str) -> bool:
        """使会话失效"""
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                "DELETE FROM user_sessions WHERE session_token = %s",
                (session_token,)
            )
            
            conn.commit()
            cursor.close()
            conn.close()
            
            logger.info(f"Session invalidated: {session_token}")
            return True
            
        except Exception as e:
            logger.error(f"Invalidate session error: {e}")
            return False
    
    def invalidate_user_sessions(self, user_id: int) -> bool:
        """使用户的所有会话失效"""
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                "DELETE FROM user_sessions WHERE user_id = %s",
                (user_id,)
            )
            
            conn.commit()
            cursor.close()
            conn.close()
            
            logger.info(f"All sessions invalidated for user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Invalidate user sessions error: {e}")
            return False

# 全局认证器和会话管理器实例
authenticator = Authenticator()
session_manager = SessionManager()