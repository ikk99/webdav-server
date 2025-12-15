from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_cors import CORS
from functools import wraps
import logging
from models import Database, User
from auth import SessionManager
from permissions import PermissionManager
from .admin import admin_bp

def create_web_app():
    """创建 Flask 应用"""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
    CORS(app)
    
    # 注册管理员蓝图
    app.register_blueprint(admin_bp)
    
    session_manager = SessionManager()
    
    def login_required(f):
        """登录装饰器"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            session_token = session.get('session_token')
            if not session_token:
                return redirect(url_for('login'))
            
            user = session_manager.validate_session(session_token)
            if not user:
                session.pop('session_token', None)
                return redirect(url_for('login'))
            
            return f(user, *args, **kwargs)
        return decorated_function
    
    def admin_required(f):
        """管理员装饰器"""
        @wraps(f)
        @login_required
        def decorated_function(user, *args, **kwargs):
            if not user.is_admin:
                return jsonify({'error': '需要管理员权限'}), 403
            return f(user, *args, **kwargs)
        return decorated_function
    
    @app.route('/')
    def index():
        """首页"""
        return redirect(url_for('login'))
    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """登录页面"""
        if request.method == 'GET':
            return render_template('login.html')
        
        # POST 请求：处理登录
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.authenticate(username, password)
        if not user:
            return render_template('login.html', error='用户名或密码错误')
        
        # 创建会话
        session_token = session_manager.create_session(user.id)
        if session_token:
            session['session_token'] = session_token
            session['user_id'] = user.id
            session['username'] = user.username
            
            if user.is_admin:
                return redirect(url_for('admin.dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        
        return render_template('login.html', error='登录失败')
    
    @app.route('/logout')
    def logout():
        """登出"""
        session_token = session.get('session_token')
        if session_token:
            session_manager.invalidate_session(session_token)
        session.clear()
        return redirect(url_for('login'))
    
    @app.route('/dashboard')
    @login_required
    def user_dashboard(user):
        """用户仪表板"""
        accessible_folders = user.get_accessible_folders()
        return render_template('dashboard.html', 
                             user=user,
                             folders=accessible_folders)
    
    # 注意：这里删除了原来的 admin_dashboard 路由，因为已经在 admin.py 中定义了
    
    # API 路由
    @app.route('/api/users', methods=['GET'])
    @admin_required
    def api_get_users(user):
        """获取用户列表"""
        try:
            conn = Database.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("SELECT id, username, display_name, email, is_active, is_admin FROM users")
            users = cursor.fetchall()
            
            cursor.close()
            conn.close()
            
            return jsonify({'users': users})
            
        except Exception as e:
            logging.error(f"Get users error: {e}")
            return jsonify({'error': '获取用户列表失败'}), 500
    
    @app.route('/api/users', methods=['POST'])
    @admin_required
    def api_create_user(user):
        """创建用户"""
        try:
            data = request.json
            new_user = User.create(
                username=data['username'],
                password=data['password'],
                display_name=data.get('display_name', ''),
                email=data.get('email', ''),
                is_admin=data.get('is_admin', False)
            )
            
            if new_user:
                return jsonify({'message': '用户创建成功', 'user_id': new_user.id})
            else:
                return jsonify({'error': '用户创建失败'}), 400
                
        except Exception as e:
            logging.error(f"Create user error: {e}")
            return jsonify({'error': '创建用户失败'}), 500
    
    @app.route('/api/users/<int:user_id>/permissions', methods=['GET'])
    @admin_required
    def api_get_user_permissions(user, user_id):
        """获取用户权限"""
        try:
            permissions = PermissionManager.get_user_permissions(user_id)
            return jsonify({'permissions': permissions})
            
        except Exception as e:
            logging.error(f"Get user permissions error: {e}")
            return jsonify({'error': '获取用户权限失败'}), 500
    
    @app.route('/api/users/<int:user_id>/permissions', methods=['POST'])
    @admin_required
    def api_set_user_permissions(user, user_id):
        """设置用户权限"""
        try:
            data = request.json
            folder_path = data['folder_path']
            permissions = data['permissions']
            
            if PermissionManager.set_user_permissions(user_id, folder_path, permissions):
                return jsonify({'message': '权限设置成功'})
            else:
                return jsonify({'error': '权限设置失败'}), 400
                
        except Exception as e:
            logging.error(f"Set user permissions error: {e}")
            return jsonify({'error': '设置用户权限失败'}), 500
    
    @app.route('/api/folders')
    @login_required
    def api_get_folders(user):
        """获取文件夹列表"""
        try:
            import os
            from pathlib import Path
            from config import Config
            
            root_path = Path(Config.WEBDAV_ROOT)
            folders = []
            
            # 获取根目录下的文件夹
            for item in root_path.iterdir():
                if item.is_dir():
                    rel_path = "/" + item.name
                    folders.append({
                        'path': rel_path,
                        'name': item.name
                    })
            
            return jsonify({'folders': folders})
            
        except Exception as e:
            logging.error(f"Get folders error: {e}")
            return jsonify({'error': '获取文件夹列表失败'}), 500
    
    # 健康检查端点
    @app.route('/health')
    def health_check():
        """健康检查"""
        try:
            # 检查数据库连接
            conn = Database.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.close()
            conn.close()
            
            # 检查数据目录
            from config import Config
            if not Config.WEBDAV_ROOT.exists():
                return jsonify({'status': 'error', 'message': '数据目录不存在'}), 500
                
            return jsonify({'status': 'healthy'})
            
        except Exception as e:
            logging.error(f"Health check failed: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500
    
    # 错误处理
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': '页面未找到'}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        logging.error(f"服务器内部错误: {error}")
        return jsonify({'error': '服务器内部错误'}), 500
    
    return app