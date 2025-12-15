#!/usr/bin/env python3
"""
管理员功能模块
提供用户管理、权限管理、系统监控等功能
"""

from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for, flash, current_app
from functools import wraps
import logging
import os
import shutil
from pathlib import Path
from datetime import datetime, timedelta
from models import Database, User
from auth import session_manager
from permissions import PermissionManager
from config import Config

# 创建蓝图
admin_bp = Blueprint('admin', __name__, 
                    template_folder='templates/admin',
                    static_folder='static',
                    url_prefix='/admin')

logger = logging.getLogger(__name__)

# 管理员装饰器
def admin_required(f):
    """管理员装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_token = session.get('session_token')
        if not session_token:
            return redirect(url_for('admin.login'))
        
        user = session_manager.validate_session(session_token)
        if not user:
            session.pop('session_token', None)
            return redirect(url_for('admin.login'))
        
        if not user.is_admin:
            flash('需要管理员权限', 'error')
            return redirect(url_for('admin.dashboard'))
        
        return f(user, *args, **kwargs)
    return decorated_function

@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    """管理员登录页面"""
    if request.method == 'GET':
        return render_template('login.html')
    
    username = request.form.get('username')
    password = request.form.get('password')
    remember = request.form.get('remember', False)
    
    user = User.authenticate(username, password)
    if not user:
        flash('用户名或密码错误', 'error')
        return render_template('login.html')
    
    if not user.is_admin:
        flash('该账户没有管理员权限', 'error')
        return render_template('login.html')
    
    # 创建会话
    session_token = session_manager.create_session(user.id)
    if session_token:
        session['session_token'] = session_token
        session['user_id'] = user.id
        session['username'] = user.username
        session['is_admin'] = user.is_admin
        
        if remember:
            session.permanent = True
        else:
            session.permanent = False
        
        return redirect(url_for('admin.dashboard'))
    
    flash('登录失败，请稍后重试', 'error')
    return render_template('login.html')

@admin_bp.route('/logout')
def logout():
    """管理员登出"""
    session_token = session.get('session_token')
    if session_token:
        session_manager.invalidate_session(session_token)
    session.clear()
    return redirect(url_for('admin.login'))

@admin_bp.route('/')
@admin_required
def dashboard(user):
    """管理员仪表板"""
    return render_template('dashboard.html', user=user)

@admin_bp.route('/users')
@admin_required
def user_management(user):
    """用户管理页面"""
    try:
        # 使用 User 类的方法获取用户列表
        users = User.get_all(active_only=False)
        return render_template('users.html', user=user, users=users)
        
    except Exception as e:
        logger.error(f"获取用户列表失败: {e}")
        flash('获取用户列表失败', 'error')
        # 返回空列表，避免模板渲染失败
        return render_template('users.html', user=user, users=[])

@admin_bp.route('/users/create', methods=['GET', 'POST'])
@admin_required
def create_user(user):
    """创建用户页面"""
    if request.method == 'GET':
        return render_template('create_user.html', user=user)
    
    # POST 请求：创建用户
    username = request.form.get('username')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    display_name = request.form.get('display_name')
    email = request.form.get('email')
    is_admin = request.form.get('is_admin') == 'on'
    
    # 验证输入
    if not username or not password:
        flash('用户名和密码不能为空', 'error')
        return render_template('create_user.html', user=user)
    
    if password != confirm_password:
        flash('两次输入的密码不一致', 'error')
        return render_template('create_user.html', user=user)
    
    if len(password) < 6:
        flash('密码长度不能少于6位', 'error')
        return render_template('create_user.html', user=user)
    
    # 创建用户
    new_user = User.create(
        username=username,
        password=password,
        display_name=display_name or username,
        email=email or f"{username}@example.com",
        is_admin=is_admin
    )
    
    if new_user:
        flash(f'用户 {username} 创建成功', 'success')
        return redirect(url_for('admin.user_management'))
    else:
        flash('用户创建失败，用户名可能已存在', 'error')
        return render_template('create_user.html', user=user)

@admin_bp.route('/users/<int:user_id>')
@admin_required
def user_detail(user, user_id):
    """用户详情页面"""
    try:
        target_user = User.get_by_id(user_id)
        if not target_user:
            flash('用户不存在', 'error')
            return redirect(url_for('admin.user_management'))
        
        # 获取用户的文件夹权限
        permissions = PermissionManager.get_user_permissions(user_id)
        
        # 获取所有文件夹列表
        folders = get_folder_list()
        
        # 获取所有权限类型
        all_permissions = get_all_permissions()
        
        return render_template('user_detail.html', 
                             user=user,
                             target_user=target_user,
                             permissions=permissions,
                             folders=folders,
                             all_permissions=all_permissions)
        
    except Exception as e:
        logger.error(f"获取用户详情失败: {e}")
        flash('获取用户详情失败', 'error')
        return redirect(url_for('admin.user_management'))

@admin_bp.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_user(user, user_id):
    """编辑用户"""
    try:
        target_user = User.get_by_id(user_id)
        if not target_user:
            flash('用户不存在', 'error')
            return redirect(url_for('admin.user_management'))
        
        if request.method == 'GET':
            return render_template('edit_user.html', 
                                 user=user, 
                                 target_user=target_user)
        
        # POST 请求：更新用户
        display_name = request.form.get('display_name')
        email = request.form.get('email')
        is_active = request.form.get('is_active') == 'on'
        is_admin = request.form.get('is_admin') == 'on'
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # 验证密码
        if new_password:
            if new_password != confirm_password:
                flash('两次输入的密码不一致', 'error')
                return render_template('edit_user.html', 
                                     user=user, 
                                     target_user=target_user)
            if len(new_password) < 6:
                flash('密码长度不能少于6位', 'error')
                return render_template('edit_user.html', 
                                     user=user, 
                                     target_user=target_user)
        
        # 更新用户信息
        conn = Database.get_connection()
        cursor = conn.cursor()
        
        if new_password:
            import bcrypt
            password_hash = bcrypt.hashpw(
                new_password.encode('utf-8'),
                bcrypt.gensalt()
            ).decode('utf-8')
            
            cursor.execute("""
                UPDATE users 
                SET display_name = %s, email = %s, is_active = %s, 
                    is_admin = %s, password_hash = %s, updated_at = NOW()
                WHERE id = %s
            """, (display_name, email, is_active, is_admin, password_hash, user_id))
        else:
            cursor.execute("""
                UPDATE users 
                SET display_name = %s, email = %s, is_active = %s, 
                    is_admin = %s, updated_at = NOW()
                WHERE id = %s
            """, (display_name, email, is_active, is_admin, user_id))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        flash('用户信息更新成功', 'success')
        return redirect(url_for('admin.user_management'))
        
    except Exception as e:
        logger.error(f"编辑用户失败: {e}")
        flash('编辑用户失败', 'error')
        return redirect(url_for('admin.user_management'))

@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user, user_id):
    """删除用户"""
    try:
        # 不能删除自己
        if user.id == user_id:
            return jsonify({'success': False, 'message': '不能删除自己'}), 400
        
        conn = Database.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        
        affected_rows = cursor.rowcount
        cursor.close()
        conn.close()
        
        if affected_rows > 0:
            return jsonify({'success': True, 'message': '用户删除成功'})
        else:
            return jsonify({'success': False, 'message': '用户不存在'}), 404
            
    except Exception as e:
        logger.error(f"删除用户失败: {e}")
        return jsonify({'success': False, 'message': '删除用户失败'}), 500

@admin_bp.route('/api/users/<int:user_id>/permissions', methods=['POST'])
@admin_required
def set_user_permissions(user, user_id):
    """设置用户权限 (API)"""
    try:
        data = request.get_json()
        folder_path = data.get('folder_path')
        permissions = data.get('permissions', [])
        
        if not folder_path:
            return jsonify({'success': False, 'message': '文件夹路径不能为空'}), 400
        
        if PermissionManager.set_user_permissions(user_id, folder_path, permissions):
            return jsonify({'success': True, 'message': '权限设置成功'})
        else:
            return jsonify({'success': False, 'message': '权限设置失败'}), 400
            
    except Exception as e:
        logger.error(f"设置用户权限失败: {e}")
        return jsonify({'success': False, 'message': '设置用户权限失败'}), 500

@admin_bp.route('/api/users/<int:user_id>/permissions/remove', methods=['POST'])
@admin_required
def remove_user_permissions(user, user_id):
    """删除用户权限"""
    try:
        data = request.get_json()
        folder_path = data.get('folder_path')
        
        if not folder_path:
            return jsonify({'success': False, 'message': '文件夹路径不能为空'}), 400
        
        conn = Database.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            DELETE FROM user_folder_permissions 
            WHERE user_id = %s AND folder_path = %s
        """, (user_id, folder_path))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({'success': True, 'message': '权限删除成功'})
        
    except Exception as e:
        logger.error(f"删除用户权限失败: {e}")
        return jsonify({'success': False, 'message': '删除用户权限失败'}), 500

@admin_bp.route('/folders')
@admin_required
def folder_management(user):
    """文件夹管理页面"""
    try:
        folders = get_folder_list()
        return render_template('folders.html', user=user, folders=folders)
    except Exception as e:
        logger.error(f"获取文件夹列表失败: {e}")
        flash('获取文件夹列表失败', 'error')
        return render_template('folders.html', user=user, folders=[])

@admin_bp.route('/api/folders/create', methods=['POST'])
@admin_required
def create_folder(user):
    """创建文件夹"""
    try:
        data = request.get_json()
        folder_path = data.get('folder_path')
        
        if not folder_path:
            return jsonify({'success': False, 'message': '文件夹路径不能为空'}), 400
        
        # 创建文件夹
        full_path = Path(Config.WEBDAV_ROOT) / folder_path.lstrip('/')
        full_path.mkdir(parents=True, exist_ok=True)
        
        return jsonify({'success': True, 'message': '文件夹创建成功'})
        
    except Exception as e:
        logger.error(f"创建文件夹失败: {e}")
        return jsonify({'success': False, 'message': f'创建文件夹失败: {str(e)}'}), 500

@admin_bp.route('/api/folders/delete', methods=['POST'])
@admin_required
def delete_folder(user):
    """删除文件夹"""
    try:
        data = request.get_json()
        folder_path = data.get('folder_path')
        
        if not folder_path:
            return jsonify({'success': False, 'message': '文件夹路径不能为空'}), 400
        
        if folder_path == '/':
            return jsonify({'success': False, 'message': '不能删除根目录'}), 400
        
        # 删除文件夹
        full_path = Path(Config.WEBDAV_ROOT) / folder_path.lstrip('/')
        
        if not full_path.exists():
            return jsonify({'success': False, 'message': '文件夹不存在'}), 404
        
        if not full_path.is_dir():
            return jsonify({'success': False, 'message': '指定的路径不是文件夹'}), 400
        
        # 使用 shutil.rmtree 递归删除文件夹及其内容
        shutil.rmtree(full_path)
        
        return jsonify({'success': True, 'message': '文件夹删除成功'})
        
    except Exception as e:
        logger.error(f"删除文件夹失败: {e}")
        return jsonify({'success': False, 'message': f'删除文件夹失败: {str(e)}'}), 500

@admin_bp.route('/system')
@admin_required
def system_status(user):
    """系统状态页面"""
    try:
        # 获取系统信息
        system_info = get_system_info()
        
        # 获取数据库统计
        db_stats = get_database_stats()
        
        # 获取存储使用情况
        storage_info = get_storage_info()
        
        return render_template('system_status.html', 
                             user=user,
                             system_info=system_info,
                             db_stats=db_stats,
                             storage_info=storage_info)
        
    except Exception as e:
        logger.error(f"获取系统状态失败: {e}")
        flash('获取系统状态失败', 'error')
        return render_template('system_status.html', 
                             user=user,
                             system_info={},
                             db_stats={},
                             storage_info={})

@admin_bp.route('/logs')
@admin_required
def view_logs(user):
    """查看日志页面"""
    try:
        # 获取访问日志
        conn = Database.get_connection()
        cursor = conn.cursor(dictionary=True)
        
        # 修正SQL查询，使用正确的表名 access_logs
        cursor.execute("""
            SELECT al.*, u.username, u.display_name
            FROM access_logs al
            LEFT JOIN users u ON al.user_id = u.id
            ORDER BY al.timestamp DESC
            LIMIT 100
        """)
        logs = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return render_template('logs.html', user=user, logs=logs)
        
    except Exception as e:
        logger.error(f"获取日志失败: {e}")
        flash('获取日志失败', 'error')
        return render_template('logs.html', user=user, logs=[])

@admin_bp.route('/api/system/stats')
@admin_required
def get_system_stats(user):
    """获取系统统计信息 (API)"""
    try:
        stats = {
            'total_users': get_user_count(),
            'active_users': get_active_user_count(),
            'total_folders': get_folder_count(),
            'total_files': get_file_count(),
            'storage_usage': get_storage_usage(),
            'system_load': get_system_load()
        }
        
        return jsonify({'success': True, 'stats': stats})
        
    except Exception as e:
        logger.error(f"获取系统统计失败: {e}")
        return jsonify({'success': False, 'message': '获取系统统计失败'}), 500

# 辅助函数
def get_all_permissions():
    """获取所有权限类型"""
    permissions = []
    try:
        conn = Database.get_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT id, name, description FROM permissions ORDER BY id")
        permissions = cursor.fetchall()
        
        cursor.close()
        conn.close()
    except Exception as e:
        logger.error(f"获取权限列表失败: {e}")
    
    return permissions

def get_folder_list():
    """获取文件夹列表"""
    folders = []
    try:
        root_path = Path(Config.WEBDAV_ROOT)
        if not root_path.exists():
            root_path.mkdir(parents=True, exist_ok=True)
            logger.info(f"创建WebDAV根目录: {root_path}")
        
        # 首先添加根目录
        try:
            size = sum(f.stat().st_size for f in root_path.rglob('*') if f.is_file())
        except:
            size = 0
        
        folders.append({
            'path': '/',
            'name': '根目录',
            'size': size,
            'file_count': sum(1 for _ in root_path.rglob('*') if _.is_file()),
            'folder_count': sum(1 for _ in root_path.rglob('*') if _.is_dir()) - 1,
            'created': datetime.fromtimestamp(root_path.stat().st_ctime) if root_path.exists() else None,
            'modified': datetime.fromtimestamp(root_path.stat().st_mtime) if root_path.exists() else None
        })
        
        # 获取根目录下的所有文件夹
        for item in root_path.iterdir():
            if item.is_dir():
                rel_path = "/" + item.name
                try:
                    size = sum(f.stat().st_size for f in item.rglob('*') if f.is_file())
                except:
                    size = 0
                
                folders.append({
                    'path': rel_path,
                    'name': item.name,
                    'size': size,
                    'file_count': sum(1 for _ in item.rglob('*') if _.is_file()),
                    'folder_count': sum(1 for _ in item.rglob('*') if _.is_dir()) - 1,
                    'created': datetime.fromtimestamp(item.stat().st_ctime) if item.exists() else None,
                    'modified': datetime.fromtimestamp(item.stat().st_mtime) if item.exists() else None
                })
    except Exception as e:
        logger.error(f"获取文件夹列表失败: {e}")
    
    return folders

def get_system_info():
    """获取系统信息"""
    import platform
    try:
        import psutil
    except ImportError:
        # 如果无法导入 psutil，返回基本系统信息
        logger.warning("psutil 模块未安装，无法获取完整系统信息")
        return {
            'platform': platform.platform(),
            'python_version': platform.python_version(),
            'hostname': platform.node(),
            'processor': platform.processor(),
            'system': platform.system(),
            'machine': platform.machine(),
            'cpu_count': '未知 (需要安装psutil)',
            'cpu_percent': 0,
            'memory_total': 0,
            'memory_available': 0,
            'memory_percent': 0,
            'disk_usage': {'total': 0, 'used': 0, 'free': 0, 'percent': 0},
            'boot_time': None,
            'process_count': 0,
        }
    
    # 如果成功导入 psutil，获取完整系统信息
    system_info = {
        'platform': platform.platform(),
        'python_version': platform.python_version(),
        'hostname': platform.node(),
        'processor': platform.processor(),
        'system': platform.system(),
        'machine': platform.machine(),
        'cpu_count': psutil.cpu_count(),
        'cpu_percent': psutil.cpu_percent(),
        'memory_total': psutil.virtual_memory().total,
        'memory_available': psutil.virtual_memory().available,
        'memory_percent': psutil.virtual_memory().percent,
        'boot_time': datetime.fromtimestamp(psutil.boot_time()),
        'process_count': len(psutil.pids()),
    }
    
    # 获取磁盘使用情况
    try:
        disk_usage = psutil.disk_usage(str(Path(Config.WEBDAV_ROOT)))
        system_info['disk_usage'] = disk_usage._asdict()
    except Exception as e:
        logger.error(f"获取磁盘使用情况失败: {e}")
        system_info['disk_usage'] = {'total': 0, 'used': 0, 'free': 0, 'percent': 0}
    
    return system_info

def get_database_stats():
    """获取数据库统计信息"""
    stats = {}
    try:
        conn = Database.get_connection()
        cursor = conn.cursor(dictionary=True)
        
        # 用户统计
        cursor.execute("""
            SELECT 
                COUNT(*) as total_users,
                SUM(CASE WHEN is_active = TRUE THEN 1 ELSE 0 END) as active_users,
                SUM(CASE WHEN is_admin = TRUE THEN 1 ELSE 0 END) as admin_users
            FROM users
        """)
        stats.update(cursor.fetchone())
        
        # 权限统计
        cursor.execute("SELECT COUNT(*) as total_permissions FROM user_folder_permissions")
        stats.update(cursor.fetchone())
        
        # 会话统计
        cursor.execute("SELECT COUNT(*) as active_sessions FROM user_sessions WHERE expires_at > NOW()")
        stats.update(cursor.fetchone())
        
        # 日志统计 - 修正表名为 access_logs
        cursor.execute("SELECT COUNT(*) as total_logs FROM access_logs")
        stats.update(cursor.fetchone())
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        logger.error(f"获取数据库统计失败: {e}")
    
    return stats

def get_storage_info():
    """获取存储信息"""
    import psutil
    from pathlib import Path
    
    storage_info = {
        'total': 0,
        'used': 0,
        'free': 0,
        'percent': 0
    }
    
    try:
        root_path = Path(Config.WEBDAV_ROOT)
        if root_path.exists():
            # 获取文件夹大小
            total_size = 0
            for file_path in root_path.rglob('*'):
                if file_path.is_file():
                    try:
                        total_size += file_path.stat().st_size
                    except:
                        pass
            
            # 获取磁盘使用情况
            disk_usage = psutil.disk_usage(str(root_path))
            
            storage_info = {
                'total': disk_usage.total,
                'used': total_size,
                'free': disk_usage.free,
                'percent': (total_size / disk_usage.total * 100) if disk_usage.total > 0 else 0
            }
    except Exception as e:
        logger.error(f"获取存储信息失败: {e}")
    
    return storage_info

def get_user_count():
    """获取用户总数"""
    try:
        conn = Database.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        cursor.close()
        conn.close()
        return count
    except:
        return 0

def get_active_user_count():
    """获取活跃用户数"""
    try:
        conn = Database.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE is_active = TRUE")
        count = cursor.fetchone()[0]
        cursor.close()
        conn.close()
        return count
    except:
        return 0

def get_folder_count():
    """获取文件夹数量"""
    try:
        root_path = Path(Config.WEBDAV_ROOT)
        count = sum(1 for _ in root_path.rglob('') if _.is_dir())
        return count
    except:
        return 0

def get_file_count():
    """获取文件数量"""
    try:
        root_path = Path(Config.WEBDAV_ROOT)
        count = sum(1 for _ in root_path.rglob('*') if _.is_file())
        return count
    except:
        return 0

def get_storage_usage():
    """获取存储使用率"""
    try:
        import psutil
        disk_usage = psutil.disk_usage(str(Path(Config.WEBDAV_ROOT)))
        return disk_usage.percent
    except:
        return 0

def get_system_load():
    """获取系统负载"""
    try:
        import psutil
        return psutil.getloadavg()[0]
    except:
        return 0