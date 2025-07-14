import os
import re
import secrets
import sqlite3
import string
import hmac
import hashlib
import urllib3
from datetime import datetime, timedelta
from functools import wraps
import requests
from flask import (Flask, flash, redirect, render_template, request, session,
                   url_for, Response)
from flask_paginate import Pagination, get_page_args
from authlib.integrations.flask_client import OAuth
import csv
import io

# 禁用SSL证书验证警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- App Initialization ---
app = Flask(__name__)
SECRET_KEY_FROM_ENV = os.getenv('FLASK_SECRET_KEY')
if not SECRET_KEY_FROM_ENV:
    raise ValueError("错误: 必须设置 FLASK_SECRET_KEY 环境变量! 使用 'python -c \"import secrets; print(secrets.token_hex(32))\"' 生成一个。")
app.config['SECRET_KEY'] = SECRET_KEY_FROM_ENV
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# 初始化OAuth客户端
oauth = OAuth(app)

DATABASE = '/app/data/tokens.db'
PER_PAGE = 10

# --- Environment Variable Loading ---
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')
EMBY_SERVER_URL = os.getenv('EMBY_SERVER_URL', '').rstrip('/')
EMBY_API_KEY = os.getenv('EMBY_API_KEY')
COPY_FROM_USER_ID = os.getenv('COPY_FROM_USER_ID')
PUBLIC_ACCESS_URL = os.getenv('PUBLIC_ACCESS_URL')

# --- Linux.do OAuth2 Configuration ---
LINUXDO_OAUTH_ENABLED = os.getenv('LINUXDO_OAUTH_ENABLED', 'true').lower() == 'true'
LINUXDO_CLIENT_ID = os.getenv('LINUXDO_CLIENT_ID')
LINUXDO_CLIENT_SECRET = os.getenv('LINUXDO_CLIENT_SECRET')
LINUXDO_REDIRECT_URI = os.getenv('LINUXDO_REDIRECT_URI', f'{PUBLIC_ACCESS_URL}/oauth2/callback')

# 代理配置
USE_PROXY = os.getenv('USE_PROXY', 'false').lower() == 'true'
PROXY_HOST = os.getenv('PROXY_HOST')
PROXY_PORT = os.getenv('PROXY_PORT')
DISABLE_SSL_VERIFY = os.getenv('DISABLE_SSL_VERIFY', 'false').lower() == 'true'

app.config['LINUXDO_OAUTH_ENABLED'] = LINUXDO_OAUTH_ENABLED

# 配置OAuth客户端
if LINUXDO_OAUTH_ENABLED:
    # 配置代理（如果需要）
    session_kwargs = {}
    if USE_PROXY:
        proxy_url = f"http://{PROXY_HOST}:{PROXY_PORT}"
        session_kwargs['proxies'] = {
            'http': proxy_url,
            'https': proxy_url
        }
    
    if DISABLE_SSL_VERIFY:
        session_kwargs['verify'] = False
    
    # 注册Linux.do OAuth客户端
    oauth.register(
        name='linuxdo',
        client_id=LINUXDO_CLIENT_ID,
        client_secret=LINUXDO_CLIENT_SECRET,
        access_token_url='https://connect.linux.do/oauth2/token',
        access_token_params=None,
        authorize_url='https://connect.linux.do/oauth2/authorize',
        authorize_params=None,
        api_base_url='https://connect.linux.do/',
        client_kwargs={
            'scope': 'read',
            'token_endpoint_auth_method': 'client_secret_post'
        },
        **session_kwargs
    )

# 根据trust_level设置不同的注册限制
TRUST_LEVEL_LIMITS = {
    0: 0,   # 0级用户只能注册1个账号
    1: 2,   # 1级用户可以注册2个账号
    2: 3,   # 2级用户可以注册3个账号
    3: 5,   # 3级用户可以注册5个账号
    4: 10   # 4级用户可以注册10个账号
}

if not all([ADMIN_PASSWORD, EMBY_SERVER_URL, EMBY_API_KEY, COPY_FROM_USER_ID]):
    raise ValueError("请设置所有必需的环境变量: ADMIN_PASSWORD, EMBY_SERVER_URL, EMBY_API_KEY, COPY_FROM_USER_ID")


# --- HMAC Signature Helpers ---
def _generate_signed_token(payload):
    signature = hmac.new(app.config['SECRET_KEY'].encode('utf-8'), payload.encode('utf-8'), hashlib.sha256).hexdigest()
    return f"{payload}.{signature}"

def _verify_signed_token(signed_token):
    if not signed_token or '.' not in signed_token: return None
    payload, signature = signed_token.rsplit('.', 1)
    expected_signature = hmac.new(app.config['SECRET_KEY'].encode('utf-8'), payload.encode('utf-8'), hashlib.sha256).hexdigest()
    if hmac.compare_digest(expected_signature, signature): return payload
    return None

# --- Database Setup ---
def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    os.makedirs(os.path.dirname(DATABASE), exist_ok=True)
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        # 创建tokens表
        cursor.execute(
            '''
            CREATE TABLE IF NOT EXISTS tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT NOT NULL UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_used BOOLEAN DEFAULT 0,
                registered_username TEXT
            )
            '''
        )
        
        # 创建linuxdo_users表存储用户信息
        cursor.execute(
            '''
            CREATE TABLE IF NOT EXISTS linuxdo_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                linuxdo_id INTEGER UNIQUE NOT NULL,
                username TEXT NOT NULL,
                name TEXT,
                trust_level INTEGER DEFAULT 0,
                email TEXT,
                avatar_url TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            '''
        )
        
        # 创建user_registrations表记录用户注册历史
        cursor.execute(
            '''
            CREATE TABLE IF NOT EXISTS user_registrations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                linuxdo_user_id INTEGER,
                emby_username TEXT NOT NULL,
                emby_user_id TEXT,
                emby_password TEXT,
                registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (linuxdo_user_id) REFERENCES linuxdo_users (id)
            )
            '''
        )
        
        db.commit()


# --- Decorators ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session: return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def linuxdo_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'linuxdo_user_id' not in session: 
            return redirect(url_for('linuxdo_login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# --- OAuth2 Helper Functions ---
def get_linuxdo_user_info():
    """获取Linux.do用户信息"""
    try:
        resp = oauth.linuxdo.get('/api/user')
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        app.logger.error(f"获取Linux.do用户信息失败: {e}")
        return None

def get_or_create_linuxdo_user(user_info):
    """获取或创建Linux.do用户记录"""
    db = get_db()
    try:
        # 查找现有用户
        user = db.execute(
            'SELECT * FROM linuxdo_users WHERE linuxdo_id = ?',
            (user_info['id'],)
        ).fetchone()
        
        if user:
            # 更新用户信息
            db.execute(
                '''UPDATE linuxdo_users SET 
                   username = ?, name = ?, trust_level = ?, email = ?, 
                   avatar_url = ?, last_login = CURRENT_TIMESTAMP 
                   WHERE linuxdo_id = ?''',
                (user_info['username'], user_info['name'], user_info['trust_level'],
                 user_info.get('email'), user_info.get('avatar_url'), user_info['id'])
            )
            db.commit()
            return user['id']
        else:
            # 创建新用户
            cursor = db.execute(
                '''INSERT INTO linuxdo_users 
                   (linuxdo_id, username, name, trust_level, email, avatar_url) 
                   VALUES (?, ?, ?, ?, ?, ?)''',
                (user_info['id'], user_info['username'], user_info['name'],
                 user_info['trust_level'], user_info.get('email'), user_info.get('avatar_url'))
            )
            db.commit()
            return cursor.lastrowid
    finally:
        db.close()

def get_user_registration_count(user_id):
    """获取用户已注册的账号数量"""
    db = get_db()
    try:
        count = db.execute(
            'SELECT COUNT(*) FROM user_registrations WHERE linuxdo_user_id = ?',
            (user_id,)
        ).fetchone()[0]
        return count
    finally:
        db.close()

def can_user_register(user_id, trust_level):
    """检查用户是否可以注册新账号"""
    current_count = get_user_registration_count(user_id)
    max_allowed = TRUST_LEVEL_LIMITS.get(trust_level, 1)
    return current_count < max_allowed

# --- Emby API Helper ---
def create_emby_user(username, password):
    headers = {'X-Emby-Token': EMBY_API_KEY, 'Content-Type': 'application/json'}
    create_url = f"{EMBY_SERVER_URL}/Users/New"
    create_payload = {"Name": username, "CopyFromUserId": COPY_FROM_USER_ID, "UserCopyOptions": ["UserConfiguration", "UserPolicy"]}
    try:
        response = requests.post(create_url, json=create_payload, headers=headers, timeout=15)
        response.raise_for_status()
        user_data = response.json()
        user_id = user_data.get('Id')
        if not user_id: return None, "创建用户成功，但在响应中未找到User ID。"
    except requests.RequestException as e:
        app.logger.error(f"步骤 1/2 - 创建用户 '{username}' 失败: {e}")
        try:
            if e.response is not None and "already exists" in e.response.text.lower(): return None, "用户名已存在"
        except (AttributeError, ValueError): pass
        return None, f"创建用户失败: {e}"
    try:
        set_password_url = f"{EMBY_SERVER_URL}/Users/{user_id}/Password"
        password_payload = {"Id": user_id, "NewPw": password}
        password_response = requests.post(set_password_url, json=password_payload, headers=headers, timeout=10)
        password_response.raise_for_status()
    except requests.RequestException as e:
        app.logger.error(f"步骤 2/2 - 为用户 '{username}' (ID: {user_id}) 设置密码失败: {e}")
        return None, "用户已创建但设置密码失败，请联系管理员。"
    return user_id, None

# --- Routes ---
@app.route('/')
def index(): 
    if LINUXDO_OAUTH_ENABLED:
        return redirect(url_for('linuxdo_login'))
    return redirect(url_for('login'))

# --- Linux.do OAuth2 Routes ---
@app.route('/linuxdo/login')
def linuxdo_login():
    if not LINUXDO_OAUTH_ENABLED:
        flash('Linux.do OAuth2登录功能未启用', 'warning')
        return redirect(url_for('login'))
    
    redirect_uri = url_for('oauth2_callback', _external=True)
    return oauth.linuxdo.authorize_redirect(redirect_uri)

@app.route('/oauth2/callback')
def oauth2_callback():
    if not LINUXDO_OAUTH_ENABLED:
        flash('Linux.do OAuth2登录功能未启用', 'warning')
        return redirect(url_for('login'))
    
    try:
        # 获取访问令牌
        token = oauth.linuxdo.authorize_access_token()
        
        # 获取用户信息
        user_info = get_linuxdo_user_info()
        if not user_info:
            flash('获取用户信息失败', 'error')
            return redirect(url_for('linuxdo_login'))
        
        # 保存或更新用户信息
        user_id = get_or_create_linuxdo_user(user_info)
        
        # 设置session
        session.permanent = True
        session['linuxdo_user_id'] = user_id
        session['linuxdo_username'] = user_info['username']
        session['linuxdo_name'] = user_info['name']
        session['linuxdo_trust_level'] = user_info['trust_level']
        
        flash(f'欢迎回来，{user_info["name"]}！', 'success')
        
        # 重定向到注册页面或用户仪表板
        next_url = request.args.get('next', url_for('linuxdo_dashboard'))
        return redirect(next_url)
        
    except Exception as e:
        app.logger.error(f"OAuth2回调处理失败: {e}")
        flash('OAuth2登录失败，请重试', 'error')
        return redirect(url_for('linuxdo_login'))

@app.route('/linuxdo/logout')
def linuxdo_logout():
    session.pop('linuxdo_user_id', None)
    session.pop('linuxdo_username', None)
    session.pop('linuxdo_name', None)
    session.pop('linuxdo_trust_level', None)
    flash('您已退出登录', 'info')
    return redirect(url_for('linuxdo_login'))

@app.route('/linuxdo/dashboard')
@linuxdo_login_required
def linuxdo_dashboard():
    db = get_db()
    try:
        # 获取用户信息
        user = db.execute(
            'SELECT * FROM linuxdo_users WHERE id = ?',
            (session['linuxdo_user_id'],)
        ).fetchone()
        
        # 获取用户注册历史
        registrations = db.execute(
            '''SELECT emby_username, emby_user_id, registered_at, emby_password 
               FROM user_registrations 
               WHERE linuxdo_user_id = ? 
               ORDER BY registered_at DESC''',
            (session['linuxdo_user_id'],)
        ).fetchall()
        
        # 检查是否可以注册新账号
        can_register = can_user_register(session['linuxdo_user_id'], user['trust_level'])
        current_count = get_user_registration_count(session['linuxdo_user_id'])
        max_allowed = TRUST_LEVEL_LIMITS.get(user['trust_level'], 1)
        
    finally:
        db.close()
    
    return render_template('linuxdo_dashboard.html', 
                         user=user, 
                         registrations=registrations,
                         can_register=can_register,
                         current_count=current_count,
                         max_allowed=max_allowed)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('password') == ADMIN_PASSWORD:
            session.permanent = True  
            session['logged_in'] = True
            flash('登录成功!', 'success')
            return redirect(url_for('admin'))
        else:
            return render_template('login.html', error='密码错误')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('您已退出登录。', 'info')
    return redirect(url_for('login'))

@app.route('/admin')
@login_required
def admin():
    db = get_db()
    
    search_query = request.args.get('q', '').strip()
    
    # 基于是否有搜索关键词构建SQL
    if search_query:
        like_pattern = f"%{search_query}%"
        total = db.execute(
            'SELECT COUNT(*) FROM tokens WHERE token LIKE ? OR registered_username LIKE ?',
            (like_pattern, like_pattern)
        ).fetchone()[0]
    else:
        total = db.execute('SELECT COUNT(*) FROM tokens').fetchone()[0]

    page, per_page, offset = get_page_args(page_parameter='page', 
                                           per_page_parameter='per_page', 
                                           per_page=PER_PAGE)

    if search_query:
        tokens_from_db = db.execute(
            'SELECT id, token, is_used, registered_username FROM tokens WHERE token LIKE ? OR registered_username LIKE ? ORDER BY created_at DESC LIMIT ? OFFSET ?',
            (like_pattern, like_pattern, per_page, offset)
        ).fetchall()
    else:
        tokens_from_db = db.execute(
            'SELECT id, token, is_used, registered_username FROM tokens ORDER BY created_at DESC LIMIT ? OFFSET ?',
            (per_page, offset)
        ).fetchall()
    
    # 获取Linux.do用户数据
    linuxdo_users = []
    if LINUXDO_OAUTH_ENABLED:
        linuxdo_users_data = db.execute(
            '''SELECT u.*, 
                      COUNT(r.id) as registration_count,
                      MAX(r.registered_at) as last_registration
               FROM linuxdo_users u
               LEFT JOIN user_registrations r ON u.id = r.linuxdo_user_id
               GROUP BY u.id
               ORDER BY u.last_login DESC'''
        ).fetchall()
        
        for user in linuxdo_users_data:
            max_allowed = TRUST_LEVEL_LIMITS.get(user['trust_level'], 1)
            linuxdo_users.append({
                'id': user['id'],
                'username': user['username'],
                'name': user['name'],
                'trust_level': user['trust_level'],
                'email': user['email'],
                'registration_count': user['registration_count'],
                'max_allowed': max_allowed,
                'last_login': user['last_login']
            })
    
    db.close()

    # 6. Create the pagination object
    pagination = Pagination(page=page, per_page=per_page, total=total,
                            css_framework='bootstrap5',
                            record_name='tokens',
                            args={'q': search_query} if search_query else None)

    # Process tokens
    processed_tokens = []
    for token_row in tokens_from_db:
        processed_tokens.append({
            'id': token_row['id'],
            'full_signed_token': _generate_signed_token(token_row['token']),
            'is_used': token_row['is_used'],
            'username': token_row['registered_username']
        })

    return render_template(
        'admin.html',
        tokens=processed_tokens,
        pagination=pagination,
        public_access_url=PUBLIC_ACCESS_URL,
        search_query=search_query,
        linuxdo_users=linuxdo_users
    )

@app.route('/admin/generate', methods=['POST'])
@login_required
def generate_token():
    db = get_db()
    generated_tokens = []
    # 批量生成100个token
    for _ in range(100):
        nonce = secrets.token_urlsafe(16)
        generated_tokens.append(nonce)
        db.execute('INSERT INTO tokens (token) VALUES (?)', (nonce,))
    db.commit()
    db.close()

    # 构造CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Token', '注册链接'])
    for token in generated_tokens:
        signed = _generate_signed_token(token)
        register_url = f"{PUBLIC_ACCESS_URL}/emby?token={signed}"
        writer.writerow([token, register_url])
    output.seek(0)

    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=generated_tokens_{timestamp}.csv'}
    )

@app.route('/admin/export_unused', methods=['GET'])
@login_required
def export_unused_tokens():
    db = get_db()
    unused_tokens = db.execute(
        'SELECT token FROM tokens WHERE is_used = 0 ORDER BY created_at DESC'
    ).fetchall()
    db.close()
    
    if not unused_tokens:
        flash('没有未使用的Token可导出。', 'warning')
        return redirect(url_for('admin'))
    
    # 生成CSV格式的响应
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Token', '注册链接'])
    
    for token_row in unused_tokens:
        token = token_row['token']
        signed_token = _generate_signed_token(token)
        register_url = f"{PUBLIC_ACCESS_URL}/emby?token={signed_token}"
        writer.writerow([token, register_url])
    
    output.seek(0)
    
    response = Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=unused_tokens.csv'}
    )
    return response

@app.route('/admin/delete/<int:token_id>', methods=['POST'])
@login_required
def delete_token(token_id):
    db = get_db(); db.execute('DELETE FROM tokens WHERE id = ?', (token_id,)); db.commit(); db.close()
    flash('Token 已成功删除。', 'info'); return redirect(url_for('admin'))

@app.route('/admin/user_registrations')
@login_required
def admin_user_registrations():
    user_id = request.args.get('user_id')
    if not user_id:
        return {"success": False, "msg": "缺少用户ID"}, 400
    db = get_db()
    regs = db.execute(
        '''SELECT emby_username, emby_password, registered_at
           FROM user_registrations
           WHERE linuxdo_user_id = ?
           ORDER BY registered_at DESC''',
        (user_id,)
    ).fetchall()
    db.close()
    data = [
        {
            "emby_username": r["emby_username"],
            "emby_password": r["emby_password"],
            "registered_at": r["registered_at"]
        }
        for r in regs
    ]
    return {"success": True, "data": data}

@app.route('/linuxdo/reset_password', methods=['POST'])
@linuxdo_login_required
def linuxdo_reset_password():
    emby_username = request.form.get('emby_username')
    if not emby_username:
        return {"success": False, "msg": "缺少用户名"}, 400
    db = get_db()
    reg = db.execute(
        'SELECT emby_user_id, linuxdo_user_id FROM user_registrations WHERE emby_username = ?',
        (emby_username,)
    ).fetchone()
    if not reg or reg['linuxdo_user_id'] != session['linuxdo_user_id']:
        db.close()
        return {"success": False, "msg": "无权重置该账号"}, 403
    emby_user_id = reg['emby_user_id']
    # 生成新密码
    new_password = ''.join(secrets.choice(string.digits) for _ in range(12))
    # 调用Emby API重置密码
    headers = {'X-Emby-Token': EMBY_API_KEY, 'Content-Type': 'application/json'}
    set_password_url = f"{EMBY_SERVER_URL}/Users/{emby_user_id}/Password"
    password_payload = {"Id": emby_user_id, "NewPw": new_password}
    try:
        resp = requests.post(set_password_url, json=password_payload, headers=headers, timeout=10, verify=not DISABLE_SSL_VERIFY)
        resp.raise_for_status()
    except Exception as e:
        db.close()
        return {"success": False, "msg": f"Emby API调用失败: {e}"}, 500
    # 更新数据库
    db.execute('UPDATE user_registrations SET emby_password = ? WHERE emby_username = ?', (new_password, emby_username))
    db.commit()
    db.close()
    return {"success": True, "new_password": new_password}

@app.route('/emby', methods=['GET', 'POST'])
def emby_register():
    error_msg_template = "您使用的注册链接无效、已被篡改或已过期。"
    full_token_str = request.form.get('token') if request.method == 'POST' else request.args.get('token')
    
    # 检查是否通过Linux.do OAuth2登录
    if 'linuxdo_user_id' in session:
        return linuxdo_register()
    
    # 原有的token验证逻辑
    if not full_token_str:
        return render_template('error.html', error_message="链接不完整，缺少参数。")
    token_payload = _verify_signed_token(full_token_str)
    if not token_payload:
        return render_template('error.html', error_message=error_msg_template)
    db = get_db()
    token_data = db.execute('SELECT * FROM tokens WHERE token = ? AND is_used = 0', (token_payload,)).fetchone()
    if not token_data:
        db.close()
        return render_template('error.html', error_message=error_msg_template)
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        if not re.match(r'^[a-zA-Z0-9]{4,32}$', username):
            db.close()
            return render_template('register.html', token=full_token_str, error="用户名不合法：长度需为4-32位，且只能包含英文字母和数字。")
        password = ''.join(secrets.choice(string.digits) for _ in range(12))
        user_id, error_msg = create_emby_user(username, password)
        if not user_id:
            db.close()
            return render_template('register.html', token=full_token_str, error=error_msg)
        
        db.execute(
            'UPDATE tokens SET is_used = 1, registered_username = ? WHERE id = ?',
            (username, token_data['id'])
        )
        # 保存注册信息
        db.execute(
            'INSERT INTO user_registrations (linuxdo_user_id, emby_username, emby_user_id, emby_password) VALUES (?, ?, ?, ?)',
            (None, username, user_id, password)
        )
        db.commit()
        db.close()
        
        return render_template('success.html', username=username, password=password, emby_url=EMBY_SERVER_URL)
    db.close()
    return render_template('register.html', token=full_token_str)

def linuxdo_register():
    """Linux.do用户的注册处理"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        if not re.match(r'^[a-zA-Z0-9]{4,32}$', username):
            return render_template('linuxdo_register.html', error="用户名不合法：长度需为4-32位，且只能包含英文字母和数字。")
        
        # 检查用户是否可以注册
        if not can_user_register(session['linuxdo_user_id'], session['linuxdo_trust_level']):
            current_count = get_user_registration_count(session['linuxdo_user_id'])
            max_allowed = TRUST_LEVEL_LIMITS.get(session['linuxdo_trust_level'], 1)
            return render_template('linuxdo_register.html', 
                                error=f"您已达到注册上限。当前已注册 {current_count} 个账号，最多可注册 {max_allowed} 个账号。")
        
        # 检查用户名是否已被使用
        db = get_db()
        existing_user = db.execute(
            'SELECT emby_username FROM user_registrations WHERE emby_username = ?',
            (username,)
        ).fetchone()
        if existing_user:
            db.close()
            return render_template('linuxdo_register.html', error="该用户名已被使用，请选择其他用户名。")
        
        # 创建Emby用户
        password = ''.join(secrets.choice(string.digits) for _ in range(12))
        user_id, error_msg = create_emby_user(username, password)
        if not user_id:
            db.close()
            return render_template('linuxdo_register.html', error=error_msg)
        
        # 记录注册信息
        db.execute(
            'INSERT INTO user_registrations (linuxdo_user_id, emby_username, emby_user_id, emby_password) VALUES (?, ?, ?, ?)',
            (session['linuxdo_user_id'], username, user_id, password)
        )
        db.commit()
        db.close()
        
        return render_template('linuxdo_success.html', 
                             username=username, 
                             password=password, 
                             emby_url=EMBY_SERVER_URL,
                             user_name=session['linuxdo_name'])
    
    return render_template('linuxdo_register.html')

# --- Main Execution ---
if __name__ == '__main__': 
    init_db()
    app.run(host='0.0.0.0', port=5000)