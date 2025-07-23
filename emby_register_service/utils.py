import hmac
import hashlib
import requests
import secrets
import string
from flask import current_app
from .database import get_db

# --- HMAC Signature Helpers ---
def _generate_signed_token(payload):
    secret_key = current_app.config['SECRET_KEY']
    signature = hmac.new(secret_key.encode('utf-8'), payload.encode('utf-8'), hashlib.sha256).hexdigest()
    return f"{payload}.{signature}"

def _verify_signed_token(signed_token):
    if not signed_token or '.' not in signed_token: return None
    payload, signature = signed_token.rsplit('.', 1)
    secret_key = current_app.config['SECRET_KEY']
    expected_signature = hmac.new(secret_key.encode('utf-8'), payload.encode('utf-8'), hashlib.sha256).hexdigest()
    if hmac.compare_digest(expected_signature, signature): return payload
    return None

# --- Emby API Helper ---
def create_emby_user(username, password):
    config = current_app.config
    headers = {'X-Emby-Token': config['EMBY_API_KEY'], 'Content-Type': 'application/json'}
    create_url = f"{config['EMBY_SERVER_URL']}/Users/New"
    create_payload = {"Name": username, "CopyFromUserId": config['COPY_FROM_USER_ID'], "UserCopyOptions": ["UserConfiguration", "UserPolicy"]}
    try:
        response = requests.post(create_url, json=create_payload, headers=headers, timeout=15)
        response.raise_for_status()
        user_data = response.json()
        user_id = user_data.get('Id')
        if not user_id: return None, "创建用户成功，但在响应中未找到User ID。"
    except requests.RequestException as e:
        current_app.logger.error(f"步骤 1/2 - 创建用户 '{username}' 失败: {e}")
        try:
            if e.response is not None and "already exists" in e.response.text.lower(): return None, "用户名已存在"
        except (AttributeError, ValueError): pass
        return None, f"创建用户失败: {e}"
    try:
        set_password_url = f"{config['EMBY_SERVER_URL']}/Users/{user_id}/Password"
        password_payload = {"Id": user_id, "NewPw": password}
        password_response = requests.post(set_password_url, json=password_payload, headers=headers, timeout=10)
        password_response.raise_for_status()
    except requests.RequestException as e:
        current_app.logger.error(f"步骤 2/2 - 为用户 '{username}' (ID: {user_id}) 设置密码失败: {e}")
        return None, "用户已创建但设置密码失败，请联系管理员。"
    return user_id, None


# --- OAuth2 Helper Functions ---
def get_linuxdo_user_info(oauth):
    """获取Linux.do用户信息"""
    try:
        resp = oauth.linuxdo.get('/api/user')
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        current_app.logger.error(f"获取Linux.do用户信息失败: {e}")
        return None

def get_or_create_linuxdo_user(user_info):
    """获取或创建Linux.do用户记录"""
    db = get_db()
    
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