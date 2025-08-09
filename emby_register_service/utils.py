import hmac
import hashlib
import requests
import secrets
import string
from datetime import datetime, timedelta
from flask import current_app
from .database import get_db, log_user_deletion

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


# --- 用户活跃度检查和清理功能 ---
def get_emby_user_info(user_id):
    """获取Emby用户信息包括最后活跃时间"""
    config = current_app.config
    headers = {'X-Emby-Token': config['EMBY_API_KEY'], 'Content-Type': 'application/json'}
    
    try:
        # 获取用户基本信息
        user_url = f"{config['EMBY_SERVER_URL']}/Users/{user_id}"
        response = requests.get(user_url, headers=headers, timeout=10, 
                               verify=not config.get('DISABLE_SSL_VERIFY', False))
        response.raise_for_status()
        user_info = response.json()
        
        # 获取用户活动信息 - 使用Sessions API获取用户会话信息
        sessions_url = f"{config['EMBY_SERVER_URL']}/Sessions"
        sessions_response = requests.get(sessions_url, headers=headers, timeout=10,
                                       verify=not config.get('DISABLE_SSL_VERIFY', False))
        sessions_response.raise_for_status()
        sessions = sessions_response.json()
        
        # 查找用户的最后活跃时间
        last_activity_date = None
        user_sessions = [s for s in sessions if s.get('UserId') == user_id]
        
        if user_sessions:
            # 如果用户当前有活跃会话，则认为是最近活跃的
            last_activity_date = datetime.now()
        else:
            # 通过用户信息中的LastActivityDate获取
            last_activity = user_info.get('LastActivityDate')
            if last_activity:
                # 解析时间并转换为naive datetime（去掉时区信息）
                parsed_time = datetime.fromisoformat(last_activity.replace('Z', '+00:00'))
                last_activity_date = parsed_time.replace(tzinfo=None)
            else:
                # 如果没有活动记录，则使用用户创建时间
                date_created = user_info.get('DateCreated')
                if date_created:
                    # 解析时间并转换为naive datetime（去掉时区信息）
                    parsed_time = datetime.fromisoformat(date_created.replace('Z', '+00:00'))
                    last_activity_date = parsed_time.replace(tzinfo=None)
        
        return {
            'user_id': user_id,
            'name': user_info.get('Name'),
            'last_activity_date': last_activity_date,
            'date_created': user_info.get('DateCreated'),
            'is_disabled': user_info.get('Policy', {}).get('IsDisabled', False)
        }
        
    except requests.RequestException as e:
        current_app.logger.error(f"获取Emby用户 {user_id} 信息失败: {e}")
        return None
    except Exception as e:
        current_app.logger.error(f"处理Emby用户 {user_id} 信息时出错: {e}")
        return None


def delete_emby_user(user_id):
    """删除Emby用户"""
    config = current_app.config
    headers = {'X-Emby-Token': config['EMBY_API_KEY'], 'Content-Type': 'application/json'}
    
    try:
        delete_url = f"{config['EMBY_SERVER_URL']}/Users/{user_id}"
        response = requests.delete(delete_url, headers=headers, timeout=10,
                                 verify=not config.get('DISABLE_SSL_VERIFY', False))
        response.raise_for_status()
        return True, None
    except requests.RequestException as e:
        current_app.logger.error(f"删除Emby用户 {user_id} 失败: {e}")
        return False, f"删除用户失败: {e}"


def verify_platform_created_user(emby_user_id, emby_username):
    """验证用户是否由平台创建"""
    config = current_app.config
    
    # 检查配置是否启用平台用户验证
    if not config.get('CLEANUP_ONLY_PLATFORM_USERS', True):
        current_app.logger.debug(f"用户 {emby_username}: 平台用户验证已禁用，跳过检查")
        return True, "验证已禁用"
    
    try:
        # 1. 检查数据库记录 - 最基本的验证
        db = get_db()
        registration = db.execute(
            'SELECT * FROM user_registrations WHERE emby_user_id = ? AND emby_username = ?',
            (emby_user_id, emby_username)
        ).fetchone()
        
        if not registration:
            current_app.logger.warning(f"用户 {emby_username} (ID: {emby_user_id}) 在注册记录中不存在，不是平台创建的用户")
            return False, "不在平台注册记录中"
        
        # 2. 通过Emby API获取用户详细信息进行进一步验证
        headers = {'X-Emby-Token': config['EMBY_API_KEY'], 'Content-Type': 'application/json'}
        user_url = f"{config['EMBY_SERVER_URL']}/Users/{emby_user_id}"
        response = requests.get(user_url, headers=headers, timeout=10,
                               verify=not config.get('DISABLE_SSL_VERIFY', False))
        response.raise_for_status()
        user_info = response.json()
        
        # 3. 验证用户名匹配
        if user_info.get('Name') != emby_username:
            current_app.logger.warning(f"用户ID {emby_user_id} 的用户名不匹配: 数据库={emby_username}, Emby={user_info.get('Name')}")
            return False, "用户名不匹配"
        
        # 4. 检查用户策略是否来自模板用户（可选验证）
        template_user_id = config.get('COPY_FROM_USER_ID')
        if template_user_id:
            try:
                # 获取模板用户信息
                template_url = f"{config['EMBY_SERVER_URL']}/Users/{template_user_id}"
                template_response = requests.get(template_url, headers=headers, timeout=10,
                                               verify=not config.get('DISABLE_SSL_VERIFY', False))
                template_response.raise_for_status()
                template_info = template_response.json()
                
                # 比较关键的策略配置，确认是从模板复制的
                user_policy = user_info.get('Policy', {})
                template_policy = template_info.get('Policy', {})
                
                # 检查几个关键的策略项是否相同
                key_policies = ['EnableAllChannels', 'EnableAllDevices', 'EnableAllFolders', 'IsAdministrator']
                policy_matches = all(
                    user_policy.get(key) == template_policy.get(key) 
                    for key in key_policies
                )
                
                if not policy_matches:
                    current_app.logger.info(f"用户 {emby_username} 的策略配置与模板用户不完全匹配，但仍继续删除（可能是后期修改）")
                else:
                    current_app.logger.debug(f"用户 {emby_username} 策略配置与模板用户匹配，确认为平台创建")
                    
            except Exception as e:
                current_app.logger.warning(f"验证用户 {emby_username} 的模板策略时出错: {e}，继续执行删除")
        
        current_app.logger.info(f"用户 {emby_username} 验证通过：确认为平台创建的用户")
        return True, "验证通过"
        
    except requests.RequestException as e:
        current_app.logger.error(f"验证用户 {emby_username} 时Emby API调用失败: {e}")
        # API调用失败时，如果数据库中有记录，仍然认为是平台用户
        db = get_db()
        registration = db.execute(
            'SELECT * FROM user_registrations WHERE emby_user_id = ? AND emby_username = ?',
            (emby_user_id, emby_username)
        ).fetchone()
        
        if registration:
            current_app.logger.warning(f"用户 {emby_username} API验证失败，但数据库记录存在，继续执行删除")
            return True, "数据库记录存在（API验证失败）"
        else:
            return False, f"数据库记录不存在且API验证失败: {e}"
    
    except Exception as e:
        current_app.logger.error(f"验证用户 {emby_username} 时出现未知错误: {e}")
        return False, f"验证失败: {e}"


def cleanup_inactive_users():
    """清理不活跃的用户"""
    config = current_app.config
    
    # 检查是否启用了用户清理功能
    if not config.get('ENABLE_USER_CLEANUP', True):
        current_app.logger.info("用户清理功能已禁用")
        return {
            'deleted_count': 0,
            'errors': [],
            'total_checked': 0,
            'message': '用户清理功能已禁用'
        }
    
    db = get_db()
    current_time = datetime.now()
    
    # 从配置获取清理参数
    new_user_days = config.get('CLEANUP_NEW_USER_DAYS', 7)
    inactive_user_days = config.get('CLEANUP_INACTIVE_USER_DAYS', 30)
    
    # 获取所有已注册的用户
    registrations = db.execute(
        '''SELECT emby_user_id, emby_username, registered_at, linuxdo_user_id
           FROM user_registrations 
           WHERE emby_user_id IS NOT NULL'''
    ).fetchall()
    
    deleted_count = 0
    errors = []
    
    current_app.logger.info(f"开始清理不活跃用户，检查 {len(registrations)} 个用户")
    current_app.logger.info(f"清理规则: 新用户 {new_user_days} 天未登录，老用户 {inactive_user_days} 天未活跃")
    
    for registration in registrations:
        emby_user_id = registration['emby_user_id']
        emby_username = registration['emby_username']
        registered_at_str = registration['registered_at']
        
        # 解析注册时间
        try:
            # 检查是否已经是datetime对象
            if isinstance(registered_at_str, datetime):
                registered_at = registered_at_str
                # 确保是naive datetime（去掉时区信息）
                if registered_at.tzinfo is not None:
                    registered_at = registered_at.replace(tzinfo=None)
            else:
                # 尝试解析字符串
                try:
                    registered_at = datetime.strptime(registered_at_str, '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    parsed_time = datetime.fromisoformat(registered_at_str)
                    # 确保是naive datetime（去掉时区信息）
                    registered_at = parsed_time.replace(tzinfo=None) if parsed_time.tzinfo else parsed_time
        except (ValueError, TypeError) as e:
            current_app.logger.error(f"无法解析用户 {emby_username} 的注册时间: {registered_at_str}, 错误: {e}")
            continue
        
        # 获取用户在Emby中的活跃信息
        user_info = get_emby_user_info(emby_user_id)
        if not user_info:
            current_app.logger.warning(f"无法获取用户 {emby_username} (ID: {emby_user_id}) 的Emby信息，可能用户已被删除")
            continue
        
        should_delete = False
        reason = ""
        
        # 检查删除条件
        time_since_registration = current_time - registered_at
        
        # 调试日志：检查时间对象类型
        current_app.logger.debug(f"用户 {emby_username} - current_time类型: {type(current_time)}, tzinfo: {getattr(current_time, 'tzinfo', None)}")
        current_app.logger.debug(f"用户 {emby_username} - registered_at类型: {type(registered_at)}, tzinfo: {getattr(registered_at, 'tzinfo', None)}")
        
        if user_info['last_activity_date']:
            last_activity = user_info['last_activity_date']
            current_app.logger.debug(f"用户 {emby_username} - last_activity类型: {type(last_activity)}, tzinfo: {getattr(last_activity, 'tzinfo', None)}")
            time_since_last_activity = current_time - last_activity
            
            # 注册超过指定天数且从未登录过的用户
            if time_since_registration > timedelta(days=new_user_days) and time_since_last_activity >= time_since_registration:
                should_delete = True
                reason = f"注册超过{new_user_days}天({time_since_registration.days}天)且从未登录"
            # 最近指定天数未登录的用户
            elif time_since_last_activity > timedelta(days=inactive_user_days):
                should_delete = True
                reason = f"超过{inactive_user_days}天未登录(上次活跃: {time_since_last_activity.days}天前)"
        else:
            # 没有活动记录，如果注册超过指定天数则删除
            if time_since_registration > timedelta(days=new_user_days):
                should_delete = True
                reason = f"注册超过{new_user_days}天({time_since_registration.days}天)且无活动记录"
        
        if should_delete:
            current_app.logger.info(f"准备删除不活跃用户: {emby_username} - {reason}")
            
            # 验证用户是否由平台创建（安全检查）
            is_platform_user, verify_reason = verify_platform_created_user(emby_user_id, emby_username)
            if not is_platform_user:
                current_app.logger.warning(f"跳过删除用户 {emby_username}: {verify_reason}")
                errors.append(f"跳过删除用户 {emby_username}: {verify_reason}")
                continue
            
            current_app.logger.info(f"用户 {emby_username} 验证通过，确认为平台创建的用户: {verify_reason}")
            
            # 计算删除统计信息
            days_since_reg = time_since_registration.days if time_since_registration else None
            days_since_activity = None
            if user_info['last_activity_date']:
                days_since_activity = (current_time - user_info['last_activity_date']).days
            
            # 删除Emby中的用户
            success, error = delete_emby_user(emby_user_id)
            if success:
                # 记录删除日志
                try:
                    log_user_deletion(
                        emby_user_id=emby_user_id,
                        emby_username=emby_username,
                        linuxdo_user_id=registration['linuxdo_user_id'],
                        deletion_reason=reason,
                        registered_at=registered_at,
                        last_activity_date=user_info['last_activity_date'],
                        days_since_registration=days_since_reg,
                        days_since_last_activity=days_since_activity,
                        deleted_by='system_cleanup'
                    )
                    current_app.logger.info(f"已记录用户删除日志: {emby_username}")
                except Exception as log_error:
                    current_app.logger.error(f"记录删除日志失败 {emby_username}: {log_error}")
                
                # 删除数据库中的注册记录
                db.execute(
                    'DELETE FROM user_registrations WHERE emby_user_id = ?',
                    (emby_user_id,)
                )
                db.commit()
                
                deleted_count += 1
                current_app.logger.info(f"成功删除不活跃用户: {emby_username}")
            else:
                errors.append(f"删除用户 {emby_username} 失败: {error}")
    
    result = {
        'deleted_count': deleted_count,
        'errors': errors,
        'total_checked': len(registrations)
    }
    
    current_app.logger.info(f"用户清理完成: 检查了 {result['total_checked']} 个用户，删除了 {result['deleted_count']} 个用户")
    if result['errors']:
        current_app.logger.error(f"清理过程中出现 {len(result['errors'])} 个错误")
    
    return result 