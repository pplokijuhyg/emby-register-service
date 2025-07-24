import secrets
import string
import re
import io
import csv
from datetime import datetime, timedelta
from functools import wraps
import requests
import os
import xml.etree.ElementTree as ET
from email.utils import formatdate

from flask import (
    Blueprint, flash, redirect, render_template, request, session, url_for, Response, current_app
)
from flask_paginate import Pagination, get_page_args

from .database import get_db, get_user_registration_count, can_user_register
from .utils import (
    _generate_signed_token, _verify_signed_token, create_emby_user,
    get_linuxdo_user_info, get_or_create_linuxdo_user
)
from authlib.integrations.flask_client import OAuth

bp = Blueprint('main', __name__)
oauth = OAuth()

# --- Decorators ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('main.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def linuxdo_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'linuxdo_user_id' not in session:
            return redirect(url_for('main.linuxdo_login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---
@bp.route('/')
def index():
    if current_app.config['LINUXDO_OAUTH_ENABLED']:
        return redirect(url_for('main.linuxdo_login'))
    return redirect(url_for('main.login'))

# --- Linux.do OAuth2 Routes ---
@bp.route('/linuxdo/login')
def linuxdo_login():
    if not current_app.config['LINUXDO_OAUTH_ENABLED']:
        flash('Linux.do OAuth2登录功能未启用', 'warning')
        return redirect(url_for('main.login'))
    
    redirect_uri = url_for('main.oauth2_callback', _external=True)
    return oauth.linuxdo.authorize_redirect(redirect_uri)

@bp.route('/oauth2/callback')
def oauth2_callback():
    if not current_app.config['LINUXDO_OAUTH_ENABLED']:
        flash('Linux.do OAuth2登录功能未启用', 'warning')
        return redirect(url_for('main.login'))
    
    try:
        token = oauth.linuxdo.authorize_access_token()
        user_info = get_linuxdo_user_info(oauth)
        if not user_info:
            flash('获取用户信息失败', 'error')
            return redirect(url_for('main.linuxdo_login'))
        
        user_id = get_or_create_linuxdo_user(user_info)
        
        session.permanent = True
        session['linuxdo_user_id'] = user_id
        session['linuxdo_username'] = user_info['username']
        session['linuxdo_name'] = user_info['name']
        session['linuxdo_trust_level'] = user_info['trust_level']
        
        flash(f'欢迎回来，{user_info["name"]}！', 'success')
        
        next_url = request.args.get('next', url_for('main.linuxdo_dashboard'))
        return redirect(next_url)
        
    except Exception as e:
        current_app.logger.error(f"OAuth2回调处理失败: {e}")
        flash('OAuth2登录失败，请重试', 'error')
        return redirect(url_for('main.linuxdo_login'))

@bp.route('/linuxdo/logout')
def linuxdo_logout():
    session.clear()
    flash('您已退出登录', 'info')
    return redirect(url_for('main.linuxdo_login'))

@bp.route('/linuxdo/dashboard')
@linuxdo_login_required
def linuxdo_dashboard():
    db = get_db()
    user = db.execute(
        'SELECT * FROM linuxdo_users WHERE id = ?',
        (session['linuxdo_user_id'],)
    ).fetchone()
    
    registrations = db.execute(
        '''SELECT emby_username, emby_user_id, registered_at, emby_password 
           FROM user_registrations 
           WHERE linuxdo_user_id = ? 
           ORDER BY registered_at DESC''',
        (session['linuxdo_user_id'],)
    ).fetchall()
    
    can_reg = can_user_register(session['linuxdo_user_id'], user['trust_level'])
    current_count = get_user_registration_count(session['linuxdo_user_id'])
    max_allowed = current_app.config['TRUST_LEVEL_LIMITS'].get(user['trust_level'], 1)
    
    return render_template('linuxdo_dashboard.html', 
                         user=user, 
                         registrations=registrations,
                         can_register=can_reg,
                         current_count=current_count,
                         max_allowed=max_allowed)

@bp.route('/requests', methods=['GET', 'POST'])
@linuxdo_login_required
def show_requests():
    db = get_db()
    # 自动清理2个月前的申请
    db.execute(
        """DELETE FROM requests WHERE requested_at < ?""",
        ((datetime.now() - timedelta(days=60)).strftime('%Y-%m-%d %H:%M:%S'),)
    )
    db.commit()
    if request.method == 'POST':
        douban_url = request.form.get('douban_url')
        if not douban_url:
            flash('豆瓣地址是必填项。', 'danger')
        else:
            # 提取豆瓣id
            import re
            m = re.search(r'/subject/(\d+)', douban_url)
            douban_id = m.group(1) if m else None
            if not douban_id:
                flash('豆瓣链接格式不正确，无法提取ID。', 'danger')
            else:
                # 限制每人每天只能申请一部剧
                user_id = session['linuxdo_user_id']
                today = datetime.now().strftime('%Y-%m-%d')
                count_today = db.execute(
                    'SELECT COUNT(*) FROM requests WHERE requested_by_user_id = ? AND DATE(requested_at) = ?',
                    (user_id, today)
                ).fetchone()[0]
                if count_today >= 1:
                    flash('每人每天只能申请添加一部剧。', 'warning')
                    return redirect(url_for('main.show_requests'))
                # 查重
                exists = db.execute('SELECT id FROM requests WHERE douban_id = ?', (douban_id,)).fetchone()
                if exists:
                    # 已有该剧集，自动投票
                    request_id = exists['id']
                    user_id = session['linuxdo_user_id']
                    already_voted = db.execute('SELECT 1 FROM votes WHERE user_id = ? AND request_id = ?', (user_id, request_id)).fetchone()
                    if already_voted:
                        flash('您已经投过票了', 'warning')
                    else:
                        db.execute('INSERT INTO votes (user_id, request_id) VALUES (?, ?)', (user_id, request_id))
                        db.commit()
                        flash('已为该剧集投票成功！', 'success')
                    return redirect(url_for('main.show_requests'))
                else:
                    # 抓取豆瓣页面
                    cookies = os.getenv('DOUBAN_COOKIES')
                    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0','referer':"https://search.douban.com/movie/subject_search?search_text=%E5%BC%82%E4%BA%BA%E4%B9%8B%E4%B8%8B&amp;cat=1002"}
                    if cookies:
                        headers['Cookie'] = cookies
                    try:
                        resp = requests.get(douban_url, headers=headers, timeout=10, verify=False)
                        resp.raise_for_status()
                        html = resp.text
                        # 提取标题
                        title_match = re.search(r'<meta property="og:title" content="([^"]+)"', html)
                        show_name = title_match.group(1) if title_match else None
                        # 提取图片
                        img_match = re.search(r'<meta property="og:image" content="([^"]+)"', html)
                        poster_image_url = img_match.group(1) if img_match else None
                        if not show_name:
                            flash('无法从豆瓣页面提取剧集名称。', 'danger')
                        else:
                            db.execute(
                                'INSERT INTO requests (show_name, douban_url, douban_id, poster_image_url, requested_by_user_id, status) VALUES (?, ?, ?, ?, ?, ?)',
                                (show_name, douban_url, douban_id, poster_image_url, session['linuxdo_user_id'], 'approved')
                            )
                            db.commit()
                            flash('剧集申请已提交！', 'success')
                            return redirect(url_for('main.show_requests'))
                    except Exception as e:
                        flash(f'抓取豆瓣信息失败: {e}', 'danger')

    # 自动将想看数大于5的剧集状态改为已处理（approved）
    # 已废弃，不再自动处理

    # 获取所有申请列表及投票数和当前用户是否已投票
    all_requests = db.execute(
        '''
        SELECT r.*, u.username,
            (SELECT COUNT(*) FROM votes v WHERE v.request_id = r.id) as vote_count,
            (SELECT COUNT(*) FROM votes v WHERE v.request_id = r.id AND v.user_id = ?) as user_voted
        FROM requests r
        JOIN linuxdo_users u ON r.requested_by_user_id = u.id
        ORDER BY r.requested_at DESC
        ''',
        (session['linuxdo_user_id'],)
    ).fetchall()

    return render_template('requests.html', requests=all_requests)

@bp.route('/requests/vote/<int:request_id>', methods=['POST'])
@linuxdo_login_required
def vote_request(request_id):
    db = get_db()
    user_id = session['linuxdo_user_id']
    # 检查是否已投票
    already = db.execute('SELECT 1 FROM votes WHERE user_id = ? AND request_id = ?', (user_id, request_id)).fetchone()
    if already:
        flash('您已经投过票了。', 'warning')
    else:
        db.execute('INSERT INTO votes (user_id, request_id) VALUES (?, ?)', (user_id, request_id))
        db.commit()
        flash('投票成功！', 'success')
    return redirect(url_for('main.show_requests'))


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('password') == current_app.config['ADMIN_PASSWORD']:
            session.permanent = True
            session['logged_in'] = True
            flash('登录成功!', 'success')
            return redirect(url_for('main.admin'))
        else:
            return render_template('login.html', error='密码错误')
    return render_template('login.html')

@bp.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('您已退出登录。', 'info')
    return redirect(url_for('main.login'))

@bp.route('/admin')
@login_required
def admin():
    db = get_db()
    
    search_query = request.args.get('q', '').strip()
    
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
                                           per_page=current_app.config['PER_PAGE'])

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
    
    linuxdo_users = []
    if current_app.config['LINUXDO_OAUTH_ENABLED']:
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
            max_allowed = current_app.config['TRUST_LEVEL_LIMITS'].get(user['trust_level'], 1)
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
    
    # 获取剧集申请数据
    requests = db.execute(
        '''
        SELECT r.id, r.show_name, r.douban_url, r.poster_image_url, r.status, r.requested_at, u.username
        FROM requests r
        JOIN linuxdo_users u ON r.requested_by_user_id = u.id
        ORDER BY r.requested_at DESC
        '''
    ).fetchall()
    
    db.close()

    # 6. Create the pagination object
    pagination = Pagination(page=page, per_page=per_page, total=total,
                            css_framework='bootstrap5',
                            record_name='tokens',
                            args={'q': search_query} if search_query else None)

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
        public_access_url=current_app.config['PUBLIC_ACCESS_URL'],
        search_query=search_query,
        linuxdo_users=linuxdo_users,
        requests=requests
    )

@bp.route('/admin/requests', methods=['GET'])
@login_required
def admin_requests():
    db = get_db()
    # 自动清理2个月前的申请
    db.execute(
        """DELETE FROM requests WHERE requested_at < ?""",
        ((datetime.now() - timedelta(days=60)).strftime('%Y-%m-%d %H:%M:%S'),)
    )
    db.commit()
    status = request.args.get('status')
    query = '''
        SELECT r.id, r.show_name, r.douban_url, r.poster_image_url, r.status, r.requested_at, u.username,
            (SELECT COUNT(*) FROM votes v WHERE v.request_id = r.id) as vote_count
        FROM requests r
        JOIN linuxdo_users u ON r.requested_by_user_id = u.id
    '''
    params = []
    if status:
        query += ' WHERE r.status = ?'
        params.append(status)
    query += ' ORDER BY vote_count DESC, r.requested_at DESC'
    requests = db.execute(query, params).fetchall()
    return render_template('admin_requests.html', requests=requests, filter_status=status)

@bp.route('/admin/requests/delete/<int:request_id>', methods=['POST'])
@login_required
def delete_request(request_id):
    db = get_db()
    db.execute('DELETE FROM requests WHERE id = ?', (request_id,))
    db.commit()
    flash('申请已删除。', 'success')
    return redirect(url_for('main.admin_requests'))

@bp.route('/admin/requests/update_status/<int:request_id>/<status>', methods=['GET', 'POST'])
@login_required
def update_request_status(request_id, status):
    if status not in ['pending', 'approved', 'rejected', 'added']:
        flash('无效的状态。', 'danger')
        return redirect(url_for('main.admin_requests'))
    
    db = get_db()
    db.execute('UPDATE requests SET status = ? WHERE id = ?', (status, request_id))
    db.commit()
    flash('申请状态已更新。', 'success')
    return redirect(url_for('main.admin_requests'))


@bp.route('/admin/generate', methods=['POST'])
@login_required
def generate_token():
    db = get_db()
    generated_tokens = []
    for _ in range(100):
        nonce = secrets.token_urlsafe(16)
        generated_tokens.append(nonce)
        db.execute('INSERT INTO tokens (token) VALUES (?)', (nonce,))
    db.commit()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Token', '注册链接'])
    for token in generated_tokens:
        signed = _generate_signed_token(token)
        register_url = f"{current_app.config['PUBLIC_ACCESS_URL']}/emby?token={signed}"
        writer.writerow([token, register_url])
    output.seek(0)

    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=generated_tokens_{timestamp}.csv'}
    )

@bp.route('/admin/export_unused', methods=['GET'])
@login_required
def export_unused_tokens():
    db = get_db()
    unused_tokens = db.execute(
        'SELECT token FROM tokens WHERE is_used = 0 ORDER BY created_at DESC'
    ).fetchall()
    
    if not unused_tokens:
        flash('没有未使用的Token可导出。', 'warning')
        return redirect(url_for('main.admin'))
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Token', '注册链接'])
    
    for token_row in unused_tokens:
        token = token_row['token']
        signed_token = _generate_signed_token(token)
        register_url = f"{current_app.config['PUBLIC_ACCESS_URL']}/emby?token={signed_token}"
        writer.writerow([token, register_url])
    
    output.seek(0)
    
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=unused_tokens.csv'}
    )

@bp.route('/admin/delete/<int:token_id>', methods=['POST'])
@login_required
def delete_token(token_id):
    db = get_db()
    db.execute('DELETE FROM tokens WHERE id = ?', (token_id,))
    db.commit()
    flash('Token 已成功删除。', 'info')
    return redirect(url_for('main.admin'))

@bp.route('/admin/user_registrations')
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
    data = [
        {
            "emby_username": r["emby_username"],
            "emby_password": r["emby_password"],
            "registered_at": r["registered_at"]
        }
        for r in regs
    ]
    return {"success": True, "data": data}

@bp.route('/linuxdo/reset_password', methods=['POST'])
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
        return {"success": False, "msg": "无权重置该账号"}, 403
    emby_user_id = reg['emby_user_id']
    new_password = ''.join(secrets.choice(string.digits) for _ in range(12))
    
    headers = {'X-Emby-Token': current_app.config['EMBY_API_KEY'], 'Content-Type': 'application/json'}
    set_password_url = f"{current_app.config['EMBY_SERVER_URL']}/Users/{emby_user_id}/Password"
    password_payload = {"Id": emby_user_id, "NewPw": new_password}
    try:
        resp = requests.post(set_password_url, json=password_payload, headers=headers, timeout=10, verify=not current_app.config['DISABLE_SSL_VERIFY'])
        resp.raise_for_status()
    except Exception as e:
        return {"success": False, "msg": f"Emby API调用失败: {e}"}, 500
    
    db.execute('UPDATE user_registrations SET emby_password = ? WHERE emby_username = ?', (new_password, emby_username))
    db.commit()
    return {"success": True, "new_password": new_password}

@bp.route('/emby', methods=['GET', 'POST'])
def emby_register():
    error_msg_template = "您使用的注册链接无效、已被篡改或已过期。"
    full_token_str = request.form.get('token') if request.method == 'POST' else request.args.get('token')
    
    if 'linuxdo_user_id' in session:
        return linuxdo_register()
    
    if not full_token_str:
        return render_template('error.html', error_message="链接不完整，缺少参数。")
    token_payload = _verify_signed_token(full_token_str)
    if not token_payload:
        return render_template('error.html', error_message=error_msg_template)
    db = get_db()
    token_data = db.execute('SELECT * FROM tokens WHERE token = ? AND is_used = 0', (token_payload,)).fetchone()
    if not token_data:
        return render_template('error.html', error_message=error_msg_template)
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        if not re.match(r'^[a-zA-Z0-9]{4,32}$', username):
            return render_template('register.html', token=full_token_str, error="用户名不合法：长度需为4-32位，且只能包含英文字母和数字。")
        
        password = ''.join(secrets.choice(string.digits) for _ in range(12))
        user_id, error_msg = create_emby_user(username, password)
        if not user_id:
            return render_template('register.html', token=full_token_str, error=error_msg)
        
        db.execute(
            'UPDATE tokens SET is_used = 1, registered_username = ? WHERE id = ?',
            (username, token_data['id'])
        )
        db.execute(
            'INSERT INTO user_registrations (linuxdo_user_id, emby_username, emby_user_id, emby_password) VALUES (?, ?, ?, ?)',
            (None, username, user_id, password)
        )
        db.commit()
        
        return render_template('success.html', username=username, password=password, emby_url=current_app.config['EMBY_SERVER_URL'])
    
    return render_template('register.html', token=full_token_str)

def linuxdo_register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        if not re.match(r'^[a-zA-Z0-9]{4,32}$', username):
            return render_template('linuxdo_register.html', error="用户名不合法：长度需为4-32位，且只能包含英文字母和数字。")
        
        if not can_user_register(session['linuxdo_user_id'], session['linuxdo_trust_level']):
            current_count = get_user_registration_count(session['linuxdo_user_id'])
            max_allowed = current_app.config['TRUST_LEVEL_LIMITS'].get(session['linuxdo_trust_level'], 1)
            return render_template('linuxdo_register.html', 
                                error=f"您已达到注册上限。当前已注册 {current_count} 个账号，最多可注册 {max_allowed} 个账号。")
        
        db = get_db()
        existing_user = db.execute(
            'SELECT emby_username FROM user_registrations WHERE emby_username = ?',
            (username,)
        ).fetchone()
        if existing_user:
            return render_template('linuxdo_register.html', error="该用户名已被使用，请选择其他用户名。")
        
        password = ''.join(secrets.choice(string.digits) for _ in range(12))
        user_id, error_msg = create_emby_user(username, password)
        if not user_id:
            return render_template('linuxdo_register.html', error=error_msg)
        
        db.execute(
            'INSERT INTO user_registrations (linuxdo_user_id, emby_username, emby_user_id, emby_password) VALUES (?, ?, ?, ?)',
            (session['linuxdo_user_id'], username, user_id, password)
        )
        db.commit()
        
        return render_template('linuxdo_success.html', 
                             username=username, 
                             password=password, 
                             emby_url=current_app.config['EMBY_SERVER_URL'],
                             user_name=session['linuxdo_name'])
    
    return render_template('linuxdo_register.html') 

@bp.route('/rss')
def public_rss():
    db = get_db()
    from datetime import datetime, timedelta
    time_limit = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')
    requests = db.execute(
        'SELECT show_name, douban_url, poster_image_url, requested_at FROM requests WHERE requested_at > ? ORDER BY requested_at DESC',
        (time_limit,)
    ).fetchall()
    from email.utils import formatdate
    rss_items = []
    for req in requests:
        item = f'''
        <item>
            <title>{req['show_name']}</title>
            <description></description>
            <link>{req['douban_url']}</link>
            <guid isPermaLink="false">{req['douban_url']}</guid>
        </item>
        '''
        rss_items.append(item)
    rss = f'''<?xml version="1.0" encoding="UTF-8"?>
<rss xmlns:atom="http://www.w3.org/2005/Atom" version="2.0">
<channel>
<title>视频订阅</title>
<link>{request.url_root.rstrip('/')}/rss</link>
<atom:link href="{request.url}" rel="self" type="application/rss+xml"/>
<description></description>
<generator>EmbyRegisterService</generator>
<webMaster>admin@example.com</webMaster>
<language>zh-CN</language>
<lastBuildDate>{formatdate(localtime=True)}</lastBuildDate>
<ttl>5</ttl>
{''.join(rss_items)}
</channel>
</rss>'''
    return Response(rss, mimetype='application/rss+xml') 