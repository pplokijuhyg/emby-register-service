import sqlite3
import os
from flask import current_app, g

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    with current_app.open_resource('schema.sql') as f:
        db.executescript(f.read().decode('utf8'))

def init_app(app):
    app.teardown_appcontext(close_db)
    # Here you can also add a CLI command to init the DB
    # For now, we will call init_db manually or before the first request.
    with app.app_context():
        # Ensure the instance folder exists
        try:
            os.makedirs(os.path.dirname(current_app.config['DATABASE']))
        except OSError:
            pass
        
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

        # 创建剧集申请表
        cursor.execute(
            '''
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                show_name TEXT NOT NULL,
                douban_url TEXT NOT NULL,
                douban_id TEXT NOT NULL,
                poster_image_url TEXT,
                requested_by_user_id INTEGER NOT NULL,
                requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'pending',
                FOREIGN KEY (requested_by_user_id) REFERENCES linuxdo_users (id),
                UNIQUE(douban_id)
            )
            '''
        )

        # 创建投票表
        cursor.execute(
            '''
            CREATE TABLE IF NOT EXISTS votes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                request_id INTEGER NOT NULL,
                voted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, request_id),
                FOREIGN KEY (user_id) REFERENCES linuxdo_users (id),
                FOREIGN KEY (request_id) REFERENCES requests (id)
            )
            '''
        )

        db.commit()


def get_user_registration_count(user_id):
    """获取用户已注册的账号数量"""
    db = get_db()
    count = db.execute(
        'SELECT COUNT(*) FROM user_registrations WHERE linuxdo_user_id = ?',
        (user_id,)
    ).fetchone()[0]
    return count

def can_user_register(user_id, trust_level):
    """检查用户是否可以注册新账号"""
    from .config import Config
    current_count = get_user_registration_count(user_id)
    max_allowed = Config.TRUST_LEVEL_LIMITS.get(trust_level, 1)
    return current_count < max_allowed 