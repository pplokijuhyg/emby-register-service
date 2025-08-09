import os
from datetime import timedelta

# --- App Initialization ---
class Config:
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY')
    if not SECRET_KEY:
        raise ValueError("错误: 必须设置 FLASK_SECRET_KEY 环境变量! 使用 'python -c \"import secrets; print(secrets.token_hex(32))\"' 生成一个。")
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    
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
    LINUXDO_REDIRECT_URI = os.getenv('LINUXDO_REDIRECT_URI', f'{PUBLIC_ACCESS_URL}/oauth2/callback' if PUBLIC_ACCESS_URL else None)


    # 代理配置
    USE_PROXY = os.getenv('USE_PROXY', 'false').lower() == 'true'
    PROXY_HOST = os.getenv('PROXY_HOST')
    PROXY_PORT = os.getenv('PROXY_PORT')
    DISABLE_SSL_VERIFY = os.getenv('DISABLE_SSL_VERIFY', 'false').lower() == 'true'

    # 根据trust_level设置不同的注册限制
    TRUST_LEVEL_LIMITS = {
        0: 0,   # 0级用户只能注册1个账号
        1: 2,   # 1级用户可以注册2个账号
        2: 3,   # 2级用户可以注册3个账号
        3: 5,   # 3级用户可以注册5个账号
        4: 10   # 4级用户可以注册10个账号
    }

    DATABASE = '/app/data/tokens.db'
    PER_PAGE = 10

    # 检查所有必需的环境变量
    required_vars = {
        'ADMIN_PASSWORD': ADMIN_PASSWORD,
        'EMBY_SERVER_URL': EMBY_SERVER_URL,
        'EMBY_API_KEY': EMBY_API_KEY,
        'COPY_FROM_USER_ID': COPY_FROM_USER_ID,
        'PUBLIC_ACCESS_URL': PUBLIC_ACCESS_URL
    }
    missing_vars = [var for var, value in required_vars.items() if not value]
    if missing_vars:
        raise ValueError(f"错误: 以下环境变量缺失或为空，请检查你的 .env 文件: {', '.join(missing_vars)}")

    # Cookie 安全设置
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = PUBLIC_ACCESS_URL.startswith('https') if PUBLIC_ACCESS_URL else False
    
    # 用户清理功能配置
    ENABLE_USER_CLEANUP = os.getenv('ENABLE_USER_CLEANUP', 'true').lower() == 'true'
    CLEANUP_NEW_USER_DAYS = int(os.getenv('CLEANUP_NEW_USER_DAYS', '7'))  # 新用户未登录天数
    CLEANUP_INACTIVE_USER_DAYS = int(os.getenv('CLEANUP_INACTIVE_USER_DAYS', '30'))  # 用户未活跃天数
    CLEANUP_INTERVAL_HOURS = int(os.getenv('CLEANUP_INTERVAL_HOURS', '24'))  # 清理检查间隔（小时）
    CLEANUP_ONLY_PLATFORM_USERS = os.getenv('CLEANUP_ONLY_PLATFORM_USERS', 'true').lower() == 'true'  # 只删除平台创建的用户
    CLEANUP_ORPHANED_RECORDS = os.getenv('CLEANUP_ORPHANED_RECORDS', 'true').lower() == 'true'  # 清理Emby中不存在的孤儿记录 