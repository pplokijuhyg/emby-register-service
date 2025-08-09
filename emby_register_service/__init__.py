import os
import urllib3
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix
from .config import Config
from . import database
from .routes import bp, oauth
from . import scheduler

# 禁用SSL证书验证警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    
    # 添加代理修复中间件
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_object(Config)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # Initialize extensions
    database.init_app(app)
    oauth.init_app(app)

    # Register Linux.do OAuth client
    if app.config.get('LINUXDO_OAUTH_ENABLED'):
        session_kwargs = {}
        if app.config.get('USE_PROXY'):
            proxy_url = f"http://{app.config['PROXY_HOST']}:{app.config['PROXY_PORT']}"
            session_kwargs['proxies'] = {'http': proxy_url, 'https': proxy_url}
        
        if app.config.get('DISABLE_SSL_VERIFY'):
            session_kwargs['verify'] = False
            
        oauth.register(
            name='linuxdo',
            client_id=app.config['LINUXDO_CLIENT_ID'],
            client_secret=app.config['LINUXDO_CLIENT_SECRET'],
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
    
    # Register blueprint
    app.register_blueprint(bp)
    
    # Initialize scheduler for cleanup tasks
    scheduler.init_scheduler(app)

    return app 