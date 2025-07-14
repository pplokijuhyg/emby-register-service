#!/usr/bin/env python3
"""
Authlib OAuth2 配置测试脚本
"""

import os
import sys
from authlib.integrations.requests_client import OAuth2Session

def test_oauth_config():
    """测试OAuth2配置"""
    print("=== Authlib OAuth2 配置测试 ===\n")
    
    # 测试配置
    client_id = "hi3geJYfTotoiR5S62u3rh4W5tSeC5UG"
    client_secret = "VMPBVoAfOB5ojkGXRDEtzvDhRLENHpaN"
    redirect_uri = "http://localhost:5000/oauth2/callback"
    authorize_url = "https://connect.linux.do/oauth2/authorize"
    token_url = "https://connect.linux.do/oauth2/token"
    api_base_url = "https://connect.linux.do/"
    
    # 代理配置
    use_proxy = os.getenv('USE_PROXY', 'false').lower() == 'true'
    proxy_host = os.getenv('PROXY_HOST', '127.0.0.1')
    proxy_port = os.getenv('PROXY_PORT', '10808')
    disable_ssl_verify = os.getenv('DISABLE_SSL_VERIFY', 'true').lower() == 'true'
    
    print(f"客户端ID: {client_id}")
    print(f"重定向URI: {redirect_uri}")
    print(f"使用代理: {use_proxy}")
    print(f"禁用SSL验证: {disable_ssl_verify}")
    
    if use_proxy:
        proxy_url = f"http://{proxy_host}:{proxy_port}"
        print(f"代理地址: {proxy_url}")
    
    print("\n1. 创建OAuth2会话...")
    
    # 创建OAuth2会话
    session_kwargs = {}
    if use_proxy:
        session_kwargs['proxies'] = {
            'http': f"http://{proxy_host}:{proxy_port}",
            'https': f"http://{proxy_host}:{proxy_port}"
        }
    
    if disable_ssl_verify:
        session_kwargs['verify'] = False
    
    try:
        oauth = OAuth2Session(
            client_id,
            redirect_uri=redirect_uri,
            scope='read',
            **session_kwargs
        )
        print("   ✅ OAuth2会话创建成功")
    except Exception as e:
        print(f"   ❌ OAuth2会话创建失败: {e}")
        return
    
    print("\n2. 生成授权URL...")
    try:
        authorization_url, state = oauth.create_authorization_url(authorize_url)
        print(f"   ✅ 授权URL生成成功")
        print(f"   授权URL: {authorization_url}")
        print(f"   状态参数: {state}")
    except Exception as e:
        print(f"   ❌ 授权URL生成失败: {e}")
        return
    
    print("\n3. 测试配置完成")
    print("   请在浏览器中访问上述授权URL进行测试")
    print("   授权成功后，系统会自动处理回调")

def test_environment():
    """测试环境配置"""
    print("=== 环境配置测试 ===\n")
    
    required_vars = [
        'LINUXDO_OAUTH_ENABLED',
        'LINUXDO_CLIENT_ID', 
        'LINUXDO_CLIENT_SECRET',
        'LINUXDO_REDIRECT_URI',
        'USE_PROXY',
        'PROXY_HOST',
        'PROXY_PORT',
        'DISABLE_SSL_VERIFY'
    ]
    
    for var in required_vars:
        value = os.getenv(var, 'NOT_SET')
        status = "✅" if value != 'NOT_SET' else "❌"
        print(f"{status} {var}: {value}")
    
    print(f"\n=== 环境测试完成 ===")

if __name__ == "__main__":
    print("Authlib OAuth2 配置测试工具\n")
    
    while True:
        print("请选择测试项目:")
        print("1. 测试环境配置")
        print("2. 测试OAuth2配置")
        print("3. 退出")
        print("请输入选择 (1-3): ", end="")
        
        try:
            choice = input().strip()
            if choice == "1":
                test_environment()
            elif choice == "2":
                test_oauth_config()
            elif choice == "3":
                print("退出测试")
                break
            else:
                print("无效选择，请重新输入")
        except KeyboardInterrupt:
            print("\n退出测试")
            break
        
        print("\n" + "="*50 + "\n") 