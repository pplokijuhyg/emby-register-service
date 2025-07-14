# Linux.do OAuth2 登录功能

本项目已集成 Linux.do 论坛的 OAuth2 登录功能，用户可以使用论坛账号登录并注册 Emby 账号。

## 功能特性

- 🔐 使用 Linux.do 论坛账号登录
- 📊 根据论坛信任等级分配注册权限
- 📝 记录用户注册历史
- 🛡️ 防止账号滥用
- 📱 响应式界面设计
- 🔒 使用 Authlib 标准 OAuth2 客户端库
- 🛡️ 内置 CSRF 保护和状态验证

## 信任等级权限分配

| 信任等级 | 可注册账号数量 | 说明 |
|---------|---------------|------|
| 0级 | 1个 | 新用户 |
| 1级 | 2个 | 基础用户 |
| 2级 | 3个 | 活跃用户 |
| 3级 | 5个 | 资深用户 |
| 4级 | 10个 | 高级用户 |

## 环境变量配置

### 必需的环境变量

```bash
# 启用 Linux.do OAuth2 功能
LINUXDO_OAUTH_ENABLED=true

# Linux.do OAuth2 配置
LINUXDO_CLIENT_ID=your_client_id
LINUXDO_CLIENT_SECRET=your_client_secret
LINUXDO_REDIRECT_URI=https://your-domain.com/oauth2/callback

# 网络配置（如果需要代理）
USE_PROXY=true
PROXY_HOST=127.0.0.1
PROXY_PORT=10808
DISABLE_SSL_VERIFY=true

# 其他必需的环境变量
FLASK_SECRET_KEY=your_secret_key
ADMIN_PASSWORD=your_admin_password
EMBY_SERVER_URL=https://your-emby-server.com
EMBY_API_KEY=your_emby_api_key
COPY_FROM_USER_ID=your_template_user_id
PUBLIC_ACCESS_URL=https://your-domain.com
```

### 测试配置

如果只是想测试功能，可以使用以下测试配置：

```bash
LINUXDO_OAUTH_ENABLED=true
LINUXDO_CLIENT_ID=hi3geJYfTotoiR5S62u3rh4W5tSeC5UG
LINUXDO_CLIENT_SECRET=VMPBVoAfOB5ojkGXRDEtzvDhRLENHpaN
LINUXDO_REDIRECT_URI=https://your-domain.com/oauth2/callback

# 如果需要代理
USE_PROXY=true
PROXY_HOST=127.0.0.1
PROXY_PORT=10808
DISABLE_SSL_VERIFY=true
```

## 数据库结构

系统会自动创建以下数据表：

### linuxdo_users 表
存储 Linux.do 用户信息：
- `id`: 主键
- `linuxdo_id`: Linux.do 用户ID
- `username`: 用户名
- `name`: 昵称
- `trust_level`: 信任等级 (0-4)
- `email`: 邮箱
- `avatar_url`: 头像URL
- `created_at`: 创建时间
- `last_login`: 最后登录时间

### user_registrations 表
记录用户注册历史：
- `id`: 主键
- `linuxdo_user_id`: 关联的 Linux.do 用户ID
- `emby_username`: 注册的 Emby 用户名
- `emby_user_id`: Emby 用户ID
- `registered_at`: 注册时间

## 使用流程

1. **用户访问**: 用户访问网站首页
2. **选择登录方式**: 
   - 使用 Linux.do 账号登录（推荐）
   - 使用管理员密码登录
3. **OAuth2 授权**: 跳转到 Linux.do 进行授权
4. **获取用户信息**: 系统获取用户的信任等级等信息
5. **注册账号**: 根据信任等级限制注册数量
6. **管理账号**: 用户可以在仪表板查看注册历史

## 管理员功能

管理员可以在后台管理页面查看：

### Token 管理
- 生成新的注册 Token
- 导出未使用的 Token
- 查看 Token 使用情况
- 删除 Token

### Linux.do 用户管理
- 查看所有 Linux.do 用户
- 查看用户信任等级
- 查看用户注册数量
- 查看用户注册历史

## API 端点

### OAuth2 相关
- `GET /linuxdo/login` - 启动 Linux.do 登录
- `GET /oauth2/callback` - OAuth2 回调处理
- `GET /linuxdo/logout` - 退出登录

### 用户功能
- `GET /linuxdo/dashboard` - 用户仪表板
- `GET /emby` - 注册页面（支持 Token 和 OAuth2 两种方式）

## 安全特性

- ✅ CSRF 保护（使用 state 参数）
- ✅ 会话管理
- ✅ 用户权限验证
- ✅ 注册数量限制
- ✅ 用户名唯一性检查
- ✅ 使用 Authlib 标准 OAuth2 库
- ✅ 自动处理令牌刷新
- ✅ 安全的令牌存储

## 故障排除

### 常见问题

1. **OAuth2 回调失败**
   - 检查 `LINUXDO_REDIRECT_URI` 是否正确
   - 确保域名在 Linux.do 应用配置中已注册

2. **用户信息获取失败**
   - 检查网络连接
   - 验证 `LINUXDO_CLIENT_ID` 和 `LINUXDO_CLIENT_SECRET`

3. **SSL证书验证失败**
   - 如果使用代理，设置 `DISABLE_SSL_VERIFY=true`
   - 设置 `USE_PROXY=true` 并配置代理地址
   - 检查代理服务器是否正常工作

4. **数据库错误**
   - 确保数据库目录有写入权限
   - 检查数据库文件是否损坏

### 日志查看

查看应用日志以获取详细错误信息：

```bash
docker logs your-container-name
```

## 开发说明

### 添加新的信任等级限制

修改 `app.py` 中的 `TRUST_LEVEL_LIMITS` 字典：

```python
TRUST_LEVEL_LIMITS = {
    0: 1,   # 0级用户只能注册1个账号
    1: 2,   # 1级用户可以注册2个账号
    2: 3,   # 2级用户可以注册3个账号
    3: 5,   # 3级用户可以注册5个账号
    4: 10,  # 4级用户可以注册10个账号
    5: 15   # 新增5级用户可注册15个账号
}
```

### 自定义用户信息字段

如果需要获取更多用户信息，可以修改 `get_linuxdo_user_info` 函数和数据库结构。

## 许可证

本项目遵循原有项目的许可证。 