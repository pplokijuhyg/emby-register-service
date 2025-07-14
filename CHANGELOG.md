# 更新日志

## [2.0.0] - 2024-12-19

### 新增功能

#### 🔑 Linux.do OAuth2 登录系统
- 集成 Linux.do 论坛的 OAuth2 登录功能
- 用户可以使用论坛账号登录并注册 Emby 账号
- 根据论坛信任等级分配注册权限
- 使用 Authlib 标准 OAuth2 客户端库
- 内置 CSRF 保护和状态验证

#### 📊 权限管理系统
- 0级用户：1个账号
- 1级用户：2个账号  
- 2级用户：3个账号
- 3级用户：5个账号
- 4级用户：10个账号

#### 📝 用户管理功能
- 用户仪表板：查看个人信息和注册历史
- 注册历史记录：记录所有注册的 Emby 账号
- 权限检查：防止超出注册限制

#### 🛡️ 安全特性
- CSRF 保护（使用 state 参数）
- 会话管理
- 用户权限验证
- 注册数量限制
- 用户名唯一性检查
- 使用 Authlib 标准 OAuth2 库
- 自动处理令牌刷新
- 安全的令牌存储

### 数据库更新

#### 新增数据表
- `linuxdo_users`: 存储 Linux.do 用户信息
- `user_registrations`: 记录用户注册历史

#### 数据表结构
```sql
-- linuxdo_users 表
CREATE TABLE linuxdo_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    linuxdo_id INTEGER UNIQUE NOT NULL,
    username TEXT NOT NULL,
    name TEXT,
    trust_level INTEGER DEFAULT 0,
    email TEXT,
    avatar_url TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- user_registrations 表
CREATE TABLE user_registrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    linuxdo_user_id INTEGER,
    emby_username TEXT NOT NULL,
    emby_user_id TEXT,
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (linuxdo_user_id) REFERENCES linuxdo_users (id)
);
```

### 新增路由

#### OAuth2 相关
- `GET /linuxdo/login` - 启动 Linux.do 登录
- `GET /oauth2/callback` - OAuth2 回调处理
- `GET /linuxdo/logout` - 退出登录

#### 用户功能
- `GET /linuxdo/dashboard` - 用户仪表板
- `GET /emby` - 注册页面（支持 Token 和 OAuth2 两种方式）

### 新增模板文件

- `templates/linuxdo_login.html` - Linux.do 登录页面
- `templates/linuxdo_dashboard.html` - 用户仪表板
- `templates/linuxdo_register.html` - Linux.do 用户注册页面
- `templates/linuxdo_success.html` - 注册成功页面

### 环境变量

#### 新增环境变量
- `LINUXDO_OAUTH_ENABLED` - 启用 Linux.do OAuth2 功能
- `LINUXDO_CLIENT_ID` - Linux.do OAuth2 客户端ID
- `LINUXDO_CLIENT_SECRET` - Linux.do OAuth2 客户端密钥
- `LINUXDO_REDIRECT_URI` - 回调地址

### 管理员功能增强

#### 后台管理页面
- 添加标签页导航
- 新增 Linux.do 用户管理标签页
- 显示用户信任等级和注册数量
- 查看用户注册历史

### 文档更新

- 更新 `readme.md` 添加新功能说明
- 新增 `LINUXDO_OAUTH_README.md` 详细文档
- 新增 `test_oauth.py` 测试脚本
- 新增 `CHANGELOG.md` 更新日志

### 兼容性

- 保持原有 Token 注册功能完全兼容
- 向后兼容所有现有配置
- 可选启用 OAuth2 功能

### 测试

- 添加 OAuth2 流程测试脚本
- 环境配置验证
- 用户信息获取测试

---

## [1.0.0] - 2024-06-08

### 初始版本
- Token 注册系统
- 管理员后台
- Emby 用户创建
- CSV 导出功能 