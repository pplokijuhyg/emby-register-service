### 这个工具是我使用Google Gemini 2.5写出来的，只是能用的水平，方便分享自己的emby服务给朋友去注册

### 功能特性

- 🔐 **Token 注册**: 传统的 Token 注册方式
- 🔑 **Linux.do OAuth2 登录**: 使用 Linux.do 论坛账号登录（新功能）
- 📊 **权限管理**: 根据论坛信任等级分配注册权限
- 📝 **注册历史**: 记录用户注册历史
- 🛡️ **防滥用**: 防止账号滥用

### 使用方法

#### 1. 构建和部署

进入代码目录自己构建出docker镜像： `docker build -t emby-register-service .` 然后参考下面的示例编写docker-compose.yml。 如果你不想自己从代码构建，也可以用我构建好的镜像 guowanghushifu/emby-register-service

#### 2. 生成密钥

找台安装了python的机器执行 `python3 -c "import secrets; print(secrets.token_hex(32))"` 生成签名的密钥填到 FLASK_SECRET_KEY 环境变量

#### 3. 配置环境变量

修改docker-compose.yml中的其他环境变量：

**基础配置：**
- `PUBLIC_ACCESS_URL`: 你这个docker的公网访问地址，如果非标准端口，一起写上，例如 https://your-domain.com:18080
- `ADMIN_PASSWORD`：你的管理员密码，不要用弱密码
- `EMBY_SERVER_URL`：EMBY服务器的地址，如果非标准端口，一起写上，例如 https://emby.your-domain.com:8920
- `EMBY_API_KEY`：和EMBY服务器交互的时候需要用到的API，去emby服务器管理面板里面申请
- `COPY_FROM_USER_ID`：从模板用户复制emby参数，这里填写他的ID，看如下说明

**Linux.do OAuth2 配置（可选）：**
- `LINUXDO_OAUTH_ENABLED=true`：启用 Linux.do OAuth2 功能
- `LINUXDO_CLIENT_ID`：Linux.do OAuth2 客户端ID
- `LINUXDO_CLIENT_SECRET`：Linux.do OAuth2 客户端密钥
- `LINUXDO_REDIRECT_URI`：回调地址，通常为 `https://your-domain.com/oauth2/callback`

**网络配置（可选）：**
- `USE_PROXY=false`：是否使用代理（true/false）
- `PROXY_HOST=127.0.0.1`：代理服务器地址
- `PROXY_PORT=10808`：代理服务器端口
- `DISABLE_SSL_VERIFY=true`：是否禁用SSL证书验证（true/false）

#### 4. 配置模板用户

先去emby里面创建一个模板用户，注意不要给他管理权限!!!，把这个用户的各项参数配置好，例如他是否能看所有的库，是否能转码，是否能删除文件等；然后在控制台用户管理那里点这个用户，浏览器地址栏会显示这样的一串（举例）：https://emby.your-domain.com:8920/web/index.html#!/users/user?userId=a22935174ac24711aa54f84999999⁠ ，把userId= 这后面的这串代码a22935174ac24711aa54f84999999拷贝出来，写到 COPY_FROM_USR_ID 这个环境变量

#### 5. 访问服务

浏览器访问 PUBLIC_ACCESS_URL：
- 如果启用了 Linux.do OAuth2，会跳转到 Linux.do 登录页面
- 如果未启用，会显示管理员登录页面

### docker-compose.yml 示例

#### 基础配置（仅 Token 注册）
```yaml
services:
    emby-register-service:
        ports:
            - 18080:5000
        volumes:
            - ./data:/app/data
        container_name: my-emby-register-app
        environment:
            - FLASK_SECRET_KEY=54a7a4e7d286d13dbf610f14677d11290dede4eb8f0f20f01f3b57b109530f8d
            - PUBLIC_ACCESS_URL=https://your-reg-domain.com
            - ADMIN_PASSWORD=your_admin_password
            - EMBY_SERVER_URL=https://emby.your-domain.com:8920
            - EMBY_API_KEY=your_api_key
            - COPY_FROM_USER_ID=your_template_user_id
        restart: unless-stopped
        image: emby-register-service
        # image: guowanghushifu/emby-register-service
```

#### 完整配置（包含 Linux.do OAuth2）
```yaml
services:
    emby-register-service:
        ports:
            - 18080:5000
        volumes:
            - ./data:/app/data
        container_name: my-emby-register-app
        environment:
            - FLASK_SECRET_KEY=54a7a4e7d286d13dbf610f14677d11290dede4eb8f0f20f01f3b57b109530f8d
            - PUBLIC_ACCESS_URL=https://your-reg-domain.com
            - ADMIN_PASSWORD=your_admin_password
            - EMBY_SERVER_URL=https://emby.your-domain.com:8920
            - EMBY_API_KEY=your_api_key
            - COPY_FROM_USER_ID=your_template_user_id
            # Linux.do OAuth2 配置
            - LINUXDO_OAUTH_ENABLED=true
            - LINUXDO_CLIENT_ID=your_client_id
            - LINUXDO_CLIENT_SECRET=your_client_secret
            - LINUXDO_REDIRECT_URI=https://your-reg-domain.com/oauth2/callback
            # 网络配置（如果需要代理）
            - USE_PROXY=true
            - PROXY_HOST=127.0.0.1
            - PROXY_PORT=10808
            - DISABLE_SSL_VERIFY=true
        restart: unless-stopped
        image: emby-register-service
        # image: guowanghushifu/emby-register-service
```

### Token管理界面
![PixPin_2025-06-08_16-24-41.png](https://image.dooo.ng/c/2025/06/08/68454b033e0d3.webp)

### 用户注册界面
![PixPin_2025-06-08_16-25-49.png](https://image.dooo.ng/c/2025/06/08/68454b02d33ec.webp)

### Linux.do OAuth2 功能

#### 信任等级权限分配

| 信任等级 | 可注册账号数量 | 说明 |
|---------|---------------|------|
| 0级 | 1个 | 新用户 |
| 1级 | 2个 | 基础用户 |
| 2级 | 3个 | 活跃用户 |
| 3级 | 5个 | 资深用户 |
| 4级 | 10个 | 高级用户 |

#### 使用流程

1. **用户访问**: 用户访问网站首页
2. **Linux.do 登录**: 点击"使用 Linux.do 账号登录"
3. **OAuth2 授权**: 跳转到 Linux.do 进行授权
4. **获取用户信息**: 系统获取用户的信任等级等信息
5. **注册账号**: 根据信任等级限制注册数量
6. **管理账号**: 用户可以在仪表板查看注册历史

#### 管理员功能

管理员可以在后台管理页面查看：

- **Token 管理**: 传统的 Token 管理功能
- **Linux.do 用户管理**: 查看所有 Linux.do 用户、信任等级、注册数量等

#### 详细文档

更多详细信息请参考 [Linux.do OAuth2 功能文档](LINUXDO_OAUTH_README.md)。

