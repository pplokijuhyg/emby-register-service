# Emby Register Service

一个基于 Flask 的 Emby 注册与剧集申请管理平台，支持 Linux.do OAuth 登录、Emby 用户注册、邀请码管理、剧集申请、投票、管理员后台等功能。

## 主要功能

- **Emby 用户注册**：支持邀请码注册和 Linux.do OAuth 登录注册。
- **邀请码管理**：管理员可批量生成、导出、删除邀请码。
- **剧集申请**：用户可通过豆瓣链接一键申请新剧集，系统自动抓取剧集名和海报。
- **投票系统**：每个用户可为感兴趣的剧集投票（想看+1），每人每剧集仅能投一票。
- **剧集去重**：同一豆瓣剧集只允许申请一次，后续用户可直接投票。
- **剧集申请自动清理**：2个月前的申请自动删除。
- **管理员后台**：支持剧集申请管理、状态变更、删除、筛选、按投票数排序等。
- **公开 RSS 接口**：/rss 路由输出剧集申请列表，支持 RSS 订阅。
- **支持 Docker 部署**，支持热更新开发。

## 环境变量说明

| 变量名              | 说明                                   |
|---------------------|----------------------------------------|
| FLASK_SECRET_KEY    | Flask 会话密钥，必须设置               |
| ADMIN_PASSWORD      | 管理员登录密码，必须设置               |
| EMBY_SERVER_URL     | Emby 服务器地址                        |
| EMBY_API_KEY        | Emby API 密钥                          |
| COPY_FROM_USER_ID   | Emby 模板用户 ID                       |
| PUBLIC_ACCESS_URL   | 服务对外访问的完整 URL                 |
| LINUXDO_OAUTH_ENABLED | 是否启用 Linux.do OAuth 登录（true/false）|
| LINUXDO_CLIENT_ID   | Linux.do OAuth Client ID               |
| LINUXDO_CLIENT_SECRET | Linux.do OAuth Client Secret           |
| DOUBAN_COOKIES      | 抓取豆瓣页面时附加的 Cookie（可选）     |

## 主要路由

- `/`：首页，自动跳转到登录或仪表盘
- `/login`：管理员登录
- `/linuxdo/login`：Linux.do OAuth 登录
- `/linuxdo/dashboard`：用户仪表盘
- `/requests`：剧集申请与投票页面
- `/admin`：管理员后台
- `/admin/requests`：剧集申请管理
- `/rss`：公开的剧集申请 RSS 订阅接口

## 快速开始

1. 配置 `.env` 文件，填写所有必需环境变量。
2. 构建并运行 Docker 容器：
   ```sh
   docker build -t emby-register-service .
   docker run -p 5000:5000 --env-file .env -v "${pwd}:/app" emby-register-service
   ```
3. 访问 `http://localhost:5000` 开始使用。

## 特色说明

- 剧集申请只需填写豆瓣链接，系统自动抓取剧集名和图片。
- 支持剧集投票，按“想看”数量排序。
- 管理员可筛选、删除、变更剧集申请状态。
- 2个月前的申请自动清理。
- 支持 RSS 订阅聚合。

---

如需定制开发或遇到问题，欢迎联系维护者！

