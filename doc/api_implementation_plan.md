# API密钥管理功能实现计划

## 1. 现有/request接口分析

现有的/request接口（位于routes.py第158-252行）主要功能包括：
1. 接收豆瓣URL
2. 提取豆瓣ID
3. 抓取豆瓣页面信息（标题、图片）
4. 限制每人每天只能申请一部剧
5. 检查是否已存在相同剧集，如果存在则自动投票
6. 将新剧集申请存入数据库

## 2. API密钥管理系统设计

### 数据库表设计

需要在database.py的init_app函数中添加一个新的`api_keys`表：

```sql
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used TIMESTAMP,
    is_active BOOLEAN DEFAULT 1,
    request_count INTEGER DEFAULT 0
)
```

### API接口设计

新API接口将类似于现有的/request接口，但使用API密钥进行验证：
- 路径：`/api/request`
- 方法：POST
- 参数：
  - `api_key`: API密钥（可以通过Header或参数传递）
  - `douban_url`: 豆瓣URL
- 返回：JSON格式的响应，包含成功/失败信息和相关数据

### 管理界面设计

在admin页面添加一个新的标签页用于API密钥管理，包括：
- 生成新API密钥
- 查看所有API密钥列表
- 激活/停用API密钥
- 删除API密钥
- 查看API密钥使用统计

## 3. 实现步骤

### 步骤1：修改database.py
- 在init_app函数中添加api_keys表的创建代码
- 添加API密钥相关的数据库操作函数：
  - `create_api_key(name, description)`: 创建新API密钥
  - `get_api_key(key)`: 获取API密钥信息
  - `update_api_key_usage(key)`: 更新API密钥使用记录
  - `get_all_api_keys()`: 获取所有API密钥
  - `toggle_api_key_status(key_id)`: 切换API密钥状态
  - `delete_api_key(key_id)`: 删除API密钥

### 步骤2：修改utils.py
- 添加API密钥生成和验证函数：
  - `generate_api_key()`: 生成随机API密钥
  - `validate_api_key(key)`: 验证API密钥有效性

### 步骤3：修改routes.py
- 添加新的API路由：
  - `/api/request`: 处理豆瓣订阅请求
- 添加API密钥管理路由：
  - `/admin/api_keys`: API密钥管理页面
  - `/admin/api_keys/generate`: 生成新API密钥
  - `/admin/api_keys/toggle/<int:key_id>`: 切换API密钥状态
  - `/admin/api_keys/delete/<int:key_id>`: 删除API密钥

### 步骤4：修改admin.html
- 添加API密钥管理标签页
- 添加API密钥列表显示
- 添加API密钥操作按钮

### 步骤5：创建新的模板文件
- 创建`admin_api_keys.html`模板文件

## 4. 代码实现细节

### database.py修改

在init_app函数中添加api_keys表创建代码（第133行后）：

```python
# 创建API密钥表
cursor.execute(
    '''
    CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_used TIMESTAMP,
        is_active BOOLEAN DEFAULT 1,
        request_count INTEGER DEFAULT 0
    )
    '''
)
```

添加API密钥相关函数：

```python
def create_api_key(name, description=None):
    """创建新API密钥"""
    import secrets
    db = get_db()
    key = f"emby_{secrets.token_urlsafe(32)}"
    cursor = db.execute(
        'INSERT INTO api_keys (key, name, description) VALUES (?, ?, ?)',
        (key, name, description)
    )
    db.commit()
    return cursor.lastrowid, key

def get_api_key(key):
    """获取API密钥信息"""
    db = get_db()
    return db.execute('SELECT * FROM api_keys WHERE key = ?', (key,)).fetchone()

def update_api_key_usage(key):
    """更新API密钥使用记录"""
    db = get_db()
    db.execute(
        'UPDATE api_keys SET last_used = CURRENT_TIMESTAMP, request_count = request_count + 1 WHERE key = ?',
        (key,)
    )
    db.commit()

def get_all_api_keys():
    """获取所有API密钥"""
    db = get_db()
    return db.execute('SELECT * FROM api_keys ORDER BY created_at DESC').fetchall()

def toggle_api_key_status(key_id):
    """切换API密钥状态"""
    db = get_db()
    db.execute(
        'UPDATE api_keys SET is_active = NOT is_active WHERE id = ?',
        (key_id,)
    )
    db.commit()

def delete_api_key(key_id):
    """删除API密钥"""
    db = get_db()
    db.execute('DELETE FROM api_keys WHERE id = ?', (key_id,))
    db.commit()
```

### utils.py修改

添加API密钥生成和验证函数：

```python
def generate_api_key():
    """生成随机API密钥"""
    import secrets
    return f"emby_{secrets.token_urlsafe(32)}"

def validate_api_key(key):
    """验证API密钥有效性"""
    from .database import get_api_key
    api_key = get_api_key(key)
    if api_key and api_key['is_active']:
        return True
    return False
```

### routes.py修改

添加新的API路由：

```python
@bp.route('/api/request', methods=['POST'])
def api_request():
    """API接口：通过豆瓣链接添加订阅"""
    # 获取API密钥
    api_key = request.headers.get('X-API-Key') or request.form.get('api_key') or request.json.get('api_key')
    
    if not api_key:
        return jsonify({'success': False, 'message': '缺少API密钥'}), 401
    
    # 验证API密钥
    if not validate_api_key(api_key):
        return jsonify({'success': False, 'message': '无效的API密钥'}), 401
    
    # 获取豆瓣URL
    data = request.get_json() if request.is_json else request.form
    douban_url = data.get('douban_url')
    
    if not douban_url:
        return jsonify({'success': False, 'message': '豆瓣地址是必填项'}), 400
    
    # 提取豆瓣ID
    import re
    m = re.search(r'/subject/(\d+)', douban_url)
    douban_id = m.group(1) if m else None
    
    if not douban_id:
        return jsonify({'success': False, 'message': '豆瓣链接格式不正确，无法提取ID'}), 400
    
    # 检查是否已存在相同剧集
    db = get_db()
    exists = db.execute('SELECT id FROM requests WHERE douban_id = ?', (douban_id,)).fetchone()
    
    if exists:
        return jsonify({'success': False, 'message': '该剧集已存在申请记录'}), 400
    
    # 抓取豆瓣页面
    cookies = os.getenv('DOUBAN_COOKIES')
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0',
        'referer': "https://search.douban.com/movie/subject_search?search_text=%E5%BC%82%E4%BA%BA%E4%B9%8B%E4%B8%8B&cat=1002"
    }
    
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
            return jsonify({'success': False, 'message': '无法从豆瓣页面提取剧集名称'}), 400
        
        # 保存到数据库
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        db.execute(
            'INSERT INTO requests (show_name, douban_url, douban_id, poster_image_url, requested_by_user_id, status, requested_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (show_name, douban_url, douban_id, poster_image_url, None, 'approved', current_time)
        )
        db.commit()
        
        # 更新API密钥使用记录
        update_api_key_usage(api_key)
        
        return jsonify({
            'success': True, 
            'message': '剧集申请已提交',
            'data': {
                'show_name': show_name,
                'douban_url': douban_url,
                'douban_id': douban_id,
                'poster_image_url': poster_image_url
            }
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'抓取豆瓣信息失败: {str(e)}'}), 500
```

添加API密钥管理路由：

```python
@bp.route('/admin/api_keys')
@login_required
def admin_api_keys():
    """API密钥管理页面"""
    db = get_db()
    api_keys = db.execute('SELECT * FROM api_keys ORDER BY created_at DESC').fetchall()
    return render_template('admin_api_keys.html', api_keys=api_keys)

@bp.route('/admin/api_keys/generate', methods=['POST'])
@login_required
def generate_api_key():
    """生成新API密钥"""
    name = request.form.get('name')
    description = request.form.get('description')
    
    if not name:
        flash('API密钥名称是必填项', 'danger')
        return redirect(url_for('main.admin_api_keys'))
    
    try:
        key_id, key = create_api_key(name, description)
        flash(f'API密钥已生成：{key}', 'success')
    except Exception as e:
        flash(f'生成API密钥失败：{str(e)}', 'danger')
    
    return redirect(url_for('main.admin_api_keys'))

@bp.route('/admin/api_keys/toggle/<int:key_id>', methods=['POST'])
@login_required
def toggle_api_key(key_id):
    """切换API密钥状态"""
    try:
        toggle_api_key_status(key_id)
        flash('API密钥状态已更新', 'success')
    except Exception as e:
        flash(f'更新API密钥状态失败：{str(e)}', 'danger')
    
    return redirect(url_for('main.admin_api_keys'))

@bp.route('/admin/api_keys/delete/<int:key_id>', methods=['POST'])
@login_required
def delete_api_key_route(key_id):
    """删除API密钥"""
    try:
        delete_api_key(key_id)
        flash('API密钥已删除', 'success')
    except Exception as e:
        flash(f'删除API密钥失败：{str(e)}', 'danger')
    
    return redirect(url_for('main.admin_api_keys'))
```

### admin.html修改

在导航标签中添加API密钥管理标签（第37行后）：

```html
<li class="nav-item" role="presentation">
    <button class="nav-link {{ 'active' if request.args.get('tab') == 'api_keys' else '' }}" 
            id="api-keys-tab" data-bs-toggle="tab" data-bs-target="#api-keys" type="button" role="tab">
        API密钥管理
    </button>
</li>
```

在标签页内容中添加API密钥管理标签页内容（第533行后）：

```html
<!-- API密钥管理标签页 -->
<div class="tab-pane fade {{ 'show active' if request.args.get('tab') == 'api_keys' else '' }}" id="api-keys" role="tabpanel">
    <h5 class="mb-3">API密钥管理</h5>
    
    <!-- 生成新API密钥表单 -->
    <div class="card mb-4">
        <div class="card-header">
            生成新API密钥
        </div>
        <div class="card-body">
            <form method="post" action="{{ url_for('main.generate_api_key') }}">
                <div class="row">
                    <div class="col-md-4">
                        <div class="mb-3">
                            <label for="name" class="form-label">名称*</label>
                            <input type="text" class="form-control" id="name" name="name" required>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="mb-3">
                            <label for="description" class="form-label">描述</label>
                            <input type="text" class="form-control" id="description" name="description">
                        </div>
                    </div>
                    <div class="col-md-2 d-flex align-items-end">
                        <button type="submit" class="btn btn-primary w-100">生成</button>
                    </div>
                </div>
            </form>
        </div>
    </div>
    
    <!-- API密钥列表 -->
    <div class="card">
        <div class="card-header">
            API密钥列表
        </div>
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-striped table-hover align-middle">
                    <thead>
                        <tr>
                            <th scope="col">名称</th>
                            <th scope="col">密钥</th>
                            <th scope="col">描述</th>
                            <th scope="col">创建时间</th>
                            <th scope="col">最后使用</th>
                            <th scope="col">使用次数</th>
                            <th scope="col">状态</th>
                            <th scope="col">操作</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for key in api_keys %}
                        <tr>
                            <td>{{ key.name }}</td>
                            <td>
                                <code>{{ key.key[:20] }}...</code>
                                <button class="btn btn-sm btn-outline-info ms-2" onclick="copyApiKey('{{ key.key }}', this)">
                                    复制
                                </button>
                            </td>
                            <td>{{ key.description or '—' }}</td>
                            <td>{{ key.created_at }}</td>
                            <td>{{ key.last_used or '从未使用' }}</td>
                            <td>{{ key.request_count }}</td>
                            <td>
                                {% if key.is_active %}
                                    <span class="badge bg-success">激活</span>
                                {% else %}
                                    <span class="badge bg-secondary">停用</span>
                                {% endif %}
                            </td>
                            <td>
                                <div class="btn-group" role="group">
                                    <form method="post" action="{{ url_for('main.toggle_api_key', key_id=key.id) }}" class="d-inline">
                                        <button type="submit" class="btn btn-sm {% if key.is_active %}btn-warning{% else %}btn-success{% endif %}">
                                            {% if key.is_active %}停用{% else %}激活{% endif %}
                                        </button>
                                    </form>
                                    <form method="post" action="{{ url_for('main.delete_api_key_route', key_id=key.id) }}" class="d-inline" onsubmit="return confirm('确定要删除这个API密钥吗？');">
                                        <button type="submit" class="btn btn-sm btn-danger">删除</button>
                                    </form>
                                </div>
                            </td>
                        </tr>
                        {% else %}
                        <tr>
                            <td colspan="8" class="text-center">暂无API密钥</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>
```

在JavaScript部分添加复制API密钥的函数（第753行后）：

```javascript
function copyApiKey(key, buttonElement) {
    copyTextToClipboard(key, buttonElement);
}
```

## 5. 使用说明

### API接口使用

1. 请求URL：`POST /api/request`
2. 请求头或参数中需要包含API密钥：
   - Header方式：`X-API-Key: your_api_key`
   - 参数方式：`api_key=your_api_key`
3. 请求体中需要包含豆瓣URL：
   - Form Data：`douban_url=https://movie.douban.com/subject/xxx/`
   - JSON：`{"douban_url": "https://movie.douban.com/subject/xxx/"}`

### 示例请求

```bash
curl -X POST https://your-domain.com/api/request \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key_here" \
  -d '{"douban_url": "https://movie.douban.com/subject/1234567/"}'
```

### 示例响应

成功响应：
```json
{
  "success": true,
  "message": "剧集申请已提交",
  "data": {
    "show_name": "剧集名称",
    "douban_url": "https://movie.douban.com/subject/1234567/",
    "douban_id": "1234567",
    "poster_image_url": "https://img.example.com/poster.jpg"
  }
}
```

错误响应：
```json
{
  "success": false,
  "message": "错误信息"
}
```

## 6. 注意事项

1. API密钥需要妥善保管，不要泄露给无关人员
2. 每个API密钥可以多次使用，系统会记录使用次数和最后使用时间
3. 可以通过admin页面随时停用或删除API密钥
4. API接口与网页版的/request接口功能类似，但不限制每日申请数量

## 7. 错误代码说明

| HTTP状态码 | 错误类型 | 说明 |
|------------|----------|------|
| 401 | 认证失败 | 缺少API密钥或API密钥无效 |
| 400 | 请求错误 | 豆瓣地址格式不正确或缺少必要参数 |
| 500 | 服务器错误 | 抓取豆瓣信息失败或其他服务器内部错误 |

## 8. API密钥管理

### 生成API密钥

1. 登录管理员账号
2. 进入后台管理页面
3. 切换到"API密钥管理"标签页
4. 填写名称和描述（可选），点击"生成"按钮
5. 系统会生成一个新的API密钥，请妥善保存

### 管理API密钥

1. 在API密钥列表中可以查看所有密钥的详细信息
2. 可以通过"激活"/"停用"按钮控制密钥的状态
3. 可以通过"删除"按钮永久删除密钥
4. 可以点击"复制"按钮快速复制密钥

### 监控API密钥使用情况

1. 系统会记录每个API密钥的使用次数和最后使用时间
2. 可以通过这些信息判断API密钥是否被滥用

## 9. 高级用法

### 批量提交请求

可以通过脚本批量提交多个剧集请求：

```bash
#!/bin/bash

API_KEY="your_api_key_here"
API_URL="https://your-domain.com/api/request"

# 豆瓣URL列表
DOUBAN_URLS=(
    "https://movie.douban.com/subject/26752088/"
    "https://movie.douban.com/subject/26893271/"
    "https://movie.douban.com/subject/26934246/"
)

for url in "${DOUBAN_URLS[@]}"; do
    echo "提交: $url"
    response=$(curl -s -X POST "$API_URL" \
        -H "Content-Type: application/json" \
        -H "X-API-Key: $API_KEY" \
        -d "{\"douban_url\": \"$url\"}")
    
    echo "响应: $response"
    echo "------------------------"
done
```

### Python示例

```python
import requests
import json

API_KEY = "your_api_key_here"
API_URL = "https://your-domain.com/api/request"

def submit_request(douban_url):
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY
    }
    data = {
        "douban_url": douban_url
    }
    
    response = requests.post(API_URL, headers=headers, json=data)
    result = response.json()
    
    if result.get("success"):
        print(f"成功提交: {result['data']['show_name']}")
    else:
        print(f"提交失败: {result['message']}")
    
    return result

# 使用示例
submit_request("https://movie.douban.com/subject/26752088/")
```

### JavaScript示例

```javascript
async function submitRequest(doubanUrl, apiKey) {
    const response = await fetch('https://your-domain.com/api/request', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-API-Key': apiKey
        },
        body: JSON.stringify({
            douban_url: doubanUrl
        })
    });
    
    const result = await response.json();
    
    if (result.success) {
        console.log(`成功提交: ${result.data.show_name}`);
    } else {
        console.error(`提交失败: ${result.message}`);
    }
    
    return result;
}

// 使用示例
submitRequest('https://movie.douban.com/subject/26752088/', 'your_api_key_here');
```

## 10. 最佳实践

1. **API密钥安全**：
   - 不要将API密钥硬编码在客户端代码中
   - 定期更换API密钥，特别是怀疑密钥可能已经泄露时
   - 为不同的应用或服务创建不同的API密钥，便于管理和追踪

2. **错误处理**：
   - 始终检查API响应的success字段
   - 实现适当的错误处理和重试机制
   - 记录API调用日志，便于排查问题

3. **请求频率**：
   - 虽然API不限制每日申请数量，但建议合理控制请求频率
   - 避免短时间内大量重复请求相同的剧集

4. **数据验证**：
   - 在提交前验证豆瓣URL的格式
   - 检查剧集是否已经存在，避免重复提交