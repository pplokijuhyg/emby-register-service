# 1. 使用官方的Python轻量级镜像作为基础
FROM python:3.11-slim

# 2. 设置工作目录
WORKDIR /app

# 3. 设置环境变量，防止Python写入.pyc文件
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# 4. 复制依赖文件并安装依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 5. 复制所有应用代码到工作目录
COPY . .

# 6. 暴露端口
EXPOSE 5000

# 7. 容器启动时运行的命令
CMD ["gunicorn", "--worker-class", "gevent", "--workers", "4", "--bind", "0.0.0.0:5000", "app:app"]