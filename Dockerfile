# 1. 使用官方的Python轻量级镜像作为基础
FROM python:3.11-slim

# 2. 设置代理参数
ARG http_proxy
ARG https_proxy

# 3. 设置工作目录
WORKDIR /app


# 5. 复制依赖文件并安装依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN apt-get update && apt-get install -y ca-certificates
# 6. 复制所有应用代码到工作目录
COPY . .

# 7. 安装项目
RUN pip install .

# 8. 暴露端口
EXPOSE 5000

# 9. 设置Flask环境变量
ENV FLASK_APP=emby_register_service

# 10. 运行应用
CMD ["flask", "run", "--host=0.0.0.0"]
