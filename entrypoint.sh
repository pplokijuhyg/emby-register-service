#!/bin/sh

# 退出脚本，如果任何命令失败
set -e

# 1. 运行数据库初始化
echo "正在初始化数据库..."
python -c 'from app import init_db; init_db()'
echo "数据库初始化完成。"

# 2. 使用 exec 来启动 Gunicorn
# "exec" 是这里的关键。它会用 gunicorn 进程替换掉当前的 shell 进程，
# 从而使得 Gunicorn 成为容器的主进程 (PID 1)。
echo "正在启动 Gunicorn..."
exec gunicorn --worker-class gevent --workers 4 --bind 0.0.0.0:5000 app:app
