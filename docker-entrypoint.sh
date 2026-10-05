#!/bin/sh
set -e

# 如果没有显式设置 PROXY_DB_FILE，且挂载了 /app/data 目录，自动使用挂载目录存储数据库
if [ -z "$PROXY_DB_FILE" ] && [ -d "/app/data" ]; then
    export PROXY_DB_FILE="/app/data/data.db"
fi

exec "$@"
