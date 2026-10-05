# syntax=docker/dockerfile:1
FROM python:3.11-slim

# 设置工作目录
WORKDIR /app

# 设置环境变量：时区、Python 输出无缓冲、编码
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=Asia/Shanghai \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# 安装系统运行依赖：更新 CA 证书支持 HTTPS，安装 tzdata 支持本地时区
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tzdata \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone \
    && rm -rf /var/lib/apt/lists/*

# 利用 Docker 构建缓存加速：先复制并安装依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制业务源码与仪表盘资源
COPY proxy_service.py config.json dashboard.html docker-entrypoint.sh ./

# 创建用于持久化存储的数据目录并赋予入口脚本执行权限
RUN mkdir -p /app/data && chmod +x /app/docker-entrypoint.sh

# 暴露服务端口
EXPOSE 8899

# 健康检查探针（使用 Python 内置 urllib 发起请求，无需外部 curl 依赖）
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8899/health', timeout=3)" || exit 1

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["python3", "proxy_service.py"]
