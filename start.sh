#!/usr/bin/env bash
# ==============================================================================
# 北极光代理系统 - Linux (Debian / Ubuntu / CentOS / Alpine) 服务管理脚本
# 用法: ./start.sh {start|stop|restart|status|run|logs}
# ==============================================================================

set -e

# 定位脚本所在目录
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"

PID_FILE="$APP_DIR/proxy_service.pid"
LOG_FILE="$APP_DIR/proxy_service.log"
PY_SCRIPT="$APP_DIR/proxy_service.py"
PORT=8899

# 颜色高亮
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
PLAIN="\033[0m"

# 检查 Python 环境与依赖
init_env() {
    if ! command -v python3 >/dev/null 2>&1; then
        echo -e "${RED}[错误] 未检测到 python3，请先安装 Python 3 环境 (Debian/Ubuntu: apt update && apt install -y python3 python3-pip)${PLAIN}"
        exit 1
    fi

    # 优先使用项目级虚拟环境 (.venv)，避免 Debian 12 / Ubuntu 24.04 上的 PEP 668 限制
    if [ -d "$APP_DIR/.venv" ]; then
        PYTHON_CMD="$APP_DIR/.venv/bin/python3"
        PIP_CMD="$APP_DIR/.venv/bin/pip"
    else
        PYTHON_CMD="python3"
        PIP_CMD="pip3"
    fi

    # 快速检查 bs4 是否已安装
    if ! $PYTHON_CMD -c "import bs4" >/dev/null 2>&1; then
        echo -e "${YELLOW}[提示] 检测到缺少 beautifulsoup4 依赖，正在尝试自动安装...${PLAIN}"
        if command -v pip3 >/dev/null 2>&1 || [ -f "$APP_DIR/.venv/bin/pip" ]; then
            $PIP_CMD install -r "$APP_DIR/requirements.txt" || $PIP_CMD install --break-system-packages -r "$APP_DIR/requirements.txt"
        else
            echo -e "${RED}[错误] 未检测到 pip，请运行 apt install -y python3-bs4 或 python3-pip 后重试${PLAIN}"
            exit 1
        fi
    fi
}

# 获取当前运行中的进程 PID
get_pid() {
    if [ -f "$PID_FILE" ]; then
        local pid
        pid=$(cat "$PID_FILE" 2>/dev/null || true)
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            echo "$pid"
            return 0
        fi
    fi
    # 辅助兜底查找
    pgrep -f "python.*$PY_SCRIPT" 2>/dev/null | head -n 1 || true
}

# 启动服务 (守护进程)
start_service() {
    init_env
    local pid
    pid=$(get_pid)
    if [ -n "$pid" ]; then
        echo -e "${YELLOW}[警告] 服务已在运行中 (PID: $pid)${PLAIN}"
        return 0
    fi

    echo -e "${BLUE}>>> 正在启动北极光代理实时监控服务...${PLAIN}"
    nohup "$PYTHON_CMD" "$PY_SCRIPT" > "$LOG_FILE" 2>&1 &
    local new_pid=$!
    echo "$new_pid" > "$PID_FILE"

    sleep 1
    if kill -0 "$new_pid" 2>/dev/null; then
        echo -e "${GREEN}[成功] 服务已成功启动!${PLAIN}"
        echo -e "  - 进程 PID : $new_pid"
        echo -e "  - 运行日志 : $LOG_FILE"
        echo -e "  - 仪表盘   : http://127.0.0.1:$PORT/"
        echo -e "  - 统计接口 : http://127.0.0.1:$PORT/api/stats"
    else
        echo -e "${RED}[失败] 服务启动失败，请检查日志:${PLAIN}"
        tail -n 15 "$LOG_FILE"
        exit 1
    fi
}

# 前台运行服务 (调试观察)
run_service() {
    init_env
    local pid
    pid=$(get_pid)
    if [ -n "$pid" ]; then
        echo -e "${YELLOW}[警告] 服务已在后台运行中 (PID: $pid)，前台调试前请先执行 ./start.sh stop${PLAIN}"
        exit 1
    fi
    echo -e "${BLUE}>>> 正在前台启动服务 (按 Ctrl+C 安全退出)...${PLAIN}"
    exec "$PYTHON_CMD" "$PY_SCRIPT"
}

# 停止服务
stop_service() {
    local pid
    pid=$(get_pid)
    if [ -z "$pid" ]; then
        echo -e "${YELLOW}[提示] 服务当前未处于运行状态${PLAIN}"
        rm -f "$PID_FILE"
        return 0
    fi

    echo -e "${BLUE}>>> 正在停止服务 (PID: $pid)...${PLAIN}"
    kill -15 "$pid" 2>/dev/null || true

    local count=0
    while kill -0 "$pid" 2>/dev/null; do
        sleep 0.5
        count=$((count + 1))
        if [ "$count" -ge 10 ]; then
            echo -e "${YELLOW}[超时] 正常停机超时，强制终止进程...${PLAIN}"
            kill -9 "$pid" 2>/dev/null || true
            break
        fi
    done

    rm -f "$PID_FILE"
    echo -e "${GREEN}[成功] 服务已安全停止${PLAIN}"
}

# 重启服务
restart_service() {
    stop_service
    sleep 1
    start_service
}

# 服务状态查询
status_service() {
    local pid
    pid=$(get_pid)
    if [ -n "$pid" ]; then
        echo -e "${GREEN}[运行中] 北极光代理系统正常运行${PLAIN}"
        echo -e "  - 进程 PID : $pid"
        if command -v ss >/dev/null 2>&1; then
            local port_stat
            port_stat=$(ss -tlnp 2>/dev/null | grep ":$PORT " || true)
            if [ -n "$port_stat" ]; then
                echo -e "  - 端口监听 : $PORT (已就绪)"
            fi
        elif command -v netstat >/dev/null 2>&1; then
            local port_stat
            port_stat=$(netstat -tlnp 2>/dev/null | grep ":$PORT " || true)
            if [ -n "$port_stat" ]; then
                echo -e "  - 端口监听 : $PORT (已就绪)"
            fi
        fi
        echo -e "  - 最近日志 (末尾 5 行):"
        if [ -f "$LOG_FILE" ]; then
            tail -n 5 "$LOG_FILE" | sed 's/^/    /'
        else
            echo "    (日志文件暂未生成)"
        fi
    else
        echo -e "${RED}[已停止] 服务未在运行${PLAIN}"
    fi
}

# 日志追踪
logs_service() {
    if [ -f "$LOG_FILE" ]; then
        tail -f "$LOG_FILE"
    else
        echo -e "${YELLOW}[提示] 日志文件 $LOG_FILE 尚未生成${PLAIN}"
    fi
}

# 命令行入口
case "${1:-start}" in
    start)
        start_service
        ;;
    stop)
        stop_service
        ;;
    restart)
        restart_service
        ;;
    status)
        status_service
        ;;
    run)
        run_service
        ;;
    logs)
        logs_service
        ;;
    *)
        echo "用法: $0 {start|stop|restart|status|run|logs}"
        exit 1
        ;;
esac
