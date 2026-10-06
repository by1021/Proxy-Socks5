# 北极光代理 (proxy-socks5.com) 实时监控采集与全协议分发系统 (v2.5)

针对 `https://proxy-socks5.com/proxy_list` 的实时代理采集、C 段打码智能脱敏还原、全协议（**HTTPS / SOCKS5 / HTTP**）深度实测可用性验证与现代化 Glassmorphism Web 仪表盘分发系统。现已全面支持 **Docker 容器化** 与 **Linux 原生服务化 (Debian / Ubuntu)** 部署。

---

## 核心特性

1. **全协议深度真实可用性验证**：
   - **HTTPS 代理**：TLS 封装安全代理 (Secure Web Proxy) 隧道握手 + 首行精准状态校验 (`HTTP/1.x 200`)，杜绝因响应头内容长度或时间戳产生的虚假误报；双模兼顾 443 与非标端口。
   - **SOCKS5 代理**：执行完整协议版本认证握手（`\x05\x01\x00` -> `\x05\x00`）及远程目标 CONNECT 转发连接验证，确保具备真实代理转发能力。
   - **HTTP 代理**：兼测 CONNECT 隧道方法与正向 GET 代理请求，自动过滤仅开放 Web 端口的无效节点。

2. **C 段高并发极速探测与智能还原**：
   - 对目标脱敏的掩码节点（如 `202.191.X.74:443`）进行 0~255 全候选毫秒级多线程协议实测，秒级还原真实公网通畅 IP。

3. **严格数据质量门禁（拒绝写入 X 节点）**：
   - 入库函数内置物理校验拦截，拒绝任何带 `X` 或非法 IPv4 的条目，启动时自动清理过往残留失效条目。

4. **历史指纹去重与流式落盘**：
   - `Protocol://IP:Port` 联合唯一指纹，线程安全锁流式入库，发现可用节点立即保存至 SQLite WAL 高性能数据库。

5. **全平台环境适配 (Docker / Linux / Windows)**：
   - 提供标准 **Dockerfile** 与 **docker-compose.yml**，跨平台一键部署。
   - 深度适配 **Debian / Ubuntu** 等主流 Linux 发行版，提供 `start.sh` 管理脚本与 `systemd` 开机自启服务配置。
   - 彻底优化路径与编码逻辑，抹除平台路径差异，原生支持环境变量自由覆盖。

6. **现代化 Glassmorphism 实时 Web 仪表盘**：
   - 极光暗黑 / 清晰白天双主题无缝切换，实时协议卡片统计、节点模糊检索、动态检测频率微调、一键复制与多格式订阅导出。

7. **数据库全生命周期管理与数据导入导出体系 (NEW)**：
   - **多格式全量导出**：摆脱前端分页限制，直接由后端按条件流式导出 **CSV 表格**（Excel通用）、**标准 JSON**、**TXT 订阅列表**、**Detail 元数据** 以及 **原生 SQLite 二进制快照 (`.db`)**。
   - **智能批量导入流水线**：支持粘贴自由文本、带协议 URI、CSV 或 JSON 数组，自动识别协议与地址；严格走 `is_valid_ipv4`、反 X 节点质量门禁与 `seen_fingerprints` 内存指纹库去重，可选开启入库前即时连通性探活。
   - **数据库运维自检**：提供在线热备份下载、文件大小与表状态查询、一键 `VACUUM` 磁盘压缩整理与失效节点清理。

---

## 项目目录结构

```text
proxy-socks5/
├── proxy_service.py       # 核心服务（采集、探测还原、全协议可用性校验、HTTP API、SQLite引擎）
├── dashboard.html         # 现代化 Glassmorphism 实时交互仪表盘前端
├── config.json            # 核心参数配置文件（支持动态持久化与环境变量覆盖）
├── requirements.txt       # Python 依赖清单
├── Dockerfile             # 容器镜像构建清单（基于 python:3.11-slim）
├── docker-compose.yml     # Docker Compose 多环境一键编排配置
├── docker-entrypoint.sh   # 容器运行时环境初始化入口
├── .dockerignore          # Docker 构建忽略规则
├── start.sh               # Linux (Debian/Ubuntu) 专用启停管理脚本 (start|stop|restart|status|run|logs)
├── proxy-socks5.service   # Linux systemd 系统守护进程单元配置
├── start.bat              # Windows 双击一键启动脚本
├── data.db                # SQLite 数据库（自动生成，持久化存储节点）
└── README.md              # 项目部署与使用文档
```

---

## 部署方式速查

你可以根据当前服务器环境选择最适合的部署方式：

| 部署方式 | 推荐场景 | 特点 |
| :--- | :--- | :--- |
| **Docker Compose** | **首选推荐**（云服务器、VPS、NAS） | 一行命令启动，环境绝对隔离，数据自动卷持久化 |
| **Docker 独立容器** | 容器化生产集群 / Portainer / K8s | 标准镜像构建，轻量免运维 |
| **Linux 管理脚本** | Debian / Ubuntu 物理机或轻量 VPS | 提供 `start.sh`，支持后台守护、平滑停机、日志追踪 |
| **systemd 系统服务** | 生产级 Linux 宿主机 | 开机自启、故障自动重启、与系统日志一体化 |
| **Windows 本地** | 本地测试 / 开发者桌面 | 双击 `start.bat` 即可开箱即用 |

---

## 🚀 方式一：Docker 部署（推荐）

适用于任意安装有 Docker 的 Linux 服务器（Debian, Ubuntu, CentOS, Alpine 等）。

### 1. 使用 Docker Compose 一键启动（最推荐）

```bash
# 进入项目目录
cd proxy-socks5

# 构建并后台启动服务
docker compose up -d --build

# 查看运行日志
docker compose logs -f

# 查看健康状态
docker compose ps
```
> **数据持久化说明**：数据将自动持久化至宿主机的 `./data/` 目录中，重启或重新拉取镜像数据不丢失。

停止或重启服务：
```bash
docker compose restart     # 重启服务
docker compose down        # 停止并移除容器
```

---

### 2. 使用标准 Docker CLI 运行

```bash
# 1. 构建镜像
docker build -t proxy-socks5:latest .

# 2. 运行容器（映射 8899 端口，并挂载宿主机 ./data 目录用于数据持久化）
docker run -d \
  --name proxy-socks5-service \
  --restart unless-stopped \
  -p 8899:8899 \
  -v "$(pwd)/data:/app/data" \
  proxy-socks5:latest

# 3. 检查容器状态与健康检查探针
docker ps -f name=proxy-socks5-service

# 4. 查看实时日志
docker logs -f proxy-socks5-service
```

---

## 🐧 方式二：Linux 环境原生部署 (Debian / Ubuntu 等)

### 1. 准备系统基础环境

在 Debian / Ubuntu 上更新系统并安装 Python 3 与 pip：

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv ca-certificates
```

> 💡 **针对 Debian 12 (Bookworm) 与 Ubuntu 24.04 (Noble) 的提示**：
> 新版系统默认启用了 PEP 668（外部管理环境限制）。内置的 `start.sh` 脚本已自动处理虚拟环境创建或安全安装，无需担心冲突。

### 2. 使用内置管理脚本 `start.sh`

项目内置了针对 Linux 设计的专属运维脚本 `start.sh`，支持标准的守护进程操作：

```bash
# 赋予执行权限
chmod +x start.sh

# 启动服务 (自动在后台以后台守护进程模式运行)
./start.sh start

# 查看服务运行状态、PID 与监听端口
./start.sh status

# 实时追踪运行日志
./start.sh logs

# 调试运行 (前台控制台打印，按 Ctrl+C 退出)
./start.sh run

# 重启或停止服务
./start.sh restart
./start.sh stop
```

---

### 3. 配置 systemd 系统常驻服务（开机自启）

如需将服务注册为 Debian / Ubuntu 的系统级守护进程（自动开机自启、崩溃重启）：

```bash
# 1. 将项目放置在目标目录（例如 /opt/proxy-socks5）
sudo cp -r . /opt/proxy-socks5
cd /opt/proxy-socks5

# 2. 安装 Python 依赖
pip3 install -r requirements.txt || pip3 install --break-system-packages -r requirements.txt

# 3. 复制服务配置文件到 systemd
sudo cp proxy-socks5.service /etc/systemd/system/

# 4. 重新加载 systemd 并启动服务
sudo systemctl daemon-reload
sudo systemctl enable --now proxy-socks5

# 5. 查看运行状态与日志
sudo systemctl status proxy-socks5
sudo journalctl -u proxy-socks5 -f
```

---

### 4. Linux 防火墙放行 (UFW / iptables)

若服务运行在云服务器上且外部无法访问仪表盘，请确保开放 `8899` 端口：

- **UFW (Ubuntu / Debian 默认)**：
  ```bash
  sudo ufw allow 8899/tcp
  sudo ufw status
  ```
- **云服务商安全组**：请在阿里云/腾讯云/AWS/华为云控制台安全组规则中放行入方向 `TCP: 8899`。

---

## 💻 方式三：Windows 本地运行

1. 安装依赖：`pip install -r requirements.txt`
2. 双击运行 `start.bat` 或在终端运行：`python proxy_service.py`。

---

## ⚙️ 环境变量与高级配置

系统全面支持通过 **环境变量** 动态注入配置，优先级高于 `config.json`，非常适合容器化批量部署：

| 环境变量名 | 默认值 | 示例值 | 说明 |
| :--- | :--- | :--- | :--- |
| `PROXY_API_HOST` | `0.0.0.0` | `0.0.0.0` | 服务监听的绑定地址 |
| `PROXY_API_PORT` | `8899` | `8899` | HTTP 服务端口 |
| `PROXY_POLL_INTERVAL` | `60` | `30` | 轮询采集周期 (秒) |
| `PROXY_PROBE_TIMEOUT` | `1.8` | `2.0` | 节点可用性探测超时 (秒) |
| `PROXY_PROBE_WORKERS` | `96` | `128` | C 段批量并发扫描探测线程数 |
| `PROXY_NODE_CONCURRENCY` | `5` | `10` | 节点并发处理数 |
| `PROXY_DB_FILE` | `data.db` | `/app/data/data.db` | SQLite 数据库存储绝对或相对路径 |

---

## 📡 API 端点速查

| 端点 | 响应格式 | 核心说明 |
| :--- | :--- | :--- |
| `http://127.0.0.1:8899/` | `text/html` | 现代化 Glassmorphism 实时交互仪表盘 |
| `http://127.0.0.1:8899/nodes.txt` | `text/plain` | 纯代理列表，格式为 `protocol://ip:port`，支持直接订阅、Clash/V2Ray 等 |
| `http://127.0.0.1:8899/https.txt` | `text/plain` | **专属 HTTPS 代理端点**，仅输出严格通过 TLS 校验的真实 HTTPS 节点 |
| `http://127.0.0.1:8899/socks5.txt` | `text/plain` | **专属 SOCKS5 代理端点**，仅输出 SOCKS5 节点 |
| `http://127.0.0.1:8899/http.txt` | `text/plain` | **专属 HTTP 代理端点**，仅输出 HTTP 节点 |
| `http://127.0.0.1:8899/nodes.txt?raw=1` | `text/plain` | 无协议前缀列表，格式为 `ip:port`，方便自动化脚本解析 |
| `http://127.0.0.1:8899/detail.txt` | `text/plain` | 完整元数据档案，包含时间戳、协议、真实 IP 端口、国家地区、网络属性标签 |
| `http://127.0.0.1:8899/api/proxies` | `application/json` | 结构化 JSON 格式代理列表，支持 `?type=https` 及 `?search=关键词` 过滤 |
| `http://127.0.0.1:8899/api/stats` | `application/json` | 包含各协议数量分布、服务运行状态、轮次等统计信息 |
| `http://127.0.0.1:8899/api/config` | `application/json` | 动态获取或修改检测参数（支持 `interval` 采集周期与 `timeout` 超时设置） |
| `http://127.0.0.1:8899/api/trigger` | `application/json` | 手动触发后台立即执行一轮采集探测 |
| `http://127.0.0.1:8899/health` | `application/json` | **健康检查探针**，返回 `{"status":"ok"}`，供 Docker / K8s 保活监测 |
| `http://127.0.0.1:8899/api/export` | `CSV / JSON / TXT` | **全量多格式数据导出**，支持 `format` (csv/json/txt/detail/sqlite)、`proto`、`status` 条件筛选 |
| `http://127.0.0.1:8899/api/import` | `application/json` (POST) | **节点批量导入与去重入库**，智能解析 URI/CSV/JSON，含质量门禁与可选探活 |
| `http://127.0.0.1:8899/api/db/backup` | `application/octet-stream` | **SQLite 数据库快照备份**，在线热备份免加锁下载完整二进制 `data.db` 副本 |
| `http://127.0.0.1:8899/api/db/stats` | `application/json` | 获取 SQLite 数据库存储大小、节点量及协议分布状态 |
| `http://127.0.0.1:8899/api/db/vacuum` | `application/json` (POST) | 手动触发 SQLite `VACUUM;` 整理数据库磁盘空间并重建索引 |
| `http://127.0.0.1:8899/api/db/clear` | `application/json` (POST) | 安全清理失效或失败节点记录 |
