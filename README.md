# 北极光代理 (proxy-socks5.com) 实时监控采集与全协议分发系统 (v2.5)

针对 `https://proxy-socks5.com/proxy_list` 的实时代理采集、C 段打码智能脱敏还原、全协议（**HTTPS / SOCKS5 / HTTP**）深度实测可用性验证与现代化 Glassmorphism Web 仪表盘分发系统。

---

## 核心特性

1. **全协议深度真实可用性验证**：
   - **HTTPS 代理（全新深度优化）**：
     * **TLS 封装安全代理 (Secure Web Proxy)**：在底层建立 SSL/TLS 握手，随后在安全加密隧道内执行 `CONNECT` 请求测试。
     * **精确状态行拦截**：首行精确比对 `HTTP/1.x 200`，杜绝因响应头包含时间戳、端口或内容长度（如 `2000`、`2026` 等）导致的虚假 404/500 误报。
     * **双模透传校验**：针对标准 443 端口与非标准端口，兼顾 TLS 加密隧道与标准明文 CONNECT 隧道。
   - **SOCKS5 代理**：完整执行 SOCKS5 握手认证（`\x05\x01\x00` -> `\x05\x00`）及远程目标 CONNECT 转发连接验证，确保能真正代理网络流量。
   - **HTTP 代理**：分别测试 CONNECT 隧道（`CONNECT target:80 HTTP/1.1` -> `200 OK`）与正向 GET 代理请求（`204 No Content` / `200 OK`），自动剔除仅开放 Web 端口的无效主机。

2. **C 段高并发极速探测与智能还原**：
   - 目标网站展示的 IP 默认第三段脱敏为大写字母 `X`（如 `202.191.X.74:443`）。
   - 系统利用并发线程池对 0~255 个 C 段候选进行极速并行协议验证，在毫秒级时间内精准还原出真实通畅 IP。

3. **严格数据质量门禁（拒绝写入 X 节点）**：
   - **硬隔离门禁**：入库写入函数内置物理拦截，任何包含 `X` 或未通过真实 IPv4 校验的条目一律拒绝写入并产生告警。
   - **启动自检**：启动时自动扫描历史数据文件，彻底清除过往残留的未还原条目与失效节点。

4. **历史指纹去重与流式落盘**：
   - 采用 `Protocol://IP:Port` 与 `IP:Port` 联合唯一指纹去重，多线程加锁保障并发文件写入安全，节点一经验证成功立即流式追加落盘。

5. **现代化 Glassmorphism 实时 Web 仪表盘**：
   - 采用深色极光玻璃拟态设计（Glassmorphism），包含呼吸灯状态胶囊、实时各协议数量卡片（总节点、HTTPS、SOCKS5、HTTP）、采集轮次监控。
   - **白天 / 黑夜模式无缝切换**：顶栏一键切换浅色明亮（Light）与极光暗黑（Dark）主题，自动记忆保存至本地存储。
  - **动态检测频率与参数设置 (UI+API)**：支持在界面可视化设置轮询周期（默认 60s/轮）与探测超时（默认 1.8s），保存后立即生效并具备实时倒计时。
  - **全协议切换 Tab**：一键切换显示 全部 / 🔒 HTTPS / ⚡ SOCKS5 / 🌐 HTTP 代理。
   - **即时模糊搜索**：支持实时按 IP、端口、国家省市（如“印度”、“德国”、“美国”）、标签（“家宽”、“机房”、“原生IP”）动态过滤。
   - **便捷工具栏**：支持一键复制当前节点、导出 TXT 订阅、导出 JSON 数据、一键触发即时采集检测，并支持一键复制各行地址与纯 IP 模式。

---

## 项目目录结构

```text
proxy-socks5/
├── proxy_service.py   # 核心主服务（采集、探测还原、真实可用性校验、HTTP API）
├── dashboard.html     # 现代化 Glassmorphism 实时交互仪表盘前端
├── start.bat          # Windows 一键启动脚本
├── nodes.txt          # 纯代理节点文件 (每行一条: protocol://ip:port)
├── detail.txt         # 详细档案文件 (含入库时间、协议、真实IP、端口、归属地区、网络属性)
├── requirements.txt   # Python 依赖清单
└── README.md          # 项目说明文档
```

---

## 快速上手

### 1. 安装依赖
```bash
pip install -r requirements.txt
```

### 2. 启动服务
- **方式一（命令行）**：
  ```bash
  python proxy_service.py
  ```
- **方式二（Windows 双击）**：
  直接双击运行 `start.bat`。

---

## API 端点速查

| 端点 | 格式 | 说明 |
| :--- | :--- | :--- |
| `http://127.0.0.1:8899/` | `text/html` | 现代化 Glassmorphism 实时交互仪表盘 |
| `http://127.0.0.1:8899/nodes.txt` | `text/plain` | 纯代理列表，格式为 `protocol://ip:port`，支持直接订阅、Clash/V2Ray 等 |
| `http://127.0.0.1:8899/https.txt` | `text/plain` | **专属 HTTPS 代理端点**，仅输出严格通过 TLS 校验的真实 HTTPS 节点 |
| `http://127.0.0.1:8899/socks5.txt` | `text/plain` | **专属 SOCKS5 代理端点**，仅输出 SOCKS5 节点 |
| `http://127.0.0.1:8899/http.txt` | `text/plain` | **专属 HTTP 代理端点**，仅输出 HTTP 节点 |
| `http://127.0.0.1:8899/nodes.txt?raw=1` | `text/plain` | 无协议前缀列表，格式为 `ip:port`，方便脚本解析 |
| `http://127.0.0.1:8899/detail.txt` | `text/plain` | 完整元数据档案，包含时间戳、协议、真实IP端口、国家地区、网络属性标签 |
| `http://127.0.0.1:8899/api/proxies` | `application/json` | 结构化 JSON 格式代理列表，支持 `?type=https` 及 `?search=关键词` 过滤 |
| `http://127.0.0.1:8899/api/stats` | `application/json` | 包含各协议数量分布、服务运行状态、轮次等统计信息 |
| `http://127.0.0.1:8899/api/config` | `application/json` | 动态获取或修改检测参数（支持 `interval` 采集周期与 `timeout` 超时设置） |
| `http://127.0.0.1:8899/api/trigger` | `application/json` | 手动触发后台立即执行一轮采集探测 |
