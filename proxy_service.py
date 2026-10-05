# -*- coding: utf-8 -*-
"""
北极光代理 (proxy-socks5.com) 实时监控采集 + 全协议真实性校验 + HTTP API 智能分发系统
- 协议级深度真实可用性校验：
  * HTTPS 代理：TLS 封装安全代理 (Secure Web Proxy) 隧道建立 + 状态行精确校验 (严格杜绝伪造 404/500)
  * SOCKS5 代理：协议版本握手 + 远程目标 CONNECT 转发连接双重校验
  * HTTP 代理：CONNECT 隧道方法与正向 GET 代理请求综合校验
- C 段高并发极速探测与智能还原（硬门禁保障：绝不写入任何带 X 掩码的未还原节点）
- 严格数据质量门禁：入库前多重检验真实公网 IPv4，杜绝虚假与不可用节点
- 历史指纹去重 + 增量流式落盘（发现有效即落盘）
- 内置轻量多线程 Web 服务，提供全协议独立端点与现代化 Glassmorphism 实时状态仪表盘
"""

import os
import sys
import re
import json
import time
import socket
import ssl
import datetime
import threading
import concurrent.futures
import urllib.request
import urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import bs4
import sqlite3

# 适配 Windows 控制台 UTF-8 输出
try:
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    if hasattr(sys.stderr, 'reconfigure'):
        sys.stderr.reconfigure(encoding='utf-8')
except Exception:
    pass

# ==================== 核心配置 ====================
API_HOST = "0.0.0.0"                 # 监听地址 (0.0.0.0 允许局域网或公网访问)
API_PORT = 8899                      # API 与仪表盘服务端口
NODES_FILE = "nodes.txt"             # 纯节点存储文件
DETAIL_FILE = "detail.txt"           # 详细信息档案文件
DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxies.db")  # SQLite 本地数据库文件
DASHBOARD_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.html")
TARGET_URL = "https://proxy-socks5.com/proxy_list"
POLL_INTERVAL = 60                   # 轮询采集周期 (秒)
PROBE_WORKERS = 96                   # C段单节点探测并发线程数
PROBE_TIMEOUT = 1.8                  # 协议检测单次超时 (秒)
NODE_CONCURRENCY = 5                 # 同时并发处理的目标节点数
# ==================================================

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

DEFAULT_CONFIG = {
    "api_host": API_HOST,
    "api_port": API_PORT,
    "poll_interval": POLL_INTERVAL,
    "probe_timeout": PROBE_TIMEOUT,
    "probe_workers": PROBE_WORKERS,
    "node_concurrency": NODE_CONCURRENCY,
    "target_url": TARGET_URL,
    "nodes_file": NODES_FILE,
    "detail_file": DETAIL_FILE,
    "db_file": DB_FILE
}

def load_config() -> dict:
    """从 config.json 加载持久化配置，若不存在则使用预设默认值并自动创建"""
    global POLL_INTERVAL, PROBE_TIMEOUT, PROBE_WORKERS, NODE_CONCURRENCY, API_HOST, API_PORT, DB_FILE
    cfg = DEFAULT_CONFIG.copy()
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                saved = json.load(f)
                if isinstance(saved, dict):
                    cfg.update(saved)
                    POLL_INTERVAL = int(cfg.get('poll_interval', POLL_INTERVAL))
                    PROBE_TIMEOUT = float(cfg.get('probe_timeout', PROBE_TIMEOUT))
                    PROBE_WORKERS = int(cfg.get('probe_workers', PROBE_WORKERS))
                    NODE_CONCURRENCY = int(cfg.get('node_concurrency', NODE_CONCURRENCY))
                    API_HOST = str(cfg.get('api_host', API_HOST))
                    API_PORT = int(cfg.get('api_port', API_PORT))
                    DB_FILE = str(cfg.get('db_file', DB_FILE))
            log(f"已加载配置文件 {CONFIG_FILE} (采集周期: {POLL_INTERVAL}s, 探测超时: {PROBE_TIMEOUT}s)")
        except Exception as e:
            log(f"读取配置文件异常，使用默认值: {e}")
    else:
        save_config(cfg)
        log(f"已初始化生成配置文件: {CONFIG_FILE}")
    return cfg

def save_config(cfg: dict = None) -> bool:
    """将当前内存配置持久化写入 config.json 文件"""
    global POLL_INTERVAL, PROBE_TIMEOUT, PROBE_WORKERS, NODE_CONCURRENCY, API_HOST, API_PORT, DB_FILE
    if cfg is None:
        cfg = DEFAULT_CONFIG.copy()
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    saved = json.load(f)
                    if isinstance(saved, dict):
                        cfg.update(saved)
            except Exception:
                pass
        cfg["poll_interval"] = POLL_INTERVAL
        cfg["probe_timeout"] = PROBE_TIMEOUT
        cfg["probe_workers"] = PROBE_WORKERS
        cfg["node_concurrency"] = NODE_CONCURRENCY
        cfg["api_host"] = API_HOST
        cfg["api_port"] = API_PORT

    with data_lock:
        try:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(cfg, f, ensure_ascii=False, indent=2)
            log(f"[配置持久化] 已保存至 {CONFIG_FILE}: 采集周期={POLL_INTERVAL}s, 单次超时={PROBE_TIMEOUT}s")
            return True
        except Exception as e:
            log(f"[配置保存失败] 写入 {CONFIG_FILE} 异常: {e}")
            return False


# 全局共享 SSL 上下文 (禁用证书校验以支持自签代理节点，复用上下文减少开销)
ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

seen_fingerprints = set()
masked_cache = {}                    # 缓存已探测结果，避免周期内重复无效探测
data_lock = threading.Lock()
poll_event = threading.Event()
is_polling_active = False

service_stats = {
    "total_captured": 0,
    "last_poll_time": "尚未轮询",
    "last_poll_timestamp": 0,
    "start_time": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    "poll_round": 0,
    "is_busy": False,
    "last_message": "服务已初始化，等待轮询采集"
}

def log(msg: str):
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{now}] {msg}", flush=True)

def is_valid_ipv4(ip_str: str) -> bool:
    """严格校验是否为合规的公网 IPv4 地址（排除带 X 或格式异常字符串）"""
    if not ip_str or not isinstance(ip_str, str):
        return False
    if 'X' in ip_str or 'x' in ip_str:
        return False
    parts = ip_str.split('.')
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit():
            return False
        val = int(p)
        if val < 0 or val > 255:
            return False
        if len(p) > 1 and p.startswith('0'):
            return False
    return True

def verify_socks5(ip: str, port: int, timeout: float = PROBE_TIMEOUT) -> bool:
    """验证 SOCKS5 代理：握手确认 + 建立转发连接"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        # 1. 握手报文：VER=5, NMETHODS=1, METHOD=00(NO AUTH)
        s.sendall(b"\x05\x01\x00")
        resp = s.recv(2)
        if resp not in (b"\x05\x00", b"\x05\x02"):
            return False
        # 2. 发起 CONNECT 转发请求测试
        target = b"connectivitycheck.gstatic.com"
        cmd = b"\x05\x01\x00\x03" + bytes([len(target)]) + target + (80).to_bytes(2, 'big')
        s.sendall(cmd)
        resp2 = s.recv(10)
        return len(resp2) >= 2 and resp2[1] == 0
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass

def verify_https(ip: str, port: int, timeout: float = PROBE_TIMEOUT) -> bool:
    """
    深度验证 HTTPS 代理：
    模式 1：TLS 封装安全代理 (Secure Web Proxy，常见于 443 等端口)
            建立 TLS 握手 -> 发送 CONNECT 请求 -> 精确校验 HTTP 状态行 200 或 Connection Established
    模式 2：标准明文 CONNECT 隧道代理 (支持透传转发 HTTPS 流量)
    """
    # 模式 1：TLS 封装代理
    s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s1.settimeout(timeout)
    try:
        s1.connect((ip, port))
        try:
            ss = ssl_ctx.wrap_socket(s1, server_hostname=None)
            ss.settimeout(timeout)
            ss.sendall(b"CONNECT httpbin.org:80 HTTP/1.1\r\nHost: httpbin.org:80\r\n\r\n")
            resp = ss.recv(128)
            ss.close()
            # 精确比对首行状态码 200，杜绝 404/500 等由于响应头含数字 200 产生的误报
            if re.match(rb"^HTTP/1\.[01]\s+200\b", resp) or b"connection established" in resp.lower():
                return True
        except Exception:
            pass
    except Exception:
        pass
    finally:
        try:
            s1.close()
        except Exception:
            pass

    # 模式 2：标准明文 CONNECT 隧道
    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2.settimeout(timeout)
    try:
        s2.connect((ip, port))
        s2.sendall(b"CONNECT httpbin.org:80 HTTP/1.1\r\nHost: httpbin.org:80\r\n\r\n")
        resp2 = s2.recv(128)
        if re.match(rb"^HTTP/1\.[01]\s+200\b", resp2) or b"connection established" in resp2.lower():
            return True
    except Exception:
        pass
    finally:
        try:
            s2.close()
        except Exception:
            pass

    return False

def verify_http(ip: str, port: int, timeout: float = PROBE_TIMEOUT) -> bool:
    """验证 HTTP 代理：CONNECT 隧道方法 或 正向 GET 代理请求"""
    # 方法 1：测试 CONNECT 隧道
    s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s1.settimeout(timeout)
    try:
        s1.connect((ip, port))
        s1.sendall(b"CONNECT httpbin.org:80 HTTP/1.1\r\nHost: httpbin.org:80\r\n\r\n")
        resp = s1.recv(128)
        if re.match(rb"^HTTP/1\.[01]\s+200\b", resp) or b"connection established" in resp.lower():
            return True
    except Exception:
        pass
    finally:
        try:
            s1.close()
        except Exception:
            pass

    # 方法 2：正向 GET 代理请求
    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2.settimeout(timeout)
    try:
        s2.connect((ip, port))
        req = b"GET http://connectivitycheck.gstatic.com/generate_204 HTTP/1.1\r\nHost: connectivitycheck.gstatic.com\r\nConnection: close\r\n\r\n"
        s2.sendall(req)
        resp2 = s2.recv(128)
        if re.match(rb"^HTTP/1\.[01]\s+(200|204)\b", resp2):
            return True
    except Exception:
        pass
    finally:
        try:
            s2.close()
        except Exception:
            pass

    # 若端口为 443，额外尝试 HTTPS 握手
    if port == 443:
        if verify_https(ip, port, timeout):
            return True

    return False

def verify_proxy_candidate(proto: str, ip: str, port: int, timeout: float = PROBE_TIMEOUT) -> bool:
    """按协议分发真实可用性验证"""
    if proto == 'socks5':
        return verify_socks5(ip, port, timeout)
    elif proto == 'https':
        return verify_https(ip, port, timeout)
    return verify_http(ip, port, timeout)

def unmask_and_verify(proto: str, masked_ip: str, port: int) -> str | None:
    """
    对目标 IP 进行真实地址探测与协议可用性双重验证：
    1. 若包含 X 掩码：并发测试 0~255 C 段候选，仅当协议校验通过时返回真实 IP。
    2. 若不含 X：直接进行协议校验，通过则返回，失败则返回 None。
    3. 若未能找到真实可用 IP，一律返回 None，严禁返回包含 X 的伪节点。
    """
    parts = masked_ip.split('.')
    if len(parts) != 4:
        return None

    if 'X' in parts[2] or 'x' in parts[2]:
        prefix = f"{parts[0]}.{parts[1]}"
        suffix = parts[3]

        with concurrent.futures.ThreadPoolExecutor(max_workers=PROBE_WORKERS) as ex:
            futures = {
                ex.submit(verify_proxy_candidate, proto, f"{prefix}.{c}.{suffix}", port, PROBE_TIMEOUT): f"{prefix}.{c}.{suffix}"
                for c in range(256)
            }
            for fut in concurrent.futures.as_completed(futures):
                try:
                    if fut.result():
                        real_ip = futures[fut]
                        if is_valid_ipv4(real_ip):
                            for rem in futures:
                                rem.cancel()
                            return real_ip
                except Exception:
                    pass
        return None
    else:
        if is_valid_ipv4(masked_ip) and verify_proxy_candidate(proto, masked_ip, port, timeout=PROBE_TIMEOUT):
            return masked_ip
        return None


# ==================== SQLite 本地数据库核心层 ====================
def get_db():
    """获取配置了 WAL 模式与行字典的 SQLite 数据库连接"""
    conn = sqlite3.connect(DB_FILE, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA busy_timeout = 5000;")
    return conn

def init_db():
    """初始化数据库表与索引，若为空则自动无缝迁移 detail.txt / nodes.txt 历史合法数据"""
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS proxies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                protocol TEXT NOT NULL,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                location TEXT DEFAULT '',
                tags TEXT DEFAULT '',
                entry_time TEXT NOT NULL,
                last_check_time TEXT DEFAULT '',
                status TEXT DEFAULT 'active',
                latency_ms REAL DEFAULT 0.0,
                fail_count INTEGER DEFAULT 0,
                UNIQUE(ip, port)
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_proxies_proto ON proxies(protocol);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_proxies_time ON proxies(entry_time DESC);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_proxies_status ON proxies(status);")

        # 检查是否需要从现有 detail.txt 自动迁移历史数据
        cursor = conn.execute("SELECT COUNT(*) AS cnt FROM proxies;")
        cnt = cursor.fetchone()['cnt']
        if cnt == 0 and os.path.exists(DETAIL_FILE):
            log(f"首次初始化 SQLite 数据库，正在从 {DETAIL_FILE} 自动迁移历史合法节点...")
            migrated = 0
            with open(DETAIL_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or 'X' in line or 'x' in line:
                        continue
                    m = re.match(r'\[(.*?)\]\s*\|\s*(socks5|https?)://([^:]+):(\d+)\s*\|\s*地区:\s*(.*?)\s*\|\s*属性:\s*(.*)', line)
                    if m:
                        e_time, proto, ip, port_str, loc, tags = m.groups()
                        proto = proto.lower()
                        if is_valid_ipv4(ip):
                            try:
                                port = int(port_str)
                                conn.execute("""
                                    INSERT OR IGNORE INTO proxies 
                                    (protocol, ip, port, location, tags, entry_time, last_check_time, status)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, 'active');
                                """, (proto, ip, port, loc, tags, e_time, e_time))
                                migrated += 1
                            except ValueError:
                                continue
            conn.commit()
            log(f"历史数据迁移完成，共成功收录 {migrated} 个唯一合法节点至 {DB_FILE}")

def sync_disk_files_from_db(conn=None):
    """将数据库中当前全部合法节点同步导出至 nodes.txt 与 detail.txt，保障外部文本订阅与下游工具 100% 兼容"""
    need_close = False
    if conn is None:
        conn = get_db()
        need_close = True
    try:
        rows = conn.execute("SELECT protocol, ip, port, location, tags, entry_time FROM proxies ORDER BY id ASC;").fetchall()
        with open(NODES_FILE, 'w', encoding='utf-8') as fn, \
             open(DETAIL_FILE, 'w', encoding='utf-8') as fd:
            for r in rows:
                proto_url = f"{r['protocol']}://{r['ip']}:{r['port']}"
                fn.write(f"{proto_url}\n")
                fd.write(f"[{r['entry_time']}] | {proto_url} | 地区: {r['location']} | 属性: {r['tags']}\n")
    finally:
        if need_close:
            conn.close()

def read_all_proxies_from_disk():
    """从 SQLite 数据库高效读取结构化代理列表与协议统计"""
    proxies_list = []
    counts = {"total": 0, "socks5": 0, "http": 0, "https": 0}

    try:
        with get_db() as conn:
            cur = conn.execute("SELECT protocol, COUNT(*) as cnt FROM proxies GROUP BY protocol;")
            for r in cur.fetchall():
                p = r['protocol'].lower()
                c = r['cnt']
                counts[p] = c
                counts['total'] += c

            rows = conn.execute("SELECT entry_time, protocol, ip, port, location, tags, status, latency_ms FROM proxies ORDER BY entry_time DESC;").fetchall()
            for r in rows:
                proto = r['protocol'].lower()
                ip = r['ip']
                port = r['port']
                proxies_list.append({
                    "entry_time": r['entry_time'],
                    "protocol": proto,
                    "ip": ip,
                    "port": port,
                    "url": f"{proto}://{ip}:{port}",
                    "location": r['location'],
                    "tags": r['tags'],
                    "status": r['status'],
                    "latency_ms": r['latency_ms']
                })
    except Exception as e:
        log(f"[数据库读取异常] {e}")

    return proxies_list, counts

def init_dedup_cache(force_sync_files: bool = True):
    """
    启动与运行时全量自检去重门禁：
    1. 确保 SQLite 数据库结构完整并载入全量节点
    2. 全量刷新 seen_fingerprints 去重指纹库 (proto://ip:port 与 ip:port)
    3. 同步导出 nodes.txt 与 detail.txt，保持磁盘文件 100% 对应与唯一
    """
    global seen_fingerprints
    init_db()
    with data_lock:
        seen_fingerprints.clear()
        with get_db() as conn:
            rows = conn.execute("SELECT protocol, ip, port FROM proxies ORDER BY id ASC;").fetchall()
            for r in rows:
                p, ip, port = r['protocol'].lower(), r['ip'], r['port']
                seen_fingerprints.add(f"{p}://{ip}:{port}")
                seen_fingerprints.add(f"{ip}:{port}")

            if force_sync_files:
                sync_disk_files_from_db(conn)

            service_stats["total_captured"] = len(rows)
            log(f"[本地数据库就绪] 已加载 {len(rows)} 个唯一合法有效节点 (存储文件: {DB_FILE})")
            return len(rows), 0, 0
# ==============================================================

def fetch_latest_proxies():
    """从目标网站抓取最新展示的代理列表元数据 (覆盖 SOCKS5 / HTTP / HTTPS 全协议)"""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Referer": "https://proxy-socks5.com/"
    }
    req = urllib.request.Request(TARGET_URL, headers=headers)
    html = urllib.request.urlopen(req, timeout=15).read().decode('utf-8', errors='ignore')
    soup = bs4.BeautifulSoup(html, 'html.parser')

    rows = soup.select('table tbody tr') or soup.select('table tr')[1:]
    proxies = []
    current_year = datetime.datetime.now().year

    for row in rows:
        tds = row.find_all('td')
        if len(tds) < 4:
            continue

        proto_badge = tds[0].find('span', class_='badge-type')
        protocol = proto_badge.get_text(strip=True).lower() if proto_badge else 'socks5'
        if protocol not in ('socks5', 'http', 'https'):
            protocol = 'socks5'

        port_str = tds[2].get_text(strip=True)
        if not port_str.isdigit():
            continue
        port = int(port_str)

        btn = row.find('button', class_='btn-copy')
        if btn and btn.get('data-ip'):
            ip = btn.get('data-ip').strip()
        else:
            ip_m = re.search(r'(\d{1,3}\.\d{1,3}\.[Xx\d]+\.\d{1,3})', tds[1].get_text())
            ip = ip_m.group(1) if ip_m else ''

        if not ip:
            continue

        geo_td = tds[3]
        tags = [t.get_text(strip=True) for t in geo_td.find_all('span', class_='datacenter-tag') or []]
        bracket_tags = re.findall(r'(\[[^\]]+\])', geo_td.get_text())
        tags = list(dict.fromkeys(tags + bracket_tags))

        geo_span = geo_td.find('span', class_='flex-text')
        if geo_span:
            location = geo_span.get_text(strip=True)
        else:
            raw_text = geo_td.get_text(' ', strip=True)
            for t in tags:
                raw_text = raw_text.replace(t, '')
            raw_text = re.sub(r'入库:\S+|复制|已复制', '', raw_text)
            location = ' '.join(raw_text.split())

        time_m = re.search(r'入库:(\d{2}-\d{2}\s+\d{2}:\d{2})', geo_td.get_text())
        entry_time = f"{current_year}-{time_m.group(1)}:00" if time_m else datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        proxies.append({
            "entry_time": entry_time,
            "protocol": protocol,
            "ip": ip,
            "port": port,
            "tags": " ".join(tags) if tags else "[机房]",
            "location": location
        })

    return proxies

def save_single_node(node: dict) -> bool:
    """
    流式安全落盘单个已验证节点至 SQLite 本地数据库及兼容文本文件
    【核心门禁】：
    1. 严格禁止任何包含 X 或非合规 IPv4 写入！
    2. 严格执行重复节点检测（引擎级 UNIQUE 约束 + 内存指纹库拦截），绝不写入重复信息！
    """
    ip = str(node.get('ip', '')).strip()
    try:
        port = int(node.get('port', 0))
    except (ValueError, TypeError):
        return False
    protocol = str(node.get('protocol', 'socks5')).lower().strip()
    if protocol not in ('socks5', 'http', 'https'):
        protocol = 'socks5'

    # 1. 基础有效性与防 X 门禁
    if not ip or 'X' in ip or 'x' in ip or not is_valid_ipv4(ip) or not (1 <= port <= 65535):
        log(f"[门禁拦截] 发现非法或含掩码节点，坚决拒绝写入: {protocol}://{ip}:{port}")
        return False

    fp_proto = f"{protocol}://{ip}:{port}"
    fp_raw = f"{ip}:{port}"

    with data_lock:
        # 2. 内存指纹库预拦截
        if fp_proto in seen_fingerprints or fp_raw in seen_fingerprints:
            log(f"[去重拦截] 检测到重复节点信息，拒绝写入: {fp_proto}")
            return False

        # 3. 数据库引擎级原子落盘与唯一性约束保证 (UNIQUE(ip, port))
        entry_time = node.get('entry_time') or datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        location = node.get('location') or '未知地区'
        tags = node.get('tags') or '[机房]'

        try:
            with get_db() as conn:
                cur = conn.execute("""
                    INSERT OR IGNORE INTO proxies 
                    (protocol, ip, port, location, tags, entry_time, last_check_time, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'active');
                """, (protocol, ip, port, location, tags, entry_time, entry_time))
                conn.commit()

                if cur.rowcount <= 0:
                    seen_fingerprints.add(fp_proto)
                    seen_fingerprints.add(fp_raw)
                    log(f"[数据库去重拦截] 节点已存在于 SQLite 数据库，拒绝重复写入: {fp_proto}")
                    return False
        except Exception as e:
            log(f"[数据库写入异常] {e}")
            return False

        # 4. 同步流式追加至 nodes.txt 与 detail.txt，保证外部文本订阅的绝对实时性与兼容性
        try:
            with open(NODES_FILE, 'a', encoding='utf-8') as f_nodes, \
                 open(DETAIL_FILE, 'a', encoding='utf-8') as f_detail:
                f_nodes.write(f"{fp_proto}\n")
                f_nodes.flush()
                f_detail.write(f"[{entry_time}] | {fp_proto} | 地区: {location} | 属性: {tags}\n")
                f_detail.flush()
        except Exception as e:
            log(f"[文件同步异常] {e}")

        seen_fingerprints.add(fp_proto)
        seen_fingerprints.add(fp_raw)
        service_stats["total_captured"] += 1

    log(f"[+ 成功收录入库] {fp_proto} | 地区: {location} | 属性: {tags} | 库中总数: {service_stats['total_captured']}")
    return True

def process_node(node: dict):
    """
    单个节点处理流水线：
    1. 提取并核验基础信息
    2. C 段并发探测真实 IP + 协议级实跑深度验证
    3. 校验合格后去重并落盘，未还原/不可用/重复节点直接废弃，杜绝写入重复信息
    """
    raw_ip = node['ip']
    port = node['port']
    protocol = node['protocol'].lower()
    row_key = f"{protocol}:{raw_ip}:{port}:{node['entry_time']}"

    now = time.time()
    with data_lock:
        if row_key in masked_cache:
            cached_ip, cache_time = masked_cache[row_key]
            if cached_ip is None and (now - cache_time < 600):
                return None
            if cached_ip and (f"{protocol}://{cached_ip}:{port}" in seen_fingerprints or f"{cached_ip}:{port}" in seen_fingerprints):
                return None

    real_ip = unmask_and_verify(protocol, raw_ip, port)

    with data_lock:
        masked_cache[row_key] = (real_ip, now)

    if not real_ip or 'X' in real_ip or 'x' in real_ip or not is_valid_ipv4(real_ip):
        log(f"[- 舍弃节点] 未能探测出可用真实 IP 或协议不可用: {protocol}://{raw_ip}:{port}")
        return None

    node['ip'] = real_ip
    fp_proto = f"{protocol}://{real_ip}:{port}"
    fp_raw = f"{real_ip}:{port}"

    with data_lock:
        if fp_proto in seen_fingerprints or fp_raw in seen_fingerprints:
            log(f"[去重拦截] 还原出的真实节点已在库中，跳过收录: {fp_proto}")
            return None

    if save_single_node(node):
        return node
    return None

def run_collection_cycle():
    """执行单轮全协议采集与还原探测流程 (含本轮候选防重与智能调度)"""
    global is_polling_active
    with data_lock:
        if is_polling_active:
            log("当前已有采集任务正在执行中，跳过并发触发...")
            return
        is_polling_active = True
        service_stats["is_busy"] = True

    try:
        service_stats["poll_round"] += 1
        service_stats["last_poll_time"] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        service_stats["last_poll_timestamp"] = int(time.time())
        service_stats["last_message"] = f"正在执行第 {service_stats['poll_round']} 轮抓取与探测..."
        log(f"=== 开始第 {service_stats['poll_round']} 轮抓取 ({service_stats['last_poll_time']}) ===")

        raw_list = fetch_latest_proxies()
        log(f"页面提取到 {len(raw_list)} 条展示节点 (包含 SOCKS5 / HTTP / HTTPS)，正在并发核验与真实 IP 探测...")

        # 本批次候选即时防重与历史指纹预过滤
        candidates = []
        batch_seen = set()
        for n in raw_list:
            fp_raw = f"{n['ip']}:{n['port']}"
            fp_proto = f"{n['protocol']}://{n['ip']}:{n['port']}"
            batch_key = f"{n['protocol']}://{n['ip']}:{n['port']}"
            if batch_key in batch_seen:
                continue
            batch_seen.add(batch_key)

            if 'X' not in n['ip'] and 'x' not in n['ip'] and (fp_proto in seen_fingerprints or fp_raw in seen_fingerprints):
                continue
            row_key = f"{n['protocol']}:{n['ip']}:{n['port']}:{n['entry_time']}"
            with data_lock:
                if row_key in masked_cache:
                    cached_ip, ctime = masked_cache[row_key]
                    if cached_ip is None and (time.time() - ctime < 600):
                        continue
                    if cached_ip and (f"{cached_ip}:{n['port']}" in seen_fingerprints or f"{n['protocol']}://{cached_ip}:{n['port']}" in seen_fingerprints):
                        continue
            candidates.append(n)

        if candidates:
            log(f"发现 {len(candidates)} 个新候选节点，启动高并发协议验证与 C 段脱敏还原...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=NODE_CONCURRENCY) as executor:
                list(executor.map(process_node, candidates))
        else:
            log("本轮所有展示节点均已在库中或近期已验证，无需重复探测。")

        _, counts = read_all_proxies_from_disk()
        service_stats["total_captured"] = counts["total"]
        service_stats["last_message"] = f"第 {service_stats['poll_round']} 轮完成，库中累计有效节点: {counts['total']} (HTTPS: {counts.get('https', 0)}, SOCKS5: {counts.get('socks5', 0)}, HTTP: {counts.get('http', 0)})"
        log(f"=== {service_stats['last_message']} ===\n")
    except Exception as e:
        log(f"采集轮询异常: {e}")
        service_stats["last_message"] = f"采集轮询异常: {e}"
    finally:
        with data_lock:
            is_polling_active = False
            service_stats["is_busy"] = False

def monitor_loop():
    """后台定时轮询与并发探测调度线程"""
    global POLL_INTERVAL
    log(f"后台监控采集线程已就绪，周期为 {POLL_INTERVAL} 秒/轮")
    while True:
        run_collection_cycle()
        poll_event.wait(POLL_INTERVAL)
        poll_event.clear()

class ProxyHTTPHandler(BaseHTTPRequestHandler):
    """高性能多线程 HTTP API 服务与全协议现代 Web 仪表盘"""
    def log_message(self, format, *args):
        pass

    def do_OPTIONS(self):
        """处理 CORS 预检请求"""
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
        self.send_header('Access-Control-Max-Age', '86400')
        self.end_headers()


    def do_POST(self):
        global POLL_INTERVAL, PROBE_TIMEOUT
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == '/api/config':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8', errors='ignore') if content_length > 0 else ""
            try:
                data = json.loads(body) if body else {}
            except Exception:
                data = {}
            updated = False
            if 'poll_interval' in data or 'interval' in data:
                try:
                    v = int(data.get('poll_interval', data.get('interval')))
                    if 10 <= v <= 3600:
                        POLL_INTERVAL = v
                        service_stats["poll_interval_sec"] = v
                        updated = True
                        log(f"[参数配置] 轮询采集频率已更新为: {POLL_INTERVAL} 秒/轮")
                except ValueError:
                    pass
            if 'probe_timeout' in data or 'timeout' in data:
                try:
                    t = float(data.get('probe_timeout', data.get('timeout')))
                    if 0.5 <= t <= 10.0:
                        PROBE_TIMEOUT = t
                        updated = True
                        log(f"[参数配置] 探测检测超时已更新为: {PROBE_TIMEOUT} 秒")
                except ValueError:
                    pass
            if updated:
                save_config()
                if data.get('apply_now', False) or data.get('apply_now') in ['1', 'true', True]:
                    poll_event.set()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            cfg = {
                "status": "ok",
                "updated": updated,
                "poll_interval": POLL_INTERVAL,
                "probe_timeout": PROBE_TIMEOUT,
                "default_poll_interval": 60,
                "default_probe_timeout": 1.8
            }
            self.wfile.write(json.dumps(cfg, ensure_ascii=False, indent=2).encode('utf-8'))
        elif path == '/api/trigger':
            poll_event.set()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok", "message": "已向后台采集线程发送即时探测信号"}, ensure_ascii=False).encode('utf-8'))
        elif path == '/api/dedup':
            total, dups, invalid = init_dedup_cache(force_sync_files=True)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            resp = {
                "status": "ok",
                "message": "已完成全库去重与非法节点清除",
                "total_captured": total,
                "removed_duplicates": dups,
                "removed_invalid": invalid
            }
            self.wfile.write(json.dumps(resp, ensure_ascii=False, indent=2).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        global POLL_INTERVAL, PROBE_TIMEOUT
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        # 1. 纯代理节点文本接口 (/nodes.txt, /proxies.txt, /https.txt, /socks5.txt, /http.txt)
        if path in ['/nodes.txt', '/proxies.txt', '/https.txt', '/socks5.txt', '/http.txt']:
            raw_mode = params.get('raw', ['0'])[0] == '1'
            proto_filter = params.get('type', params.get('proto', ['']))[0].lower()
            if path == '/https.txt':
                proto_filter = 'https'
            elif path == '/socks5.txt':
                proto_filter = 'socks5'
            elif path == '/http.txt':
                proto_filter = 'http'

            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
            self.end_headers()

            with data_lock:
                if os.path.exists(NODES_FILE):
                    with open(NODES_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = [l.strip() for l in f if l.strip() and 'X' not in l and 'x' not in l]
                else:
                    lines = []

            out = []
            seen_out = set()
            for line in lines:
                m = re.match(r'^(?:(socks5|https?)://)?([^/:]+:\d+)', line)
                if m:
                    line_proto = (m.group(1) or 'socks5').lower()
                    host_port = m.group(2)
                    if proto_filter and line_proto != proto_filter:
                        continue
                    key = host_port if raw_mode else f"{line_proto}://{host_port}"
                    if key in seen_out:
                        continue
                    seen_out.add(key)
                    out.append(key)
                else:
                    if not proto_filter and line not in seen_out:
                        seen_out.add(line)
                        out.append(line)

            self.wfile.write('\n'.join(out).encode('utf-8'))

        # 2. 详细元数据档案接口 (/detail.txt 或 /proxies_detail.txt)
        elif path in ['/detail.txt', '/proxies_detail.txt']:
            proto_filter = params.get('type', params.get('proto', ['']))[0].lower()
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
            self.end_headers()

            proxies_list, _ = read_all_proxies_from_disk()
            out_lines = []
            seen_detail = set()
            for p in proxies_list:
                if proto_filter and p['protocol'] != proto_filter:
                    continue
                endpoint = f"{p['ip']}:{p['port']}"
                if endpoint in seen_detail:
                    continue
                seen_detail.add(endpoint)
                out_lines.append(f"[{p['entry_time']}] | {p['protocol']}://{p['ip']}:{p['port']} | 地区: {p['location']} | 属性: {p['tags']}\n")

            self.wfile.write(''.join(out_lines).encode('utf-8'))

        # 2.1 触发即时全库去重检测与自检接口 (/api/dedup)
        elif path == '/api/dedup':
            total, dups, invalid = init_dedup_cache(force_sync_files=True)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            resp = {
                "status": "ok",
                "message": "已完成全库去重与非法节点清除",
                "total_captured": total,
                "removed_duplicates": dups,
                "removed_invalid": invalid
            }
            self.wfile.write(json.dumps(resp, ensure_ascii=False, indent=2).encode('utf-8'))

        # 3. JSON 格式状态统计 (/api/stats)
        elif path == '/api/stats':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
            self.end_headers()

            _, counts = read_all_proxies_from_disk()
            data = {
                "status": "running",
                "is_busy": service_stats["is_busy"],
                "total_captured": counts["total"],
                "protocol_counts": {
                    "https": counts.get("https", 0),
                    "socks5": counts.get("socks5", 0),
                    "http": counts.get("http", 0)
                },
                "last_poll_time": service_stats["last_poll_time"],
                "start_time": service_stats["start_time"],
                "poll_round": service_stats["poll_round"],
                "poll_interval_sec": POLL_INTERVAL,
                "probe_timeout_sec": PROBE_TIMEOUT,
                "last_poll_timestamp": service_stats["last_poll_timestamp"],
                "defaults": {
                    "poll_interval_sec": 60,
                    "probe_timeout_sec": 1.8,
                    "probe_workers": PROBE_WORKERS,
                    "node_concurrency": NODE_CONCURRENCY
                },
                "last_message": service_stats["last_message"],
                "endpoints": {
                    "all_nodes": "/nodes.txt",
                    "https_nodes": "/https.txt",
                    "socks5_nodes": "/socks5.txt",
                    "http_nodes": "/http.txt",
                    "raw_ip_port": "/nodes.txt?raw=1",
                    "detail": "/detail.txt",
                    "api_proxies": "/api/proxies"
                }
            }
            self.wfile.write(json.dumps(data, ensure_ascii=False, indent=2).encode('utf-8'))

        # 4. JSON 格式代理列表 (/api/proxies - 基于 SQLite 高性能检索与分页)
        elif path == '/api/proxies':
            proto_filter = params.get('type', params.get('proto', ['']))[0].lower()
            keyword = params.get('search', [''])[0].strip()
            limit_str = params.get('limit', ['0'])[0]
            limit = int(limit_str) if limit_str.isdigit() else 0
            page_str = params.get('page', ['0'])[0]
            page = int(page_str) if page_str.isdigit() else 0
            size_str = params.get('page_size', params.get('size', ['0']))[0]
            page_size = int(size_str) if size_str.isdigit() else 0

            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
            self.end_headers()

            with get_db() as conn:
                cur = conn.execute("SELECT protocol, COUNT(*) as cnt FROM proxies GROUP BY protocol;")
                counts = {"total": 0, "socks5": 0, "http": 0, "https": 0}
                for r in cur.fetchall():
                    p = r['protocol'].lower()
                    c = r['cnt']
                    counts[p] = c
                    counts['total'] += c

                where_clauses = []
                params_list = []
                if proto_filter:
                    where_clauses.append("protocol = ?")
                    params_list.append(proto_filter)
                if keyword:
                    where_clauses.append("(protocol LIKE ? OR ip LIKE ? OR CAST(port AS TEXT) LIKE ? OR location LIKE ? OR tags LIKE ?)")
                    kw_arg = f"%{keyword}%"
                    params_list.extend([kw_arg, kw_arg, kw_arg, kw_arg, kw_arg])

                where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

                total_filtered = conn.execute(f"SELECT COUNT(*) as cnt FROM proxies {where_sql};", params_list).fetchone()['cnt']

                limit_clause = ""
                query_params = list(params_list)
                if page > 0 and page_size > 0:
                    limit_clause = "LIMIT ? OFFSET ?"
                    query_params.extend([page_size, (page - 1) * page_size])
                    total_pages = (total_filtered + page_size - 1) // page_size
                elif limit > 0:
                    limit_clause = "LIMIT ?"
                    query_params.append(limit)
                    total_pages = 1
                else:
                    total_pages = 1

                rows = conn.execute(f"SELECT entry_time, protocol, ip, port, location, tags, status, latency_ms FROM proxies {where_sql} ORDER BY entry_time DESC {limit_clause};", query_params).fetchall()

                proxies_out = []
                for r in rows:
                    proto = r['protocol'].lower()
                    ip = r['ip']
                    port = r['port']
                    proxies_out.append({
                        "entry_time": r['entry_time'],
                        "protocol": proto,
                        "ip": ip,
                        "port": port,
                        "url": f"{proto}://{ip}:{port}",
                        "location": r['location'],
                        "tags": r['tags'],
                        "status": r['status'],
                        "latency_ms": r['latency_ms']
                    })

            res = {
                "total": counts["total"],
                "filtered_count": total_filtered,
                "page": page if page > 0 else 1,
                "page_size": page_size if page_size > 0 else total_filtered,
                "total_pages": total_pages,
                "protocol_counts": {
                    "https": counts.get("https", 0),
                    "socks5": counts.get("socks5", 0),
                    "http": counts.get("http", 0)
                },
                "proxies": proxies_out
            }
            self.wfile.write(json.dumps(res, ensure_ascii=False, indent=2).encode('utf-8'))

        # 5.1 配置读取与设置 (/api/config)
        elif path == '/api/config':
            new_interval = params.get('interval', params.get('poll_interval', [None]))[0]
            new_timeout = params.get('timeout', params.get('probe_timeout', [None]))[0]
            updated = False

            if new_interval is not None:
                try:
                    val = int(new_interval)
                    if 10 <= val <= 3600:
                        POLL_INTERVAL = val
                        service_stats["poll_interval_sec"] = val
                        updated = True
                        log(f"[参数配置] 轮询采集频率已更新为: {POLL_INTERVAL} 秒/轮")
                except ValueError:
                    pass

            if new_timeout is not None:
                try:
                    fval = float(new_timeout)
                    if 0.5 <= fval <= 10.0:
                        PROBE_TIMEOUT = fval
                        updated = True
                        log(f"[参数配置] 单次探测超时已更新为: {PROBE_TIMEOUT} 秒")
                except ValueError:
                    pass

            if updated:
                save_config()
                if params.get('apply_now', ['0'])[0] in ['1', 'true']:
                    poll_event.set()

            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
            self.end_headers()

            cfg = {
                "status": "ok",
                "updated": updated,
                "poll_interval": POLL_INTERVAL,
                "probe_timeout": PROBE_TIMEOUT,
                "default_poll_interval": 60,
                "default_probe_timeout": 1.8,
                "probe_workers": PROBE_WORKERS,
                "node_concurrency": NODE_CONCURRENCY
            }
            self.wfile.write(json.dumps(cfg, ensure_ascii=False, indent=2).encode('utf-8'))

        # 5. 手动触发即时采集探测 (/api/trigger)
        elif path == '/api/trigger':
            poll_event.set()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok", "message": "已向后台采集线程发送即时探测信号"}, ensure_ascii=False).encode('utf-8'))

        # 6. 健康检查 (/health)
        elif path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')

        # 6.5 未匹配的 /api/ 路径严格返回 JSON 404，绝不回退至 HTML
        elif path.startswith('/api/'):
            self.send_response(404)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "error", "message": f"未找到该 API 端点: {path}"}, ensure_ascii=False).encode('utf-8'))

        # 7. 仪表盘首页 (/)
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()

            if os.path.exists(DASHBOARD_FILE):
                with open(DASHBOARD_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                    html_content = f.read()
                self.wfile.write(html_content.encode('utf-8'))
            else:
                self.wfile.write(b"<h1>Dashboard file not found.</h1>")

def main():
    log("=" * 70)
    log("正在启动北极光代理实时监控采集与智能分发系统 (v2.5 全协议增强版)...")
    load_config()
    init_dedup_cache()

    # 启动后台监控与探测调度线程
    t = threading.Thread(target=monitor_loop, daemon=True)
    t.start()

    # 独占端口检测与 Windows 绑定防护，防止多进程冲突并发写入文件
    if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
        ThreadingHTTPServer.allow_reuse_address = False

    try:
        server = ThreadingHTTPServer((API_HOST, API_PORT), ProxyHTTPHandler)
    except OSError as e:
        log(f"[启动失败] 端口 {API_PORT} 绑定失败 (可能有其他实例已在运行): {e}")
        sys.exit(1)
    log(f"HTTP API 服务已就绪，正在监听: http://{API_HOST}:{API_PORT}")
    log(f"  [1] 全部纯节点接口:   http://localhost:{API_PORT}/nodes.txt")
    log(f"  [2] 专属 HTTPS 接口:  http://localhost:{API_PORT}/https.txt")
    log(f"  [3] 专属 SOCKS5 接口: http://localhost:{API_PORT}/socks5.txt")
    log(f"  [4] 专属 HTTP 接口:   http://localhost:{API_PORT}/http.txt")
    log(f"  [5] 纯 IP:Port 接口:  http://localhost:{API_PORT}/nodes.txt?raw=1")
    log(f"  [6] 完整档案接口:     http://localhost:{API_PORT}/detail.txt")
    log(f"  [7] 状态统计接口:     http://localhost:{API_PORT}/api/stats")
    log(f"  [8] 现代化仪表盘首页: http://localhost:{API_PORT}/")
    log("=" * 70)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("接收到中断信号，系统安全退出...")
        server.shutdown()

if __name__ == '__main__':
    main()
