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
import csv
import io
import signal
import gzip
import base64

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
DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data.db")  # SQLite 本地数据库文件
DASHBOARD_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.html")
TARGET_URL = "https://proxy-socks5.com/proxy_list"
POLL_INTERVAL = 60                   # 轮询采集周期 (秒)
PROBE_WORKERS = 48                   # C段单节点探测并发线程数 (削峰优化，防套接字风暴)
PROBE_TIMEOUT = 1.8                  # 协议检测单次超时 (秒)
NODE_CONCURRENCY = 3                 # 同时并发处理的目标节点数
HEALTH_CHECK_INTERVAL = 60           # 存量节点健康检查与测速周期 (秒)
UPSTREAM_PROXY = ""                  # 上游代理 (例如 http://127.0.0.1:10808，为空时自动探测)
# ==================================================

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

DEFAULT_CONFIG = {
    "api_host": API_HOST,
    "api_port": API_PORT,
    "poll_interval": POLL_INTERVAL,
    "probe_timeout": PROBE_TIMEOUT,
    "probe_workers": PROBE_WORKERS,
    "node_concurrency": NODE_CONCURRENCY,
    "health_check_interval": HEALTH_CHECK_INTERVAL,
    "upstream_proxy": UPSTREAM_PROXY,
    "target_url": TARGET_URL,
    "db_file": "data.db"
}

def load_config() -> dict:
    """从 config.json 加载持久化配置，若不存在则使用预设默认值并自动创建"""
    global POLL_INTERVAL, PROBE_TIMEOUT, PROBE_WORKERS, NODE_CONCURRENCY, API_HOST, API_PORT, DB_FILE, HEALTH_CHECK_INTERVAL, UPSTREAM_PROXY
    cfg = DEFAULT_CONFIG.copy()
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8-sig') as f:
                saved = json.load(f)
                if isinstance(saved, dict):
                    cfg.update(saved)
                    POLL_INTERVAL = int(cfg.get('poll_interval', POLL_INTERVAL))
                    PROBE_TIMEOUT = float(cfg.get('probe_timeout', PROBE_TIMEOUT))
                    PROBE_WORKERS = int(cfg.get('probe_workers', PROBE_WORKERS))
                    NODE_CONCURRENCY = int(cfg.get('node_concurrency', NODE_CONCURRENCY))
                    HEALTH_CHECK_INTERVAL = int(cfg.get('health_check_interval', HEALTH_CHECK_INTERVAL))
                    UPSTREAM_PROXY = str(cfg.get('upstream_proxy', UPSTREAM_PROXY)).strip()
                    API_HOST = str(cfg.get('api_host', API_HOST))
                    API_PORT = int(cfg.get('api_port', API_PORT))
                    
                    db_val = str(cfg.get('db_file', 'data.db')).strip()
                    # 跨平台路径自适应：在非 Windows 环境检测到 Windows 绝对路径时自动回退为相对路径
                    if os.name != 'nt' and re.match(r'^[a-zA-Z]:[\\/]', db_val):
                        log(f"[跨平台兼容] 检测到 Windows 格式绝对路径 '{db_val}'，在 {sys.platform} 下自动回退为相对路径 'data.db'")
                        db_val = "data.db"
                    
                    if not os.path.isabs(db_val):
                        DB_FILE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), db_val))
                    else:
                        DB_FILE = db_val

            # 环境变量覆盖 (支持云原生容器与 Linux 部署环境配置)
            if os.getenv("PROXY_API_HOST"):
                API_HOST = os.getenv("PROXY_API_HOST")
            if os.getenv("PROXY_API_PORT"):
                try:
                    API_PORT = int(os.getenv("PROXY_API_PORT"))
                except ValueError:
                    pass
            if os.getenv("PROXY_POLL_INTERVAL"):
                try:
                    POLL_INTERVAL = int(os.getenv("PROXY_POLL_INTERVAL"))
                except ValueError:
                    pass
            if os.getenv("PROXY_PROBE_TIMEOUT"):
                try:
                    PROBE_TIMEOUT = float(os.getenv("PROXY_PROBE_TIMEOUT"))
                except ValueError:
                    pass
            if os.getenv("PROXY_PROBE_WORKERS"):
                try:
                    PROBE_WORKERS = int(os.getenv("PROXY_PROBE_WORKERS"))
                except ValueError:
                    pass
            if os.getenv("PROXY_NODE_CONCURRENCY"):
                try:
                    NODE_CONCURRENCY = int(os.getenv("PROXY_NODE_CONCURRENCY"))
                except ValueError:
                    pass
            if os.getenv("PROXY_HEALTH_CHECK_INTERVAL"):
                try:
                    HEALTH_CHECK_INTERVAL = int(os.getenv("PROXY_HEALTH_CHECK_INTERVAL"))
                except ValueError:
                    pass
            if os.getenv("PROXY_UPSTREAM_PROXY"):
                UPSTREAM_PROXY = os.getenv("PROXY_UPSTREAM_PROXY").strip()
            if os.getenv("PROXY_TARGET_URL"):
                TARGET_URL = os.getenv("PROXY_TARGET_URL")
            if os.getenv("PROXY_DB_FILE"):
                env_db = os.getenv("PROXY_DB_FILE")
                if not os.path.isabs(env_db):
                    DB_FILE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), env_db))
                else:
                    DB_FILE = env_db

            log(f"已加载配置文件 {CONFIG_FILE} (采集周期: {POLL_INTERVAL}s, 探测超时: {PROBE_TIMEOUT}s, 存储: {DB_FILE})")
        except Exception as e:
            log(f"读取配置文件异常，使用默认值: {e}")
    else:
        save_config(cfg)
        log(f"已初始化生成配置文件: {CONFIG_FILE}")
    return cfg

def save_config(cfg: dict = None) -> bool:
    """将当前内存配置持久化写入 config.json 文件"""
    global POLL_INTERVAL, PROBE_TIMEOUT, PROBE_WORKERS, NODE_CONCURRENCY, API_HOST, API_PORT, DB_FILE, HEALTH_CHECK_INTERVAL, UPSTREAM_PROXY
    if cfg is None:
        cfg = DEFAULT_CONFIG.copy()
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r', encoding='utf-8-sig') as f:
                    saved = json.load(f)
                    if isinstance(saved, dict):
                        cfg.update(saved)
            except Exception:
                pass
        cfg["poll_interval"] = POLL_INTERVAL
        cfg["probe_timeout"] = PROBE_TIMEOUT
        cfg["probe_workers"] = PROBE_WORKERS
        cfg["node_concurrency"] = NODE_CONCURRENCY
        cfg["health_check_interval"] = HEALTH_CHECK_INTERVAL
        cfg["upstream_proxy"] = UPSTREAM_PROXY
        cfg["api_host"] = API_HOST
        cfg["api_port"] = API_PORT
        if "db_file" not in cfg or (os.path.isabs(str(cfg.get("db_file", ""))) and os.path.basename(str(cfg.get("db_file", ""))) == "data.db"):
            cfg["db_file"] = "data.db"

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
data_lock = threading.RLock()
poll_event = threading.Event()
health_check_event = threading.Event()
is_polling_active = False
is_health_checking = False

service_stats = {
    "total_captured": 0,
    "active_count": 0,
    "dead_count": 0,
    "avg_latency_ms": 0.0,
    "min_latency_ms": 0.0,
    "last_poll_time": "尚未轮询",
    "last_poll_timestamp": 0,
    "start_time": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    "poll_round": 0,
    "is_busy": False,
    "is_health_checking": False,
    "last_message": "服务已初始化，等待轮询采集与健康体检",
    "health_stats": {}
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

def verify_proxy_with_timing(proto: str, ip: str, port: int, timeout: float = PROBE_TIMEOUT) -> tuple[bool, float]:
    """带实测 RTT 毫秒延迟的可用性验证，返回 (ok, latency_ms)"""
    t0 = time.perf_counter()
    ok = verify_proxy_candidate(proto, ip, port, timeout)
    lat = round((time.perf_counter() - t0) * 1000.0, 1) if ok else 0.0
    return (ok, lat)

def unmask_and_verify(proto: str, masked_ip: str, port: int) -> tuple[str, float] | None:
    """
    对目标 IP 进行真实地址探测与协议可用性双重验证：
    - 针对包含 X 掩码的 C 段节点进行并发实测，秒级还原真实 IP；
    - 加入 stop_event 早停机制，首个通畅 IP 命中后立即取消剩余探测，避免套接字风暴；
    - 返回 (real_ip, latency_ms)，失败返回 None。
    """
    parts = masked_ip.split('.')
    if len(parts) != 4:
        return None

    if 'X' in parts[2] or 'x' in parts[2]:
        prefix = f"{parts[0]}.{parts[1]}"
        suffix = parts[3]
        found_ip = None
        found_lat = 0.0
        stop_event = threading.Event()

        def probe_candidate(candidate_ip):
            if stop_event.is_set():
                return None, 0.0
            ok, lat = verify_proxy_with_timing(proto, candidate_ip, port, timeout=PROBE_TIMEOUT)
            if ok and not stop_event.is_set():
                stop_event.set()
                return candidate_ip, lat
            return None, 0.0

        with concurrent.futures.ThreadPoolExecutor(max_workers=PROBE_WORKERS) as ex:
            futures = [ex.submit(probe_candidate, f"{prefix}.{c}.{suffix}") for c in range(256)]
            for fut in concurrent.futures.as_completed(futures):
                try:
                    res = fut.result()
                    if res and res[0]:
                        found_ip, found_lat = res
                        for rem in futures:
                            rem.cancel()
                        break
                except Exception:
                    pass

        if found_ip and is_valid_ipv4(found_ip):
            return found_ip, found_lat
        return None
    else:
        if is_valid_ipv4(masked_ip):
            ok, lat = verify_proxy_with_timing(proto, masked_ip, port, timeout=PROBE_TIMEOUT)
            if ok:
                return masked_ip, lat
        return None


# ==================== SQLite 本地数据库核心层 ====================
def get_db():
    """获取配置了 WAL 模式与行字典的 SQLite 数据库连接"""
    db_dir = os.path.dirname(os.path.abspath(DB_FILE))
    if db_dir and not os.path.exists(db_dir):
        try:
            os.makedirs(db_dir, exist_ok=True)
        except Exception:
            pass
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
        conn.execute("CREATE INDEX IF NOT EXISTS idx_proxies_latency ON proxies(latency_ms ASC);")

        # 检查是否需要从现有 detail.txt 自动迁移历史数据
        cursor = conn.execute("SELECT COUNT(*) AS cnt FROM proxies;")
        cnt = cursor.fetchone()['cnt']
        if cnt == 0 and os.path.exists("detail.txt"):
            log(f"首次初始化 SQLite 数据库，正在从 detail.txt 自动迁移历史合法节点...")
            migrated = 0
            with open("detail.txt", 'r', encoding='utf-8', errors='ignore') as f:
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
    """（已废弃磁盘文件导出，直接由 SQLite 数据库对外提供实时订阅查询）"""
    pass

def read_all_proxies_from_disk(proto_filter="", status_filter="active", sort_by="latency"):
    """
    从 SQLite 数据库高效读取结构化代理列表与全维度统计
    默认过滤离线失效节点 (status='active')，并按真实延迟由低到高升序排列
    """
    proxies_list = []
    counts = {
        "total": 0, "active": 0, "dead": 0,
        "socks5": 0, "http": 0, "https": 0,
        "active_socks5": 0, "active_http": 0, "active_https": 0,
        "dead_socks5": 0, "dead_http": 0, "dead_https": 0,
        "avg_latency": 0.0, "min_latency": 0.0
    }

    try:
        with get_db() as conn:
            cur = conn.execute("SELECT status, protocol, COUNT(*) as cnt FROM proxies GROUP BY status, protocol;")
            for r in cur.fetchall():
                st = r['status'].lower()
                proto = r['protocol'].lower()
                c = r['cnt']
                counts['total'] += c
                counts[proto] = counts.get(proto, 0) + c
                if st == 'active':
                    counts['active'] += c
                    counts[f"active_{proto}"] = counts.get(f"active_{proto}", 0) + c
                else:
                    counts['dead'] += c
                    counts[f"dead_{proto}"] = counts.get(f"dead_{proto}", 0) + c

            lat_row = conn.execute("SELECT AVG(latency_ms) as avg_lat, MIN(latency_ms) as min_lat FROM proxies WHERE status='active' AND latency_ms > 0;").fetchone()
            if lat_row and lat_row['avg_lat'] is not None:
                counts['avg_latency'] = round(lat_row['avg_lat'], 1)
                counts['min_latency'] = round(lat_row['min_lat'], 1)

            where_clauses = ["ip NOT LIKE '%X%'", "ip NOT LIKE '%x%'"]
            params = []
            if proto_filter and proto_filter.lower() not in ('', 'all'):
                where_clauses.append("protocol = ?")
                params.append(proto_filter.lower())
            if status_filter and status_filter.lower() not in ('', 'all'):
                where_clauses.append("status = ?")
                params.append(status_filter.lower())

            where_sql = "WHERE " + " AND ".join(where_clauses)
            if sort_by == 'latency':
                order_sql = "ORDER BY (CASE WHEN latency_ms > 0 THEN latency_ms ELSE 99999 END) ASC, entry_time DESC"
            else:
                order_sql = "ORDER BY entry_time DESC"

            rows = conn.execute(f"SELECT entry_time, protocol, ip, port, location, tags, status, latency_ms FROM proxies {where_sql} {order_sql};", params).fetchall()
            for r in rows:
                p_proto = r['protocol'].lower()
                proxies_list.append({
                    "entry_time": r['entry_time'],
                    "protocol": p_proto,
                    "ip": r['ip'],
                    "port": r['port'],
                    "url": f"{p_proto}://{r['ip']}:{r['port']}",
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
            active_cnt = sum(1 for r in rows if dict(r).get('status', 'active') == 'active')
            service_stats["active_count"] = active_cnt
            service_stats["dead_count"] = len(rows) - active_cnt
            log(f"[本地数据库就绪] 已加载 {len(rows)} 个唯一合法总节点 (有效: {active_cnt}, 离线: {len(rows) - active_cnt} | 存储文件: {DB_FILE})")
            return len(rows), 0, 0
# ==============================================================

def get_upstream_opener():
    """获取访问目标源站的上游代理 opener，支持自动侦测本地常用代理"""
    proxy_url = UPSTREAM_PROXY
    if not proxy_url:
        for candidate in ["http://127.0.0.1:10808", "http://127.0.0.1:10809", "http://127.0.0.1:7890"]:
            try:
                p_parts = urllib.parse.urlparse(candidate)
                s = socket.socket()
                s.settimeout(0.12)
                s.connect((p_parts.hostname, p_parts.port))
                s.close()
                proxy_url = candidate
                break
            except Exception:
                pass

    if proxy_url:
        handler = urllib.request.ProxyHandler({'http': proxy_url, 'https': proxy_url})
        return urllib.request.build_opener(handler), proxy_url
    return urllib.request.build_opener(), None

def fetch_latest_proxies():
    """从目标网站抓取最新展示的代理列表元数据 (覆盖 SOCKS5 / HTTP / HTTPS 全协议)"""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Referer": "https://proxy-socks5.com/"
    }
    req = urllib.request.Request(TARGET_URL, headers=headers)
    
    html = None
    opener, proxy_used = get_upstream_opener()
    try:
        html = opener.open(req, timeout=12).read().decode('utf-8', errors='ignore')
    except Exception as e1:
        if proxy_used:
            try:
                html = urllib.request.urlopen(req, timeout=10).read().decode('utf-8', errors='ignore')
            except Exception as e2:
                raise RuntimeError(f"代理抓取失败 ({e1}) 且直连失败 ({e2})")
        else:
            raise e1

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
    """流式安全落盘单个已验证节点至 SQLite 本地数据库，严格记录实测延迟"""
    ip = str(node.get('ip', '')).strip()
    try:
        port = int(node.get('port', 0))
    except (ValueError, TypeError):
        return False
    protocol = str(node.get('protocol', 'socks5')).lower().strip()
    if protocol not in ('socks5', 'http', 'https'):
        protocol = 'socks5'

    if not ip or 'X' in ip or 'x' in ip or not is_valid_ipv4(ip) or not (1 <= port <= 65535):
        log(f"[门禁拦截] 发现非法或含掩码节点，坚决拒绝写入: {protocol}://{ip}:{port}")
        return False

    fp_proto = f"{protocol}://{ip}:{port}"
    fp_raw = f"{ip}:{port}"
    latency_ms = float(node.get('latency_ms', 0.0) or 0.0)
    entry_time = node.get('entry_time') or datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    location = node.get('location') or '未知地区'
    tags = node.get('tags') or '[机房]'

    with data_lock:
        try:
            with get_db() as conn:
                conn.execute("""
                    INSERT INTO proxies 
                    (protocol, ip, port, location, tags, entry_time, last_check_time, status, latency_ms, fail_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, 0)
                    ON CONFLICT(ip, port) DO UPDATE SET
                        protocol = excluded.protocol,
                        location = CASE WHEN excluded.location != '未知地区' AND excluded.location != '' THEN excluded.location ELSE proxies.location END,
                        tags = CASE WHEN excluded.tags != '[机房]' AND excluded.tags != '' THEN excluded.tags ELSE proxies.tags END,
                        last_check_time = excluded.last_check_time,
                        status = 'active',
                        latency_ms = excluded.latency_ms,
                        fail_count = 0;
                """, (protocol, ip, port, location, tags, entry_time, entry_time, latency_ms))
                conn.commit()
        except Exception as e:
            log(f"[数据库写入异常] {e}")
            return False

        is_new = (fp_proto not in seen_fingerprints and fp_raw not in seen_fingerprints)
        seen_fingerprints.add(fp_proto)
        seen_fingerprints.add(fp_raw)
        if is_new:
            service_stats["total_captured"] += 1
            service_stats["active_count"] = service_stats.get("active_count", 0) + 1

    log(f"[+ 成功收录入库] {fp_proto} | 延迟: {latency_ms}ms | 地区: {location} | 属性: {tags}")
    return True

def process_node(node: dict):
    """单个节点处理流水线：C 段并发早停探测真实 IP + 实测可用性与延迟"""
    raw_ip = node['ip']
    port = node['port']
    protocol = node['protocol'].lower()
    row_key = f"{protocol}:{raw_ip}:{port}:{node['entry_time']}"

    now = time.time()
    with data_lock:
        if row_key in masked_cache:
            cached_res, cache_time = masked_cache[row_key]
            if cached_res is None and (now - cache_time < 600):
                return None
            if cached_res:
                real_ip_cached = cached_res[0] if isinstance(cached_res, (list, tuple)) else cached_res
                if real_ip_cached and (f"{protocol}://{real_ip_cached}:{port}" in seen_fingerprints or f"{real_ip_cached}:{port}" in seen_fingerprints):
                    return None

    res = unmask_and_verify(protocol, raw_ip, port)
    with data_lock:
        masked_cache[row_key] = (res, now)

    if not res:
        log(f"[- 舍弃节点] 未能探测出可用真实 IP 或协议不可用: {protocol}://{raw_ip}:{port}")
        return None

    real_ip, lat_ms = res
    if not is_valid_ipv4(real_ip):
        return None

    node['ip'] = real_ip
    node['latency_ms'] = lat_ms
    fp_proto = f"{protocol}://{real_ip}:{port}"
    fp_raw = f"{real_ip}:{port}"

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
                    cached_res, ctime = masked_cache[row_key]
                    if cached_res is None and (time.time() - ctime < 600):
                        continue
                    if cached_res:
                        real_ip_cached = cached_res[0] if isinstance(cached_res, (list, tuple)) else cached_res
                        if real_ip_cached and (f"{real_ip_cached}:{n['port']}" in seen_fingerprints or f"{n['protocol']}://{real_ip_cached}:{n['port']}" in seen_fingerprints):
                            continue
            candidates.append(n)

        if candidates:
            log(f"发现 {len(candidates)} 个新候选节点，启动高并发协议验证与 C 段脱敏还原...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=NODE_CONCURRENCY) as executor:
                list(executor.map(process_node, candidates))
        else:
            log("本轮所有展示节点均已在库中或近期已验证，无需重复探测。")

        _, counts = read_all_proxies_from_disk(status_filter="all")
        service_stats["total_captured"] = counts["total"]
        service_stats["active_count"] = counts["active"]
        service_stats["dead_count"] = counts["dead"]
        service_stats["last_message"] = f"第 {service_stats['poll_round']} 轮完成，库中累计总节点: {counts['total']} (有效: {counts.get('active', 0)}, 离线: {counts.get('dead', 0)} | HTTPS: {counts.get('https', 0)}, SOCKS5: {counts.get('socks5', 0)}, HTTP: {counts.get('http', 0)})"
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
        try:
            run_collection_cycle()
        except Exception as e:
            log(f"[监控线程异常] {e}")
        poll_event.wait(POLL_INTERVAL)
        poll_event.clear()

# ==================== 全量节点健康体检与低延迟测速引擎 ====================
def run_health_check_cycle():
    """
    全量存量节点健康检查与低延迟真实测速：
    1. 从数据库读取节点进行全协议真实连接与 RTT 测速
    2. 存活节点刷新 latency_ms、last_check_time 并标记为 'active'
    3. 离线节点递增 fail_count，达到阈值标记为 'dead'
    4. 彻底解决客户端导入后因死节点导致的卡顿与超时问题
    """
    global is_health_checking
    with data_lock:
        if is_health_checking:
            return
        is_health_checking = True
        service_stats["is_health_checking"] = True

    try:
        with get_db() as conn:
            rows = conn.execute("SELECT id, protocol, ip, port, status, fail_count FROM proxies;").fetchall()

        if not rows:
            return

        log(f"[健康测速] 开始对全库 {len(rows)} 个节点执行可用性与低延迟测速...")
        t0 = time.time()

        def test_one_node(r):
            nid, proto, ip, port = r['id'], r['protocol'], r['ip'], r['port']
            ok, lat = verify_proxy_with_timing(proto, ip, port, timeout=PROBE_TIMEOUT)
            return nid, ok, lat

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(48, len(rows))) as ex:
            results = list(ex.map(test_one_node, rows))

        alive_cnt = 0
        dead_cnt = 0
        lats = []
        now_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        with get_db() as conn:
            for nid, ok, lat in results:
                if ok:
                    alive_cnt += 1
                    lats.append(lat)
                    conn.execute("""
                        UPDATE proxies 
                        SET status = 'active', latency_ms = ?, last_check_time = ?, fail_count = 0
                        WHERE id = ?;
                    """, (lat, now_str, nid))
                else:
                    dead_cnt += 1
                    conn.execute("""
                        UPDATE proxies 
                        SET status = 'dead', latency_ms = 0.0, fail_count = fail_count + 1, last_check_time = ?
                        WHERE id = ?;
                    """, (now_str, nid))
            conn.commit()

        elapsed = round(time.time() - t0, 2)
        avg_lat = round(sum(lats) / len(lats), 1) if lats else 0.0
        min_lat = min(lats) if lats else 0.0

        service_stats["active_count"] = alive_cnt
        service_stats["dead_count"] = dead_cnt
        service_stats["avg_latency_ms"] = avg_lat
        service_stats["min_latency_ms"] = min_lat
        service_stats["health_stats"] = {
            "last_check_time": now_str,
            "total_tested": len(rows),
            "alive_count": alive_cnt,
            "dead_count": dead_cnt,
            "min_latency_ms": min_lat,
            "avg_latency_ms": avg_lat,
            "elapsed_sec": elapsed
        }
        log(f"[健康测速完成] 耗时 {elapsed}s | 存活: {alive_cnt} 个, 离线: {dead_cnt} 个 | 最低延迟: {min_lat}ms, 平均延迟: {avg_lat}ms")
    except Exception as e:
        log(f"[健康测速异常] {e}")
    finally:
        with data_lock:
            is_health_checking = False
            service_stats["is_health_checking"] = False

def health_check_loop():
    """后台独立健康体检与低延迟测速循环线程"""
    global HEALTH_CHECK_INTERVAL
    time.sleep(2)
    while True:
        try:
            run_health_check_cycle()
        except Exception as e:
            log(f"[健康测速线程异常] {e}")
        health_check_event.wait(HEALTH_CHECK_INTERVAL)
        health_check_event.clear()

# ==================== 数据导入导出与数据库增强引擎 ====================
_ip_location_cache = {}
_ip_location_lock = threading.Lock()

def resolve_ip_location(ip: str) -> tuple[str, str]:
    """
    智能查询 IP 物理归属地与网络运营商。
    返回: (location, tags)
    """
    if not ip or not is_valid_ipv4(ip):
        return ("未知地区", "[人工导入]")

    # 私有 / 局域网判断
    if ip.startswith(('127.', '10.', '192.168.', '169.254.', '0.')) or (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31):
        return ("局域网/专用网络", "[专用内网]")

    with _ip_location_lock:
        if ip in _ip_location_cache:
            return _ip_location_cache[ip]

    loc = ""
    tag = "[人工导入]"
    try:
        req = urllib.request.Request(
            f"http://ip-api.com/json/{ip}?lang=zh-CN",
            headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            if data.get('status') == 'success':
                country = data.get('country', '').strip()
                region = data.get('regionName', '').strip()
                city = data.get('city', '').strip()
                isp = data.get('isp', '').strip()
                loc_parts = []
                for p in [country, region, city]:
                    if p and p not in loc_parts:
                        loc_parts.append(p)
                loc = " ".join(loc_parts)
                if isp:
                    short_isp = isp.split()[0]
                    tag = f"[{short_isp}]"
    except Exception:
        pass

    if not loc:
        loc = "人工导入"

    with _ip_location_lock:
        _ip_location_cache[ip] = (loc, tag)

    return (loc, tag)





def parse_import_payload(raw_content: str, default_proto: str = "socks5") -> list:
    """
    智能解析用户导入的文本，完整提取全部元数据：
    协议(protocol)、IP(ip)、端口(port)、详细地理位置(location)、标签(tags)、
    入库时间(entry_time)、最后检测时间(last_check_time)、状态(status)、延迟(latency_ms)、失败次数(fail_count)。
    支持格式：JSON、标准/自定义 CSV、Detail 元数据文本、带协议 URI、纯 IP:PORT 等。
    """
    candidates = []
    text = (raw_content or "").strip().lstrip('﻿')
    if not text:
        return candidates

    # 1. 尝试 JSON 解析 (支持 [{"ip":...}] 或 {"proxies": [...]} 或纯字符串数组)
    if (text.startswith('[') and text.endswith(']')) or (text.startswith('{') and text.endswith('}')):
        try:
            parsed = json.loads(text)
            items = parsed if isinstance(parsed, list) else (parsed.get('proxies') or parsed.get('data') or [])
            for item in items:
                if isinstance(item, dict):
                    ip = str(item.get('ip', '')).strip()
                    try:
                        port = int(item.get('port', 0))
                    except (ValueError, TypeError):
                        continue
                    proto = str(item.get('protocol') or item.get('proto') or item.get('type') or default_proto).lower().strip()
                    loc = str(item.get('location') or item.get('geo') or item.get('country') or '').strip()
                    tags = str(item.get('tags') or item.get('tag') or '').strip()
                    entry_time = str(item.get('entry_time') or item.get('time') or '').strip()
                    last_check_time = str(item.get('last_check_time') or '').strip()
                    status = str(item.get('status') or 'active').strip().lower()

                    try:
                        latency_ms = float(item.get('latency_ms', 0.0) or 0.0)
                    except (ValueError, TypeError):
                        latency_ms = 0.0
                    try:
                        fail_count = int(item.get('fail_count', 0) or 0)
                    except (ValueError, TypeError):
                        fail_count = 0

                    if not loc:
                        loc, auto_tag = resolve_ip_location(ip)
                        if not tags:
                            tags = auto_tag

                    candidates.append({
                        "protocol": proto,
                        "ip": ip,
                        "port": port,
                        "location": loc or "人工导入",
                        "tags": tags or "[自定义]",
                        "entry_time": entry_time,
                        "last_check_time": last_check_time,
                        "status": status if status in ('active', 'dead') else 'active',
                        "latency_ms": latency_ms,
                        "fail_count": fail_count
                    })
                elif isinstance(item, str):
                    m = re.match(r'(?:(socks5|https?|http)://)?([0-9.]+):([0-9]+)', item.strip(), re.I)
                    if m:
                        p, ip, port = m.group(1) or default_proto, m.group(2), int(m.group(3))
                        loc, auto_tag = resolve_ip_location(ip)
                        candidates.append({
                            "protocol": p.lower(),
                            "ip": ip,
                            "port": port,
                            "location": loc,
                            "tags": auto_tag,
                            "entry_time": "",
                            "last_check_time": "",
                            "status": "active",
                            "latency_ms": 0.0,
                            "fail_count": 0
                        })
            if candidates:
                return candidates
        except Exception:
            pass

    # 2. 尝试标准/自定义 CSV 解析 (基于 csv.reader，处理带表头、含逗号和转义的完整表格)
    if ',' in text:
        try:
            reader = csv.reader(io.StringIO(text))
            rows = [r for r in reader if r and any(cell.strip() for cell in r)]
            if rows:
                first_row = [c.strip().lower() for c in rows[0]]
                header_keys = [c.replace(' ', '').replace('_', '') for c in first_row]
                has_header = any(k in ('ip', 'port', 'protocol', 'proto', 'type', 'id', 'location', '地区', '入库时间', 'status') for k in header_keys)

                if has_header:
                    col_map = {k: idx for idx, k in enumerate(header_keys)}
                    for r in rows[1:]:
                        if not r:
                            continue

                        def get_col(keys: list, default=''):
                            for k in keys:
                                idx = col_map.get(k)
                                if idx is not None and idx < len(r):
                                    v = r[idx].strip()
                                    if v:
                                        return v
                            return default

                        ip = get_col(['ip', 'ipaddress', 'ip地址', 'host', 'node'])
                        port_str = get_col(['port', '端口'])
                        if not ip or not port_str:
                            continue
                        try:
                            port = int(port_str)
                        except ValueError:
                            continue

                        proto = get_col(['protocol', 'proto', 'type', '协议'], default_proto).lower()
                        loc = get_col(['location', 'geo', '地区', '省市', '位置'])
                        tags = get_col(['tags', 'tag', '属性', '标签'])
                        entry_time = get_col(['entrytime', '入库时间', 'time', '时间'])
                        last_check_time = get_col(['lastchecktime', '检测时间', '最后检测时间'])
                        status = get_col(['status', '状态'], 'active').lower()

                        try:
                            latency_ms = float(get_col(['latencyms', 'latency', '延迟'], '0.0'))
                        except ValueError:
                            latency_ms = 0.0
                        try:
                            fail_count = int(get_col(['failcount', '失败次数'], '0'))
                        except ValueError:
                            fail_count = 0

                        if not loc:
                            loc, auto_tag = resolve_ip_location(ip)
                            if not tags:
                                tags = auto_tag

                        candidates.append({
                            "protocol": proto,
                            "ip": ip,
                            "port": port,
                            "location": loc or "人工导入",
                            "tags": tags or "[自定义]",
                            "entry_time": entry_time,
                            "last_check_time": last_check_time,
                            "status": status if status in ('active', 'dead') else 'active',
                            "latency_ms": latency_ms,
                            "fail_count": fail_count
                        })
                    if candidates:
                        return candidates
        except Exception:
            pass

    # 3. 逐行规则与 Detail / 无表头 CSV / URI / 纯 IP 解析
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        # 模式 A: detail.txt 格式: [时间] | proto://ip:port | 地区: xxx | 属性: yyy [| 状态: zzz | 延迟: nnnms]
        detail_m = re.match(
            r'(?:\[(.*?)\]\s*\|\s*)?(socks5|https?)://([^:]+):(\d+)'
            r'(?:\s*\|\s*地区:\s*(.*?))?'
            r'(?:\s*\|\s*属性:\s*(.*?))?'
            r'(?:\s*\|\s*状态:\s*(.*?))?'
            r'(?:\s*\|\s*延迟:\s*([0-9.]+)ms)?$',
            line, re.I
        )
        if detail_m:
            e_time, proto, ip, port_str, loc, tags, st, lat = detail_m.groups()
            try:
                port = int(port_str)
                lat_ms = float(lat) if lat else 0.0
                st_val = (st or 'active').strip().lower()
                candidates.append({
                    "protocol": proto.lower(),
                    "ip": ip.strip(),
                    "port": port,
                    "location": (loc or "人工导入").strip(),
                    "tags": (tags or "[自定义]").strip(),
                    "entry_time": (e_time or "").strip(),
                    "last_check_time": (e_time or "").strip(),
                    "status": st_val if st_val in ('active', 'dead') else 'active',
                    "latency_ms": lat_ms,
                    "fail_count": 0
                })
                continue
            except ValueError:
                pass

        # 模式 B: 无表头的 CSV 行 (例如: id,proto,ip,port,loc,tags,entry_time... 或 proto,ip,port...)
        if ',' in line:
            parts = [p.strip() for p in line.split(',')]
            if len(parts) >= 2:
                # 检查第一列是否是数字且第二列是协议 (例如系统导出的无表头格式: id, protocol, ip, port, ...)
                if parts[0].isdigit() and len(parts) >= 4 and parts[1].lower() in ('socks5', 'http', 'https'):
                    try:
                        proto = parts[1].lower()
                        ip = parts[2]
                        port = int(parts[3])
                        loc = parts[4] if len(parts) > 4 else ''
                        tags = parts[5] if len(parts) > 5 else ''
                        e_time = parts[6] if len(parts) > 6 else ''
                        l_check = parts[7] if len(parts) > 7 else ''
                        st = parts[8].lower() if len(parts) > 8 and parts[8].lower() in ('active', 'dead') else 'active'
                        try:
                            lat = float(parts[9]) if len(parts) > 9 else 0.0
                        except ValueError:
                            lat = 0.0
                        try:
                            fc = int(parts[10]) if len(parts) > 10 else 0
                        except ValueError:
                            fc = 0
                        if not loc:
                            loc, auto_tag = resolve_ip_location(ip)
                            if not tags:
                                tags = auto_tag
                        candidates.append({
                            "protocol": proto,
                            "ip": ip,
                            "port": port,
                            "location": loc or "人工导入",
                            "tags": tags or "[自定义]",
                            "entry_time": e_time,
                            "last_check_time": l_check,
                            "status": st,
                            "latency_ms": lat,
                            "fail_count": fc
                        })
                        continue
                    except (ValueError, IndexError):
                        pass

                # 协议开头的行 (proto, ip, port, loc, tags, ...)
                if parts[0].lower() in ('socks5', 'http', 'https'):
                    proto = parts[0].lower()
                    ip = parts[1]
                    try:
                        port = int(parts[2])
                        loc = parts[3] if len(parts) > 3 else ''
                        tags = parts[4] if len(parts) > 4 else ''
                        e_time = parts[5] if len(parts) > 5 else ''
                        if not loc:
                            loc, auto_tag = resolve_ip_location(ip)
                            if not tags:
                                tags = auto_tag
                        candidates.append({
                            "protocol": proto,
                            "ip": ip,
                            "port": port,
                            "location": loc or "人工导入",
                            "tags": tags or "[自定义]",
                            "entry_time": e_time,
                            "last_check_time": e_time,
                            "status": "active",
                            "latency_ms": 0.0,
                            "fail_count": 0
                        })
                        continue
                    except (ValueError, IndexError):
                        pass

                # IP 开头的行 (ip, port, proto, loc, tags, ...)
                if is_valid_ipv4(parts[0]):
                    ip = parts[0]
                    try:
                        port = int(parts[1])
                        proto = parts[2].lower() if len(parts) > 2 and parts[2].lower() in ('socks5', 'http', 'https') else default_proto
                        loc = parts[3] if len(parts) > 3 else ''
                        tags = parts[4] if len(parts) > 4 else ''
                        e_time = parts[5] if len(parts) > 5 else ''
                        if not loc:
                            loc, auto_tag = resolve_ip_location(ip)
                            if not tags:
                                tags = auto_tag
                        candidates.append({
                            "protocol": proto,
                            "ip": ip,
                            "port": port,
                            "location": loc or "人工导入",
                            "tags": tags or "[自定义]",
                            "entry_time": e_time,
                            "last_check_time": e_time,
                            "status": "active",
                            "latency_ms": 0.0,
                            "fail_count": 0
                        })
                        continue
                    except (ValueError, IndexError):
                        pass

        # 模式 C: 带协议 URI 正则搜索 (socks5://1.2.3.4:1080)
        uri_m = re.search(r'(socks5|https?|http)://([0-9.]+):([0-9]{1,5})', line, re.I)
        if uri_m:
            proto, ip, port_str = uri_m.groups()
            try:
                port = int(port_str)
                loc, auto_tag = resolve_ip_location(ip)
                candidates.append({
                    "protocol": proto.lower(),
                    "ip": ip,
                    "port": port,
                    "location": loc,
                    "tags": auto_tag,
                    "entry_time": "",
                    "last_check_time": "",
                    "status": "active",
                    "latency_ms": 0.0,
                    "fail_count": 0
                })
                continue
            except ValueError:
                pass

        # 模式 D: 纯 IP:PORT 正则搜索 (1.2.3.4:1080)
        ip_port_m = re.search(r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):([0-9]{1,5})', line)
        if ip_port_m:
            ip, port_str = ip_port_m.groups()
            try:
                port = int(port_str)
                loc, auto_tag = resolve_ip_location(ip)
                candidates.append({
                    "protocol": default_proto.lower(),
                    "ip": ip,
                    "port": port,
                    "location": loc,
                    "tags": auto_tag,
                    "entry_time": "",
                    "last_check_time": "",
                    "status": "active",
                    "latency_ms": 0.0,
                    "fail_count": 0
                })
            except ValueError:
                pass

    return candidates


def batch_import_nodes(candidates: list, verify_now: bool = False, max_verify_workers: int = 16) -> dict:
    """
    批量导入节点主流水线：
    1. 质量门禁过滤（合法 IPv4、反 X 节点、端口范围 1~65535）
    2. 指纹库与批次内去重
    3. 可选并发实跑可用性探活（verify_now=True）
    4. 批量原子写入 SQLite，完整保留全部元数据（entry_time, location, tags, latency_ms 等）并同步更新内存指纹
    """
    stats = {
        "status": "ok",
        "total_parsed": len(candidates),
        "success_imported": 0,
        "duplicates_skipped": 0,
        "invalid_filtered": 0,
        "verify_failed": 0
    }
    if not candidates:
        stats["message"] = "未解析到有效候选节点"
        return stats

    now_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    pre_filtered = []
    seen_in_batch = set()

    for c in candidates:
        ip = str(c.get('ip', '')).strip()
        try:
            port = int(c.get('port', 0))
        except (ValueError, TypeError):
            stats["invalid_filtered"] += 1
            continue

        proto = str(c.get('protocol', 'socks5')).lower().strip()
        if proto not in ('socks5', 'http', 'https'):
            proto = 'socks5'

        # 门禁 1: IPv4 有效性、反 X 节点、端口 1~65535
        if not ip or 'x' in ip.lower() or not is_valid_ipv4(ip) or not (1 <= port <= 65535):
            stats["invalid_filtered"] += 1
            continue

        fp_proto = f"{proto}://{ip}:{port}"
        fp_raw = f"{ip}:{port}"

        # 批次内自去重
        if fp_proto in seen_in_batch or fp_raw in seen_in_batch:
            stats["duplicates_skipped"] += 1
            continue
        seen_in_batch.add(fp_proto)
        seen_in_batch.add(fp_raw)

        # 门禁 2: 内存指纹库去重
        with data_lock:
            if fp_proto in seen_fingerprints or fp_raw in seen_fingerprints:
                stats["duplicates_skipped"] += 1
                continue

        # 完整保留原始元数据
        e_time = str(c.get('entry_time') or '').strip()
        if not re.match(r'^\d{4}-\d{2}-\d{2}', e_time):
            e_time = now_str

        l_check = str(c.get('last_check_time') or '').strip()
        if not re.match(r'^\d{4}-\d{2}-\d{2}', l_check):
            l_check = e_time

        st = str(c.get('status') or 'active').strip().lower()
        if st not in ('active', 'dead'):
            st = 'active'

        try:
            lat = float(c.get('latency_ms', 0.0) or 0.0)
        except (ValueError, TypeError):
            lat = 0.0

        try:
            fc = int(c.get('fail_count', 0) or 0)
        except (ValueError, TypeError):
            fc = 0

        pre_filtered.append({
            "protocol": proto,
            "ip": ip,
            "port": port,
            "location": str(c.get('location') or '人工导入').strip(),
            "tags": str(c.get('tags') or '[自定义]').strip(),
            "entry_time": e_time,
            "last_check_time": l_check,
            "status": st,
            "latency_ms": lat,
            "fail_count": fc
        })

    if not pre_filtered:
        stats["message"] = f"解析出 {stats['total_parsed']} 条，其中 {stats['duplicates_skipped']} 条重复，{stats['invalid_filtered']} 条非法"
        return stats

    # 可选并发探活
    survivors = []
    if verify_now:
        log(f"[批量导入] 正在对 {len(pre_filtered)} 个候选节点执行即时可用性验证...")
        workers = min(max_verify_workers, max(1, len(pre_filtered)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_node = {
                executor.submit(verify_proxy_with_timing, item['protocol'], item['ip'], item['port'], PROBE_TIMEOUT): item
                for item in pre_filtered
            }
            for future in concurrent.futures.as_completed(future_to_node):
                node_item = future_to_node[future]
                try:
                    ok, lat_measured = future.result()
                    if ok:
                        node_item['status'] = 'active'
                        node_item['latency_ms'] = lat_measured
                        node_item['last_check_time'] = now_str
                        survivors.append(node_item)
                    else:
                        stats["verify_failed"] += 1
                except Exception:
                    stats["verify_failed"] += 1
    else:
        survivors = pre_filtered

    if not survivors:
        stats["message"] = f"验证完成，候选节点均未通过存活测试 (失败 {stats['verify_failed']} 个)"
        return stats

    # 批量入库 - 完整写入全部 10 个数据字段！
    insert_rows = [
        (s['protocol'], s['ip'], s['port'], s['location'], s['tags'],
         s['entry_time'], s['last_check_time'], s['status'], s['latency_ms'], s['fail_count'])
        for s in survivors
    ]

    with data_lock:
        try:
            with get_db() as conn:
                cur = conn.executemany("""
                    INSERT OR IGNORE INTO proxies 
                    (protocol, ip, port, location, tags, entry_time, last_check_time, status, latency_ms, fail_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, insert_rows)
                conn.commit()

                # 将入库成功的节点加入内存指纹
                actual_inserted = 0
                for s in survivors:
                    fp_p = f"{s['protocol']}://{s['ip']}:{s['port']}"
                    fp_r = f"{s['ip']}:{s['port']}"
                    seen_fingerprints.add(fp_p)
                    seen_fingerprints.add(fp_r)
                    actual_inserted += 1

                stats["success_imported"] = cur.rowcount if cur.rowcount >= 0 else actual_inserted
                stats["duplicates_skipped"] += (len(survivors) - stats["success_imported"])
                service_stats["total_captured"] += stats["success_imported"]
        except Exception as e:
            log(f"[批量导入写入异常] {e}")
            stats["status"] = "error"
            stats["message"] = f"数据库写入异常: {e}"
            return stats

    stats["message"] = f"成功导入 {stats['success_imported']} 个节点，跳过 {stats['duplicates_skipped']} 个重复节点，过滤 {stats['invalid_filtered']} 个无效节点"
    if verify_now:
        stats["message"] += f"，探活未通过 {stats['verify_failed']} 个"
    log(f"[批量导入] {stats['message']}")
    return stats


def export_proxies_data(export_fmt: str = "csv", proto_filter: str = "all", status_filter: str = "all", raw: bool = False, keyword: str = ""):
    """全量/条件检索数据库并导出为指定格式内容 (CSV / JSON / TXT / DETAIL / SQLITE)"""
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    export_fmt = (export_fmt or "csv").lower().strip()

    if export_fmt in ('sqlite', 'db'):
        with get_db() as src_conn:
            dest_conn = sqlite3.connect(":memory:")
            src_conn.backup(dest_conn)
            db_bytes = dest_conn.serialize()
            return db_bytes, "application/octet-stream", f"proxies_backup_{ts}.db"

    with get_db() as conn:
        where_clauses = ["ip NOT LIKE '%X%'", "ip NOT LIKE '%x%'"]
        params_list = []
        if proto_filter and proto_filter.lower() not in ('', 'all'):
            where_clauses.append("protocol = ?")
            params_list.append(proto_filter.lower())
        if status_filter and status_filter.lower() not in ('', 'all'):
            where_clauses.append("status = ?")
            params_list.append(status_filter.lower())
        if keyword:
            where_clauses.append("(protocol LIKE ? OR ip LIKE ? OR CAST(port AS TEXT) LIKE ? OR location LIKE ? OR tags LIKE ?)")
            kw_arg = f"%{keyword.strip()}%"
            params_list.extend([kw_arg, kw_arg, kw_arg, kw_arg, kw_arg])

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
        rows = conn.execute(f"""
            SELECT id, protocol, ip, port, location, tags, entry_time, last_check_time, status, latency_ms, fail_count 
            FROM proxies {where_sql} 
            ORDER BY (CASE WHEN latency_ms > 0 THEN latency_ms ELSE 99999 END) ASC, entry_time DESC;
        """, params_list).fetchall()

    if export_fmt == 'json':
        proxies_out = []
        for r in rows:
            p = r['protocol'].lower()
            proxies_out.append({
                "id": r['id'],
                "protocol": p,
                "ip": r['ip'],
                "port": r['port'],
                "url": f"{p}://{r['ip']}:{r['port']}",
                "location": r['location'],
                "tags": r['tags'],
                "entry_time": r['entry_time'],
                "last_check_time": r['last_check_time'],
                "status": r['status'],
                "latency_ms": r['latency_ms'],
                "fail_count": r['fail_count']
            })
        payload = {
            "status": "ok",
            "total": len(proxies_out),
            "exported_at": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "filters": {
                "protocol": proto_filter or "all",
                "status": status_filter or "all",
                "keyword": keyword
            },
            "proxies": proxies_out
        }
        content = json.dumps(payload, ensure_ascii=False, indent=2).encode('utf-8')
        return content, "application/json; charset=utf-8", f"proxies_export_{ts}.json"

    elif export_fmt == 'txt':
        lines = []
        seen = set()
        for r in rows:
            line_str = f"{r['ip']}:{r['port']}" if raw else f"{r['protocol'].lower()}://{r['ip']}:{r['port']}"
            if line_str not in seen:
                seen.add(line_str)
                lines.append(line_str)
        content = chr(10).join(lines).encode('utf-8')
        return content, "text/plain; charset=utf-8", f"proxies_export_{ts}.txt"

    elif export_fmt == 'detail':
        lines = []
        seen = set()
        for r in rows:
            ep = f"{r['ip']}:{r['port']}"
            if ep not in seen:
                seen.add(ep)
                lines.append(f"[{r['entry_time']}] | {r['protocol'].lower()}://{r['ip']}:{r['port']} | 地区: {r['location']} | 属性: {r['tags']} | 状态: {r['status']} | 延迟: {r['latency_ms']}ms")
        content = chr(10).join(lines).encode('utf-8')
        return content, "text/plain; charset=utf-8", f"proxies_detail_export_{ts}.txt"

    else:  # 默认 CSV
        output = io.StringIO()
        # 写入 UTF-8 BOM，方便 Windows Excel 打开不乱码
        output.write('﻿')
        writer = csv.writer(output)
        writer.writerow(["id", "protocol", "ip", "port", "location", "tags", "entry_time", "last_check_time", "status", "latency_ms", "fail_count"])
        for r in rows:
            writer.writerow([r['id'], r['protocol'], r['ip'], r['port'], r['location'], r['tags'], r['entry_time'], r['last_check_time'], r['status'], r['latency_ms'], r['fail_count']])
        content = output.getvalue().encode('utf-8')
        return content, "text/csv; charset=utf-8", f"proxies_export_{ts}.csv"



def get_db_stats() -> dict:
    """获取 SQLite 数据库元数据、文件大小及全维度统计"""
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) as cnt FROM proxies;").fetchone()['cnt']
        active = conn.execute("SELECT COUNT(*) as cnt FROM proxies WHERE status = 'active';").fetchone()['cnt']
        dead = total - active
        counts = {"socks5": 0, "http": 0, "https": 0}
        for r in conn.execute("SELECT protocol, COUNT(*) as cnt FROM proxies WHERE status = 'active' GROUP BY protocol;").fetchall():
            counts[r['protocol'].lower()] = r['cnt']
        lat_row = conn.execute("SELECT AVG(latency_ms) as avg_lat, MIN(latency_ms) as min_lat FROM proxies WHERE status = 'active' AND latency_ms > 0;").fetchone()

    db_size = os.path.getsize(DB_FILE) if os.path.exists(DB_FILE) else 0
    size_str = f"{db_size / 1024:.1f} KB" if db_size < 1024 * 1024 else f"{db_size / (1024 * 1024):.2f} MB"
    return {
        "status": "ok",
        "db_file": DB_FILE,
        "db_size_bytes": db_size,
        "db_size_formatted": size_str,
        "total_nodes": total,
        "active_nodes": active,
        "dead_nodes": dead,
        "avg_latency_ms": round(lat_row['avg_lat'], 1) if lat_row and lat_row['avg_lat'] else 0.0,
        "min_latency_ms": round(lat_row['min_lat'], 1) if lat_row and lat_row['min_lat'] else 0.0,
        "protocol_counts": counts,
        "wal_mode": True
    }


def clear_db_records(mode: str = "failed") -> dict:
    """清理数据库记录：'failed' 清理非 active 或失活节点，'all' 清空全量节点"""
    global seen_fingerprints
    with data_lock:
        with get_db() as conn:
            if mode == 'all':
                cur = conn.execute("DELETE FROM proxies;")
                conn.execute("VACUUM;")
                deleted = cur.rowcount
            else:
                cur = conn.execute("DELETE FROM proxies WHERE status != 'active' OR fail_count > 0;")
                deleted = cur.rowcount
            conn.commit()

        # 重新同步内存指纹
        init_dedup_cache(force_sync_files=False)
    return {
        "status": "ok",
        "mode": mode,
        "deleted_count": deleted,
        "total_remaining": service_stats["total_captured"]
    }

class ProxyHTTPHandler(BaseHTTPRequestHandler):
    """高性能多线程 HTTP API 引擎与全协议实时分发 Web 仪表盘"""
    
    def log_message(self, format, *args):
        pass

    def address_string(self):
        # 禁用反向 DNS 域名解析，杜绝代理环境下域名反查卡顿
        return self.client_address[0]

    def setup(self):
        super().setup()
        try:
            self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass

    def send_bytes(self, content: bytes, content_type: str = "text/plain; charset=utf-8", status_code: int = 200, extra_headers: dict = None):
        """统一高性能响应发送：支持智能 Gzip 压缩、严格 Content-Length 与 Keep-Alive 声明"""
        accept_encoding = self.headers.get("Accept-Encoding", "")
        skip_gzip_paths = ['/nodes.txt', '/socks5.txt', '/https.txt', '/http.txt']
        req_path = getattr(self, 'path', '').split('?')[0]
        use_gzip = "gzip" in accept_encoding and len(content) > 512 and (req_path not in skip_gzip_paths)

        final_body = gzip.compress(content, compresslevel=6) if use_gzip else content

        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(final_body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Connection", "keep-alive")
        if use_gzip:
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Vary", "Accept-Encoding")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(final_body)

    def send_json(self, data: dict | list, status_code: int = 200, extra_headers: dict = None):
        content = json.dumps(data, ensure_ascii=False, indent=2).encode('utf-8')
        self.send_bytes(content, content_type="application/json; charset=utf-8", status_code=status_code, extra_headers=extra_headers)

    def send_text(self, text: str, content_type: str = "text/plain; charset=utf-8", status_code: int = 200, extra_headers: dict = None):
        self.send_bytes(text.encode('utf-8'), content_type=content_type, status_code=status_code, extra_headers=extra_headers)

    def do_OPTIONS(self):
        """处理 CORS 预检请求"""
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
        self.send_header('Access-Control-Max-Age', '86400')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_POST(self):
        global POLL_INTERVAL, PROBE_TIMEOUT, HEALTH_CHECK_INTERVAL, UPSTREAM_PROXY
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == '/api/config':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8', errors='ignore') if content_length > 0 else ""
            try: data = json.loads(body) if body else {}
            except Exception: data = {}
            updated = False

            if 'poll_interval' in data or 'interval' in data:
                try:
                    v = int(data.get('poll_interval', data.get('interval')))
                    if 10 <= v <= 3600:
                        POLL_INTERVAL = v
                        updated = True
                except ValueError: pass

            if 'probe_timeout' in data or 'timeout' in data:
                try:
                    t = float(data.get('probe_timeout', data.get('timeout')))
                    if 0.5 <= t <= 10.0:
                        PROBE_TIMEOUT = t
                        updated = True
                except ValueError: pass

            if 'health_check_interval' in data:
                try:
                    h = int(data.get('health_check_interval'))
                    if 10 <= h <= 3600:
                        HEALTH_CHECK_INTERVAL = h
                        updated = True
                except ValueError: pass

            if 'upstream_proxy' in data:
                UPSTREAM_PROXY = str(data.get('upstream_proxy')).strip()
                updated = True

            if updated:
                save_config()
                if data.get('apply_now', False) or data.get('apply_now') in ['1', 'true', True]:
                    poll_event.set()

            cfg = {
                "status": "ok",
                "updated": updated,
                "poll_interval": POLL_INTERVAL,
                "probe_timeout": PROBE_TIMEOUT,
                "health_check_interval": HEALTH_CHECK_INTERVAL,
                "upstream_proxy": UPSTREAM_PROXY
            }
            self.send_json(cfg)

        elif path == '/api/trigger':
            poll_event.set()
            self.send_json({"status": "ok", "message": "已向后台采集线程发送即时探测信号"})

        elif path == '/api/health_check':
            health_check_event.set()
            threading.Thread(target=run_health_check_cycle, daemon=True).start()
            self.send_json({"status": "ok", "message": "已触发全量节点存活健康复检与低延迟测速"})

        elif path == '/api/dedup':
            total, dups, invalid = init_dedup_cache(force_sync_files=True)
            self.send_json({
                "status": "ok",
                "message": "已完成全库去重与非法节点清除",
                "total_captured": total,
                "removed_duplicates": dups,
                "removed_invalid": invalid
            })

        elif path == '/api/import':
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 15 * 1024 * 1024:
                self.send_json({"status": "error", "message": "上传数据过大，单次限制 15MB"}, status_code=413)
                return

            body = self.rfile.read(content_length).decode('utf-8', errors='ignore') if content_length > 0 else ""
            c_type = self.headers.get('Content-Type', '')
            raw_text = ""
            default_proto = "socks5"
            verify_now = False

            try:
                if 'application/json' in c_type:
                    data = json.loads(body) if body else {}
                    raw_text = data.get('content') or data.get('text') or ""
                    default_proto = str(data.get('default_protocol') or data.get('protocol') or 'socks5').lower()
                    verify_now = bool(data.get('verify_now', False))
                    if not raw_text and ('proxies' in data or isinstance(data, list)):
                        raw_text = json.dumps(data)
                else:
                    raw_text = body
            except Exception:
                raw_text = body

            candidates = parse_import_payload(raw_text, default_proto=default_proto)
            result = batch_import_nodes(candidates, verify_now=verify_now)
            self.send_json(result)

        elif path == '/api/db/vacuum':
            with get_db() as conn:
                conn.execute("VACUUM;")
            self.send_json({"status": "ok", "message": "数据库整理优化已完成 (VACUUM 执行完毕)"})

        elif path == '/api/db/clear':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8', errors='ignore') if content_length > 0 else ""
            try: data = json.loads(body) if body else {}
            except Exception: data = {}
            mode = data.get('mode', 'failed')
            res = clear_db_records(mode=mode)
            self.send_json(res)

        else:
            self.send_json({"status": "error", "message": f"未找到该 POST 接口: {path}"}, status_code=404)

    def do_GET(self):
        global POLL_INTERVAL, PROBE_TIMEOUT, HEALTH_CHECK_INTERVAL, UPSTREAM_PROXY
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        # 1. 纯代理节点文本接口 (/nodes.txt, /proxies.txt, /https.txt, /socks5.txt, /http.txt)
        if path in ['/nodes.txt', '/proxies.txt', '/https.txt', '/socks5.txt', '/http.txt']:
            raw_mode = params.get('raw', ['0'])[0] == '1'
            proto_filter = params.get('type', params.get('proto', ['']))[0].lower()
            if path == '/https.txt': proto_filter = 'https'
            elif path == '/socks5.txt': proto_filter = 'socks5'
            elif path == '/http.txt': proto_filter = 'http'

            alive_param = params.get('alive', ['1'])[0]
            status_filter = 'all' if alive_param in ('0', 'all', 'false') else 'active'
            sort_by = params.get('sort', ['latency'])[0].lower()
            b64_mode = params.get('b64', ['0'])[0] == '1'

            try: max_lat = float(params.get('max_latency', ['0'])[0])
            except ValueError: max_lat = 0.0
            try: limit = int(params.get('limit', ['0'])[0])
            except ValueError: limit = 0

            proxies_list, _ = read_all_proxies_from_disk(proto_filter=proto_filter, status_filter=status_filter, sort_by=sort_by)
            out = []
            seen_out = set()
            for p in proxies_list:
                if max_lat > 0 and (p['latency_ms'] <= 0 or p['latency_ms'] > max_lat):
                    continue
                endpoint = f"{p['ip']}:{p['port']}"
                key = endpoint if raw_mode else f"{p['protocol']}://{endpoint}"
                if key in seen_out:
                    continue
                seen_out.add(key)
                out.append(key)
                if limit > 0 and len(out) >= limit:
                    break

            txt_body = chr(10).join(out).encode('utf-8')
            if b64_mode:
                txt_body = base64.b64encode(txt_body)
            self.send_bytes(txt_body, content_type="text/plain; charset=utf-8", extra_headers={'Cache-Control': 'no-cache, no-store'})

        # 3. 详细元数据档案接口 (/detail.txt 或 /proxies_detail.txt)
        elif path in ['/detail.txt', '/proxies_detail.txt']:
            proto_filter = params.get('type', params.get('proto', ['']))[0].lower()
            alive_param = params.get('alive', ['1'])[0]
            status_filter = 'all' if alive_param in ('0', 'all', 'false') else 'active'
            sort_by = params.get('sort', ['latency'])[0].lower()

            proxies_list, _ = read_all_proxies_from_disk(proto_filter=proto_filter, status_filter=status_filter, sort_by=sort_by)
            out_lines = []
            seen_detail = set()
            for p in proxies_list:
                endpoint = f"{p['ip']}:{p['port']}"
                if endpoint in seen_detail:
                    continue
                seen_detail.add(endpoint)
                lat_str = f"{p['latency_ms']}ms" if p['latency_ms'] else "未测"
                out_lines.append(f"[{p['entry_time']}] | {p['protocol']}://{p['ip']}:{p['port']} | 延迟: {lat_str} | 状态: {p['status']} | 地区: {p['location']} | 属性: {p['tags']}\n")

            self.send_bytes(''.join(out_lines).encode('utf-8'), content_type="text/plain; charset=utf-8", extra_headers={'Cache-Control': 'no-cache, no-store'})

        # 4. JSON 格式状态统计 (/api/stats)
        elif path == '/api/stats':
            _, counts = read_all_proxies_from_disk(status_filter="all")
            data = {
                "status": "running",
                "is_busy": service_stats["is_busy"],
                "is_health_checking": service_stats["is_health_checking"],
                "total_captured": counts["total"],
                "active_count": counts["active"],
                "dead_count": counts["dead"],
                "avg_latency_ms": counts.get("avg_latency", 0.0),
                "min_latency_ms": counts.get("min_latency", 0.0),
                "protocol_counts": {
                    "https": counts.get("https", 0),
                    "socks5": counts.get("socks5", 0),
                    "http": counts.get("http", 0)
                },
                "protocol_active_counts": {
                    "https": counts.get("active_https", 0),
                    "socks5": counts.get("active_socks5", 0),
                    "http": counts.get("active_http", 0)
                },
                "protocol_dead_counts": {
                    "https": counts.get("dead_https", 0),
                    "socks5": counts.get("dead_socks5", 0),
                    "http": counts.get("dead_http", 0)
                },
                "last_poll_time": service_stats["last_poll_time"],
                "start_time": service_stats["start_time"],
                "poll_round": service_stats["poll_round"],
                "poll_interval_sec": POLL_INTERVAL,
                "probe_timeout_sec": PROBE_TIMEOUT,
                "health_check_interval_sec": HEALTH_CHECK_INTERVAL,
                "upstream_proxy": UPSTREAM_PROXY,
                "last_poll_timestamp": service_stats["last_poll_timestamp"],
                "health_stats": service_stats.get("health_stats", {}),
                "last_message": service_stats["last_message"],
                "endpoints": {
                    "all_nodes": "/nodes.txt",
                    "https_nodes": "/https.txt",
                    "socks5_nodes": "/socks5.txt",
                    "http_nodes": "/http.txt",
                    "raw_ip_port": "/nodes.txt?raw=1",
                    "detail": "/detail.txt",
                    "api_proxies": "/api/proxies",
                    "api_export": "/api/export",
                    "api_health_check": "/api/health_check",
                    "api_import": "/api/import",
                    "db_backup": "/api/db/backup",
                    "db_stats": "/api/db/stats"
                }
            }
            self.send_json(data, extra_headers={'Cache-Control': 'no-cache, no-store'})

        # 5. JSON 格式代理列表 (/api/proxies - 基于 SQLite 高性能检索与分页)
        elif path == '/api/proxies':
            proto_filter = params.get('type', params.get('proto', ['']))[0].lower()
            keyword = params.get('search', [''])[0].strip()
            status_filter = params.get('status', [''])[0].lower()
            sort_by = params.get('sort', ['latency'])[0].lower()

            limit_str = params.get('limit', ['0'])[0]
            limit = int(limit_str) if limit_str.isdigit() else 0
            page_str = params.get('page', ['0'])[0]
            page = int(page_str) if page_str.isdigit() else 0
            size_str = params.get('page_size', params.get('size', ['0']))[0]
            page_size = int(size_str) if size_str.isdigit() else 0

            with get_db() as conn:
                cur = conn.execute("SELECT status, protocol, COUNT(*) as cnt FROM proxies GROUP BY status, protocol;")
                counts = {
                    "total": 0, "active": 0, "dead": 0,
                    "socks5": 0, "http": 0, "https": 0,
                    "active_socks5": 0, "active_http": 0, "active_https": 0,
                    "dead_socks5": 0, "dead_http": 0, "dead_https": 0
                }
                for r in cur.fetchall():
                    st = r['status'].lower()
                    p = r['protocol'].lower()
                    c = r['cnt']
                    counts['total'] += c
                    counts[p] = counts.get(p, 0) + c
                    if st == 'active':
                        counts['active'] += c
                        counts[f"active_{p}"] = counts.get(f"active_{p}", 0) + c
                    else:
                        counts['dead'] += c
                        counts[f"dead_{p}"] = counts.get(f"dead_{p}", 0) + c

                where_clauses = ["ip NOT LIKE '%X%'", "ip NOT LIKE '%x%'"]
                params_list = []
                if proto_filter:
                    where_clauses.append("protocol = ?")
                    params_list.append(proto_filter)
                if status_filter and status_filter != 'all':
                    where_clauses.append("status = ?")
                    params_list.append(status_filter)
                if keyword:
                    where_clauses.append("(protocol LIKE ? OR ip LIKE ? OR CAST(port AS TEXT) LIKE ? OR location LIKE ? OR tags LIKE ?)")
                    kw_arg = f"%{keyword}%"
                    params_list.extend([kw_arg, kw_arg, kw_arg, kw_arg, kw_arg])

                where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
                total_filtered = conn.execute(f"SELECT COUNT(*) as cnt FROM proxies {where_sql};", params_list).fetchone()['cnt']

                if sort_by == 'time':
                    order_sql = "ORDER BY entry_time DESC"
                else:
                    order_sql = "ORDER BY (CASE WHEN latency_ms > 0 THEN latency_ms ELSE 99999 END) ASC, entry_time DESC"

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

                rows = conn.execute(f"SELECT entry_time, protocol, ip, port, location, tags, status, latency_ms FROM proxies {where_sql} {order_sql} {limit_clause};", query_params).fetchall()

                proxies_out = []
                for r in rows:
                    proto = r['protocol'].lower()
                    proxies_out.append({
                        "entry_time": r['entry_time'],
                        "protocol": proto,
                        "ip": r['ip'],
                        "port": r['port'],
                        "url": f"{proto}://{r['ip']}:{r['port']}",
                        "location": r['location'],
                        "tags": r['tags'],
                        "status": r['status'],
                        "latency_ms": r['latency_ms']
                    })

            res = {
                "total": counts["total"],
                "active_total": counts["active"],
                "dead_total": counts["dead"],
                "filtered_count": total_filtered,
                "page": page if page > 0 else 1,
                "page_size": page_size if page_size > 0 else total_filtered,
                "total_pages": total_pages,
                "protocol_counts": {
                    "https": counts.get("https", 0),
                    "socks5": counts.get("socks5", 0),
                    "http": counts.get("http", 0)
                },
                "protocol_active_counts": {
                    "https": counts.get("active_https", 0),
                    "socks5": counts.get("active_socks5", 0),
                    "http": counts.get("active_http", 0)
                },
                "protocol_dead_counts": {
                    "https": counts.get("dead_https", 0),
                    "socks5": counts.get("dead_socks5", 0),
                    "http": counts.get("dead_http", 0)
                },
                "proxies": proxies_out
            }
            self.send_json(res, extra_headers={'Cache-Control': 'no-cache, no-store'})

        # 6. 配置读取 (/api/config)
        elif path == '/api/config':
            cfg = {
                "status": "ok",
                "poll_interval": POLL_INTERVAL,
                "probe_timeout": PROBE_TIMEOUT,
                "health_check_interval": HEALTH_CHECK_INTERVAL,
                "upstream_proxy": UPSTREAM_PROXY,
                "probe_workers": PROBE_WORKERS,
                "node_concurrency": NODE_CONCURRENCY
            }
            self.send_json(cfg, extra_headers={'Cache-Control': 'no-cache, no-store'})

        # 7. 手动触发即时采集探测 (/api/trigger)
        elif path == '/api/trigger':
            poll_event.set()
            self.send_json({"status": "ok", "message": "已向后台采集线程发送即时探测信号"})

        # 8. 触发即时全量健康体检与测速 (/api/health_check)
        elif path == '/api/health_check':
            health_check_event.set()
            threading.Thread(target=run_health_check_cycle, daemon=True).start()
            self.send_json({"status": "ok", "message": "已触发全量节点健康检查与低延迟测速"})

        # 9. 健康检查探针 (/health)
        elif path == '/health':
            self.send_bytes(b'{"status":"ok"}', content_type='application/json')

        # 10. 全量多格式数据导出 (/api/export)
        elif path == '/api/export':
            fmt = params.get('format', ['csv'])[0].lower()
            proto = params.get('type', params.get('proto', ['all']))[0].lower()
            status = params.get('status', ['all'])[0].lower()
            raw = params.get('raw', ['0'])[0] == '1'
            kw = params.get('search', params.get('q', ['']))[0].strip()

            content, content_type, filename = export_proxies_data(
                export_fmt=fmt,
                proto_filter=proto,
                status_filter=status,
                raw=raw,
                keyword=kw
            )
            self.send_bytes(content, content_type=content_type, extra_headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Cache-Control': 'no-cache, no-store'
            })

        # 11. 数据库备份与状态
        elif path == '/api/db/backup':
            content, content_type, filename = export_proxies_data(export_fmt="sqlite")
            self.send_bytes(content, content_type=content_type, extra_headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Cache-Control': 'no-cache, no-store'
            })

        elif path == '/api/db/stats':
            stats_info = get_db_stats()
            self.send_json(stats_info, extra_headers={'Cache-Control': 'no-cache, no-store'})

        elif path == '/api/dedup':
            total, dups, invalid = init_dedup_cache(force_sync_files=True)
            self.send_json({
                "status": "ok",
                "message": "已完成全库去重与非法节点清除",
                "total_captured": total,
                "removed_duplicates": dups,
                "removed_invalid": invalid
            })

        elif path.startswith('/api/'):
            self.send_json({"status": "error", "message": f"未找到该 API 节点: {path}"}, status_code=404)

        # 12. 仪表盘首页 (/)
        else:
            if os.path.exists(DASHBOARD_FILE):
                with open(DASHBOARD_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                    html_content = f.read()
                self.send_text(html_content, content_type='text/html; charset=utf-8')
            else:
                self.send_text("<h1>Dashboard file not found.</h1>", content_type='text/html; charset=utf-8', status_code=404)

class SilentThreadingHTTPServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        exc_type, _, _ = sys.exc_info()
        if exc_type in (ConnectionResetError, BrokenPipeError, ConnectionAbortedError, TimeoutError):
            return
        super().handle_error(request, client_address)


def main():
    log("=" * 70)
    log("北极光代理实时监控采集与全协议分发系统 (v2.6 极速优化版)...")
    load_config()
    init_dedup_cache()

    # 1. 启动后台抓取探测守护线程
    t_monitor = threading.Thread(target=monitor_loop, daemon=True)
    t_monitor.start()

    # 2. 启动后台存量节点健康检查与测速守护线程
    t_health = threading.Thread(target=health_check_loop, daemon=True)
    t_health.start()

    if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
        ThreadingHTTPServer.allow_reuse_address = False
    else:
        ThreadingHTTPServer.allow_reuse_address = True

    try:
        server = SilentThreadingHTTPServer((API_HOST, API_PORT), ProxyHTTPHandler)
    except OSError as e:
        log(f"[绑定失败] 端口 {API_PORT} 绑定失败: {e}")
        sys.exit(1)

    stop_event = threading.Event()
    def graceful_shutdown(signum=None, frame=None):
        if not stop_event.is_set():
            stop_event.set()
            sig_name = "SIGTERM" if signum == getattr(signal, "SIGTERM", None) else ("SIGINT" if signum == signal.SIGINT else str(signum))
            log(f"接收到停止信号 ({sig_name})，服务正在优雅退出...")
            threading.Thread(target=server.shutdown, daemon=True).start()

    try:
        signal.signal(signal.SIGINT, graceful_shutdown)
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, graceful_shutdown)
    except Exception:
        pass

    log(f"HTTP API 服务已就绪，正在监听: http://{API_HOST}:{API_PORT}")
    log(f"  [1] 全部纯节点接口:   http://localhost:{API_PORT}/nodes.txt")
    log(f"  [2] 专属 HTTPS 接口:  http://localhost:{API_PORT}/https.txt")
    log(f"  [3] 专属 SOCKS5 接口: http://localhost:{API_PORT}/socks5.txt")
    log(f"  [4] 专属 HTTP 接口:   http://localhost:{API_PORT}/http.txt")
    log(f"  [5] 状态统计接口:     http://localhost:{API_PORT}/api/stats")
    log(f"  [6] 健康检查探针:     http://localhost:{API_PORT}/health")
    log(f"  [7] 现代化仪表盘首页: http://localhost:{API_PORT}/")
    log("=" * 70)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        graceful_shutdown()
    finally:
        server.server_close()
        log("HTTP 服务器后台资源清理完毕，进程安全退出。")

if __name__ == '__main__':
    main()
