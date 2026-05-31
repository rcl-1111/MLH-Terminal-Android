"""
WNAD - HTTP 代理服务器模块
纯 Python 实现 HTTP/HTTPS 正向代理
无 root 要求，支持 CONNECT 隧道
"""

import socket
import select
import threading
import time
from urllib.parse import urlparse
from core.utils import C, CHECK, CROSS, INFO


BUFSIZE = 8192


def _handle_client(client_sock, addr, stats):
    """处理单个客户端请求"""
    try:
        request = client_sock.recv(BUFSIZE)
        if not request:
            return

        first_line = request.split(b"\r\n")[0].decode(errors="replace")

        # HTTPS CONNECT 隧道
        if first_line.upper().startswith("CONNECT"):
            parts = first_line.split()
            if len(parts) >= 2:
                host_port = parts[1]
                host, _, port_str = host_port.partition(":")
                port = int(port_str) if port_str else 443

                try:
                    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    remote.settimeout(10)
                    remote.connect((host, port))
                    client_sock.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    stats["https_conn"] += 1

                    # 双向隧道
                    socks = [client_sock, remote]
                    while True:
                        r, _, _ = select.select(socks, [], [], 60)
                        if not r:
                            break
                        for s in r:
                            data = s.recv(BUFSIZE)
                            if not data:
                                raise ConnectionError
                            dst = remote if s is client_sock else client_sock
                            dst.send(data)
                except Exception:
                    pass
                finally:
                    try:
                        remote.close()
                    except Exception:
                        pass

        # HTTP 正向代理
        elif first_line.startswith("GET") or first_line.startswith("POST") or first_line.startswith("HEAD"):
            parts = first_line.split()
            if len(parts) >= 2:
                url = parts[1]
                parsed = urlparse(url)
                host = parsed.hostname
                port = parsed.port or 80
                path = parsed.path or "/"
                if parsed.query:
                    path += "?" + parsed.query

                try:
                    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    remote.settimeout(10)
                    remote.connect((host, port))

                    # 重写请求行，去掉绝对 URL 部分
                    new_request = request.replace(
                        url.encode(),
                        path.encode(),
                        1
                    )
                    remote.send(new_request)
                    stats["http_req"] += 1

                    while True:
                        data = remote.recv(BUFSIZE)
                        if not data:
                            break
                        client_sock.send(data)
                except Exception:
                    pass
                finally:
                    try:
                        remote.close()
                    except Exception:
                        pass

    except Exception:
        pass
    finally:
        stats["total"] += 1
        try:
            client_sock.close()
        except Exception:
            pass


def run_proxy(bind_ip: str = "127.0.0.1", port: int = 8080, max_clients: int = 50):
    """
    启动 HTTP 代理服务器
    - 支持 HTTP 正向代理
    - 支持 HTTPS CONNECT 隧道
    """
    stats = {"total": 0, "http_req": 0, "https_conn": 0}
    running = True

    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((bind_ip, port))
        server.listen(max_clients)
        server.settimeout(3)
    except Exception as e:
        print(f" {CROSS} 无法启动代理: {e}")
        return

    print(f" {CHECK} HTTP 代理服务器已启动:")
    print(f"   地址: {C.CYAN}http://{bind_ip}:{port}{C.NC}")
    print(f"   支持: HTTP 正向代理 + HTTPS CONNECT 隧道")
    print(f" {INFO} 按 Ctrl+C 停止\n")

    try:
        while running:
            try:
                client, addr = server.accept()
                t = threading.Thread(target=_handle_client, args=(client, addr, stats), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except Exception:
                break

    except KeyboardInterrupt:
        print(f"\n {INFO} 用户中断")

    finally:
        running = False
        server.close()
        print(f"\n {CHECK} 代理服务器已停止")
        print(f"   HTTP 请求: {stats['http_req']}")
        print(f"   HTTPS 隧道: {stats['https_conn']}")
        print(f"   总处理: {stats['total']}")
