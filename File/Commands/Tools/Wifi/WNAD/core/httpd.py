"""
WNAD - HTTP 文件服务器模块
增强版 HTTP 服务器，支持文件浏览和上传
纯 Python http.server 基础扩展
"""

import os
import sys
import json
import socket
import threading
import time
from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler
from io import BytesIO
from urllib.parse import unquote
from core.utils import C, CHECK, CROSS, INFO


class UploadHTTPRequestHandler(SimpleHTTPRequestHandler):
    """支持文件上传的 HTTP 处理器"""

    upload_dir = "/tmp/wnad_uploads"
    server_start = time.time()

    def log_message(self, format, *args):
        """彩色日志"""
        client = self.client_address[0]
        msg = format % args
        print(f" {C.DIM}[HTTP]{C.NC}  {client}  {C.YELLOW}{self.command}{C.NC}  {self.path}  {msg}")

    def do_PUT(self):
        """处理文件上传 (PUT 方法)"""
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            self.send_error(400, "Empty content")
            return

        path = unquote(self.path.lstrip("/"))
        if not path:
            path = f"upload_{int(time.time())}"

        # 确保安全路径
        safe_path = os.path.normpath(os.path.join(self.upload_dir, path))
        if not safe_path.startswith(os.path.normpath(self.upload_dir)):
            self.send_error(403, "Forbidden")
            return

        os.makedirs(os.path.dirname(safe_path), exist_ok=True)

        try:
            data = self.rfile.read(length)
            with open(safe_path, "wb") as f:
                f.write(data)
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = json.dumps({"status": "ok", "file": path, "size": len(data)})
            self.wfile.write(resp.encode())
            print(f" {C.GREEN}[UPLOAD]{C.NC}  {path}  ({len(data)} bytes)")
        except Exception as e:
            self.send_error(500, str(e))

    def do_POST(self):
        """处理文件上传 (POST 表单)"""
        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            # 默认 PUT 行为
            self.do_PUT()
            return

        self.send_error(501, "Multipart upload not supported")
        self.log_message("POST multipart not implemented")

    def list_directory(self, path):
        """增强目录列表"""
        try:
            entries = sorted(os.listdir(path))
        except OSError:
            self.send_error(404, "No permission to list directory")
            return None

        display_path = unquote(self.path)

        html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>WNAD HTTPD - {display_path}</title>
<style>
body {{ font-family: monospace; margin: 20px; background: #1a1a2e; color: #e0e0e0; }}
h1 {{ color: #00d2ff; }}
a {{ color: #00d2ff; text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
table {{ border-collapse: collapse; width: 100%; }}
th {{ text-align: left; padding: 8px; border-bottom: 1px solid #333; color: #888; }}
td {{ padding: 8px; border-bottom: 1px solid #222; }}
tr:hover {{ background: #16213e; }}
.file-size {{ color: #888; }}
.file-time {{ color: #666; }}
.upload-form {{ margin: 20px 0; padding: 15px; background: #16213e; border-radius: 5px; }}
.upload-form input {{ margin: 5px 0; }}
.footer {{ margin-top: 30px; color: #555; font-size: 12px; }}
</style></head><body>
<h1>WNAD HTTPD</h1>
<p>{display_path}</p>
<div class="upload-form">
<form method="post" enctype="multipart/form-data" action="/upload">
<input type="file" name="file">
<input type="submit" value="Upload">
</form>
</div>
<hr><table>
<tr><th>Name</th><th>Size</th><th>Modified</th></tr>
"""
        for name in entries:
            full = os.path.join(path, name)
            display_name = name + "/" if os.path.isdir(full) else name
            size = os.path.getsize(full) if os.path.isfile(full) else "-"
            mtime = datetime.fromtimestamp(os.path.getmtime(full)).strftime("%Y-%m-%d %H:%M")
            href = os.path.join(display_path, name)
            html += f"<tr><td><a href='{href}'>{display_name}</a></td><td class='file-size'>{size}</td><td class='file-time'>{mtime}</td></tr>\n"

        uptime = int(time.time() - self.server_start)
        html += f"""</table>
<div class='footer'>WNAD HTTPD | Uptime: {uptime}s</div>
</body></html>"""
        encoded = html.encode("utf-8", "surrogateescape")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)
        return None


def run_httpd(port: int = 8888, directory: str = None, bind_ip: str = "0.0.0.0", upload_dir: str = None):
    """
    启动 HTTP 文件服务器
    - port: 监听端口
    - directory: 根目录 (默认当前目录)
    - upload: 上传目录
    """
    if directory is None:
        directory = os.getcwd()

    if upload_dir is None:
        upload_dir = os.path.join(directory, "uploads")
    UploadHTTPRequestHandler.upload_dir = upload_dir

    os.makedirs(upload_dir, exist_ok=True)

    class Handler(UploadHTTPRequestHandler):
        pass

    try:
        server = HTTPServer((bind_ip, port), Handler)
    except Exception as e:
        print(f" {CROSS} 无法启动 HTTP 服务器: {e}")
        return

    local_ip = socket.gethostbyname(socket.gethostname())

    print(f" {CHECK} HTTP 文件服务器已启动:")
    print(f"   地址:   {C.CYAN}http://{bind_ip}:{port}{C.NC}")
    if bind_ip in ("0.0.0.0", ""):
        print(f"   局域网:  {C.CYAN}http://{local_ip}:{port}{C.NC}")
    print(f"   根目录: {directory}")
    print(f"   上传:   {upload_dir} (PUT/表单)")
    print(f" {INFO} 按 Ctrl+C 停止\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n {INFO} 用户中断")
    finally:
        server.server_close()
        print(f" {CHECK} HTTP 服务器已停止")
