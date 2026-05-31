"""
WNAD - DNS 记录枚举模块
查询 A / AAAA / MX / NS / TXT / CNAME / SOA 记录
纯 Python 实现，直接向 DNS 服务器发送 UDP 查询
"""

import socket
import struct
import random
import time
from core.utils import C, CHECK, CROSS, INFO, print_table


QTYPE_MAP = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6,
    "MX": 15, "TXT": 16, "AAAA": 28,
}
QTYPE_REVERSE = {v: k for k, v in QTYPE_MAP.items()}


def _encode_domain(domain: str) -> bytes:
    """将域名编码为 DNS 查询格式"""
    result = b""
    for part in domain.rstrip(".").split("."):
        result += bytes([len(part)]) + part.encode()
    return result + b"\x00"


def _parse_dns_name(data: bytes, offset: int, depth: int = 0) -> tuple:
    """解析 DNS 报文中的域名（支持指针压缩）"""
    if depth > 20:
        return "", offset
    labels = []
    while offset < len(data):
        length = data[offset]
        if length & 0xC0:  # 指针
            ptr = struct.unpack("!H", data[offset:offset+2])[0] & 0x3FFF
            sub_name, _ = _parse_dns_name(data, ptr, depth + 1)
            labels.append(sub_name)
            offset += 2
            break
        elif length == 0:
            offset += 1
            break
        else:
            offset += 1
            labels.append(data[offset:offset+length].decode())
            offset += length
    return ".".join(labels), offset


def _dns_query(domain: str, qtype: int, server: str = "8.8.8.8") -> list:
    """发送 DNS 查询并解析响应，返回记录列表"""
    tid = random.randint(0, 65535)
    header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    question = _encode_domain(domain) + struct.pack("!HH", qtype, 1)
    request = header + question

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)

    try:
        sock.sendto(request, (server, 53))
        data, _ = sock.recvfrom(2048)
    except socket.timeout:
        return []
    finally:
        sock.close()

    # 解析响应
    if len(data) < 12:
        return []

    # 检查响应码
    _, flags, _, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
    rcode = flags & 0x0F
    if rcode != 0 or ancount == 0:
        return []

    records = []
    offset = 12 + len(question)

    for _ in range(ancount):
        if offset >= len(data):
            break
        _, offset = _parse_dns_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset+10])
        offset += 10

        if offset + rdlength > len(data):
            break
        rdata = data[offset:offset+rdlength]
        offset += rdlength

        rtype_name = QTYPE_REVERSE.get(rtype, f"TYPE{rtype}")

        if rtype == 1:  # A
            ip = ".".join(str(b) for b in rdata)
            records.append((rtype_name, ip, ttl))
        elif rtype == 28:  # AAAA
            ip = ":".join(f"{b[0]:02x}{b[1]:02x}" for b in zip(rdata[::2], rdata[1::2]))
            records.append((rtype_name, ip, ttl))
        elif rtype == 2:  # NS
            name, _ = _parse_dns_name(rdata, 0)
            records.append((rtype_name, name, ttl))
        elif rtype == 5:  # CNAME
            name, _ = _parse_dns_name(rdata, 0)
            records.append((rtype_name, name, ttl))
        elif rtype == 15:  # MX
            pref = struct.unpack("!H", rdata[:2])[0]
            name, _ = _parse_dns_name(rdata, 2)
            records.append((rtype_name, f"{name} (pref={pref})", ttl))
        elif rtype == 16:  # TXT
            txt_parts = []
            txt_offset = 0
            while txt_offset < len(rdata):
                txt_len = rdata[txt_offset]
                txt_offset += 1
                txt_parts.append(rdata[txt_offset:txt_offset+txt_len].decode(errors="replace"))
                txt_offset += txt_len
            records.append((rtype_name, "".join(txt_parts)[:60], ttl))
        elif rtype == 6:  # SOA
            mname, off = _parse_dns_name(rdata, 0)
            rname, _ = _parse_dns_name(rdata, off)
            records.append((rtype_name, f"{mname} {rname}", ttl))
        else:
            records.append((rtype_name, f"({len(rdata)} bytes)", ttl))

    return records


def dns_enum(domain: str, types: list = None, server: str = "8.8.8.8"):
    """DNS 记录枚举"""
    if not domain:
        print(f" {CROSS} 请输入域名")
        return

    domain = domain.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

    if types is None:
        types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    print(f" {INFO} DNS 枚举: {C.CYAN}{domain}{C.NC}")
    print(f" {INFO} 查询类型: {', '.join(types)}\n")

    all_records = []
    for t in types:
        qtype = QTYPE_MAP.get(t.upper())
        if not qtype:
            continue

        records = _dns_query(domain, qtype, server)
        if records:
            for r in records:
                all_records.append(r)
                print(f" {C.GREEN}[{r[0]}]{C.NC}  {r[1]:<50}  TTL={r[2]}")

    if not all_records:
        print(f" {INFO} 未找到任何 DNS 记录")

    # 汇总表格
    if all_records:
        print()
        rows = [[r[0], r[1][:50], str(r[2])] for r in all_records]
        print_table(["类型", "值", "TTL"], rows)
