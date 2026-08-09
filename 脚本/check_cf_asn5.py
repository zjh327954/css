import asyncio
import ssl
import sys
import os
import re
import resource
import ipaddress
import random
import socket
import multiprocessing
from concurrent.futures import ProcessPoolExecutor

# 路径定位
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPT_DIR) if os.path.basename(SCRIPT_DIR) == "脚本" else SCRIPT_DIR

# 亚洲国家/地区定义
ASIA_REGIONS = {
    "香港": ["香港", "hongkong", "hk"],
    "日本": ["日本", "japan", "jp"],
    "新加坡": ["新加坡", "singapore", "sg"],
    "其他": [
        "台湾", "韩国", "马来西亚", "泰国", "越南", "菲律宾", "印度尼西亚", "印尼", 
        "柬埔寨", "老挝", "缅甸", "文莱", "印度", "巴基斯坦", "孟加拉国", "阿联酋", 
        "迪拜", "沙特", "土耳其", "哈萨克斯坦"
    ]
}

# ulimit 调优
try:
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (max(65535, hard), max(65535, hard)))
except Exception:
    pass

try:
    import uvloop
    uvloop.install()
    UVLOOP_ENABLED = True
except ImportError:
    UVLOOP_ENABLED = False

STAGE0_TIMEOUT = 0.8
CF_SNI_1 = "www.cloudflare.com"
STAGE1_CONCURRENCY = 1500
STAGE1_TIMEOUT = 2
CF_HOST_TEST = "crypto.cloudflare.com"
STAGE2_TIMEOUT = 1.2
STAGE3_TIMEOUT = 1.2
CUSTOM_CF_DOMAIN = os.getenv("CUSTOM_CF_DOMAIN", "327954.ccwu.cc")
CPU_CORES = max(1, os.cpu_count() or 1)

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE
SSL_CTX.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3

def parse_asn_files():
    """解析 优选asn段 下的所有 txt，精准识别 运营商、地区、IP段"""
    asn_dir = os.path.join(BASE_DIR, "优选asn段")
    if not os.path.exists(asn_dir):
        print(f"[-] 目录不存在: {asn_dir}")
        return []

    ip_targets = []
    
    # 汇总所有亚洲匹配词
    all_asia_keywords = []
    for keywords in ASIA_REGIONS.values():
        all_asia_keywords.extend(keywords)

    for fname in os.listdir(asn_dir):
        if not fname.endswith(".txt"):
            continue
        fpath = os.path.join(asn_dir, fname)
        
        current_isp = "移动" # 默认移动
        current_region = ""

        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line_str = line.strip()
                if not line_str:
                    continue

                # 提取 line 中的 IP/CIDR
                cidrs = re.findall(r'(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?', line_str)
                if cidrs:
                    # 匹配该 IP 属于哪个大类（香港/日本/新加坡/其他）
                    matched_category = None
                    reg_lower = current_region.lower()
                    
                    for cat, kws in ASIA_REGIONS.items():
                        if any(kw in reg_lower for kw in kws):
                            matched_category = cat
                            break

                    if matched_category:
                        for c in cidrs:
                            try:
                                net = ipaddress.ip_network(c, strict=False)
                                hosts = [str(ip)] if net.prefixlen >= 31 else [str(ip) for ip in net.hosts()]
                                for ip_str in hosts:
                                    # 元组记录: (IP, 端口, 运营商, 归类文件)
                                    for port in [443, 8443, 2053, 2083, 2096]:
                                        ip_targets.append((ip_str, port, current_isp, matched_category))
                            except Exception:
                                continue
                else:
                    # 非 IP 行：判断是 运营商 还是 地区
                    if "移动" in line_str:
                        current_isp = "移动"
                    elif "联通" in line_str:
                        current_isp = "联通"
                    elif "电信" in line_str:
                        current_isp = "电信"
                    else:
                        current_region = line_str

    # 去重
    unique_targets = list(dict.fromkeys(ip_targets))
    random.shuffle(unique_targets)
    return unique_targets

async def check_tcp_open_async(ip, port, timeout_val, sem):
    async with sem:
        try:
            conn = asyncio.open_connection(ip, port)
            _, writer = await asyncio.wait_for(conn, timeout=timeout_val)
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

async def check_tls_sni_async(ip, port, sni, timeout_val, sem):
    async with sem:
        try:
            conn = asyncio.open_connection(ip, port, ssl=SSL_CTX, server_hostname=sni)
            _, writer = await asyncio.wait_for(conn, timeout=timeout_val)
            ssl_obj = writer.get_extra_info('ssl_object')
            der_cert = ssl_obj.getpeercert(binary_form=True) if ssl_obj else None
            writer.close()
            await writer.wait_closed()
            if not der_cert:
                return False
            cert_str = der_cert.decode('latin1', errors='ignore').lower()
            return sni.lower() in cert_str or "cloudflare" in cert_str
        except Exception:
            return False

async def check_http_async(ip, port, host, timeout_val, sem):
    async with sem:
        try:
            conn = asyncio.open_connection(ip, port, ssl=SSL_CTX, server_hostname=host)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout_val)
            req = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            writer.write(req.encode('latin1'))
            await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=timeout_val)
            writer.close()
            await writer.wait_closed()
            resp_str = data.decode('latin1', errors='ignore').lower()
            return ("301" in resp_str or "302" in resp_str) and "location:" in resp_str
        except Exception:
            return False

async def main():
    print("[*] 正在解析 '优选asn段' 中的亚洲 IP 段...", flush=True)
    targets = parse_asn_files()
    if not targets:
        print("[-] 未匹配到任何亚洲地区 IP，退出。")
        return

    print(f"[+] 提取到 {len(targets):,} 个测试目标 (IP:PORT)", flush=True)

    # 阶段 0: TCP 端口探活
    sem_tcp = asyncio.Semaphore(STAGE1_CONCURRENCY * CPU_CORES)
    print(f"\n[0/3 阶段 0] TCP 极速探活...", flush=True)
    tasks0 = [check_tcp_open_async(item[0], item[1], STAGE0_TIMEOUT, sem_tcp) for item in targets]
    res0 = await asyncio.gather(*tasks0)
    pass_0 = [targets[i] for i, ok in enumerate(res0) if ok]
    print(f"[+] 端口开放数: {len(pass_0):,}")

    if not pass_0: return

    # 阶段 1: TLS 校验
    sem_tls = asyncio.Semaphore(STAGE1_CONCURRENCY * CPU_CORES)
    print(f"\n[1/3 阶段 1] TLS 证书匹配...", flush=True)
    tasks1 = [check_tls_sni_async(item[0], item[1], CF_SNI_1, STAGE1_TIMEOUT, sem_tls) for item in pass_0]
    res1 = await asyncio.gather(*tasks1)
    pass_1 = [pass_0[i] for i, ok in enumerate(res1) if ok]
    print(f"[+] TLS 校验通过数: {len(pass_1):,}")

    if not pass_1: return

    # 阶段 2: HTTP 校验
    print(f"\n[2/3 阶段 2] HTTP 重定向校验...", flush=True)
    tasks2 = [check_http_async(item[0], item[1], CF_HOST_TEST, STAGE2_TIMEOUT, sem_tls) for item in pass_1]
    res2 = await asyncio.gather(*tasks2)
    pass_2 = [pass_1[i] for i, ok in enumerate(res2) if ok]
    print(f"[+] HTTP 校验通过数: {len(pass_2):,}")

    if not pass_2: return

    # 阶段 3: 自定义域名校验
    final_items = pass_2
    if CUSTOM_CF_DOMAIN:
        print(f"\n[3/3 阶段 3] 自定义域名校验 ({CUSTOM_CF_DOMAIN})...", flush=True)
        tasks3 = [check_tls_sni_async(item[0], item[1], CUSTOM_CF_DOMAIN, STAGE3_TIMEOUT, sem_tls) for item in pass_2]
        res3 = await asyncio.gather(*tasks3)
        final_items = [pass_2[i] for i, ok in enumerate(res3) if ok]
        print(f"[+] 最终有效数: {len(final_items):,}")

    # 分类保存到 自用/ 目录
    output_dir = os.path.join(BASE_DIR, "自用")
    os.makedirs(output_dir, exist_ok=True)

    # 按 文件名 -> 运营商(移动在上) -> IP 排序
    files_data = {"香港": [], "日本": [], "新加坡": [], "其他": []}
    
    for ip, port, isp, cat in final_items:
        if cat in files_data:
            files_data[cat].append((ip, port, isp))

    for cat_name, nodes in files_data.items():
        # 排序权重：移动=0, 联通=1, 其他=2，再按 IP 升序
        def sort_key(x):
            isp_order = 0 if "移动" in x[2] else (1 if "联通" in x[2] else 2)
            return (isp_order, ipaddress.ip_address(x[0]), x[1])

        sorted_nodes = sorted(nodes, key=sort_key)

        file_path = os.path.join(output_dir, f"{cat_name}.txt")
        
        # 区分移动和联通输出
        mobile_nodes = [f"{ip}:{port}" for ip, port, isp in sorted_nodes if "移动" in isp]
        unicom_nodes = [f"{ip}:{port}" for ip, port, isp in sorted_nodes if "联通" in isp]
        other_nodes = [f"{ip}:{port}" for ip, port, isp in sorted_nodes if "移动" not in isp and "联通" not in isp]

        with open(file_path, "w", encoding="utf-8") as f:
            if mobile_nodes:
                f.write("移动\n")
                f.write("\n".join(mobile_nodes) + "\n\n")
            if unicom_nodes:
                f.write("联通\n")
                f.write("\n".join(unicom_nodes) + "\n\n")
            if other_nodes:
                f.write("其他\n")
                f.write("\n".join(other_nodes) + "\n")

        print(f"[+] 已更新自用文件: {file_path}")

if __name__ == "__main__":
    asyncio.run(main())
