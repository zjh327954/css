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

# 1. 优化系统内核与文件描述符限制打印
print("[*] 正在尝试优化系统内核与文件描述符限制...", flush=True)
try:
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    target_limit = max(65535, hard)
    resource.setrlimit(resource.RLIMIT_NOFILE, (target_limit, target_limit))
    new_soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    print(f"[+] 文件描述符上限 (ulimit) 调整成功：{new_soft}", flush=True)
except Exception as e:
    print(f"[!] ulimit 调整失败: {e}", flush=True)

if os.geteuid() != 0:
    print("[!] 提示：当前非 Root 用户，跳过 sysctl 内核参数优化（若在 GitHub Actions 中默认是 Root）", flush=True)

# 2. 路径定位
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPT_DIR) if os.path.basename(SCRIPT_DIR) == "脚本" else SCRIPT_DIR

# 3. 亚洲国家/地区定义
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

try:
    import uvloop
    uvloop.install()
    UVLOOP_ENABLED = True
except ImportError:
    UVLOOP_ENABLED = False

STAGE0_TIMEOUT = 0.8
CF_SNI_1 = "www.cloudflare.com"

STAGE1_CONCURRENCY = int(os.getenv("STAGE1_CONCURRENCY", "1000"))
STAGE1_TIMEOUT = 2
CF_HOST_TEST = "crypto.cloudflare.com"
STAGE2_TIMEOUT = 1.2
STAGE3_TIMEOUT = 1.2
CUSTOM_CF_DOMAIN = os.getenv("CUSTOM_CF_DOMAIN", "327954.ccwu.cc")
CPU_CORES = max(1, os.cpu_count() or 1)

total_concurrency = STAGE1_CONCURRENCY * CPU_CORES
print(f"[*] 引擎初始化：uvloop={UVLOOP_ENABLED} | 进程数={CPU_CORES} | 单进程并发={STAGE1_CONCURRENCY} | 总并发数={total_concurrency}", flush=True)

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE
SSL_CTX.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3

def parse_ports_arg():
    default_ports = [443, 8443, 2053, 2083, 2096]
    if len(sys.argv) > 1 and sys.argv[1].strip():
        raw_ports = re.split(r'[, ]+', sys.argv[1].strip())
        parsed = []
        for p in raw_ports:
            if p.isdigit():
                parsed.append(int(p))
        if parsed:
            return parsed
    return default_ports

def parse_asn_files(ports):
    asn_dir = os.path.join(BASE_DIR, "优选asn段")
    if not os.path.exists(asn_dir):
        print(f"[-] 目录不存在: {asn_dir}", flush=True)
        return []

    ip_targets = []

    for fname in os.listdir(asn_dir):
        if not fname.endswith(".txt"):
            continue
        fpath = os.path.join(asn_dir, fname)
        
        current_isp = "移动"
        current_region = ""

        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line_str = line.strip()
                if not line_str:
                    continue

                cidrs = re.findall(r'(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?', line_str)
                if cidrs:
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
                                    for port in ports:
                                        ip_targets.append((ip_str, port, current_isp, matched_category))
                            except Exception:
                                continue
                else:
                    if "移动" in line_str:
                        current_isp = "移动"
                    elif "联通" in line_str:
                        current_isp = "联通"
                    elif "电信" in line_str:
                        current_isp = "电信"
                    else:
                        current_region = line_str

    unique_targets = list(dict.fromkeys(ip_targets))
    random.shuffle(unique_targets)
    return unique_targets

async def run_tasks_with_progress(task_func, items, step_name):
    """带 10% 进度打印的协程调度封装"""
    total = len(items)
    if total == 0:
        return []

    sem = asyncio.Semaphore(STAGE1_CONCURRENCY * CPU_CORES)
    completed = 0
    step_percent = 10
    next_report = step_percent

    async def worker(item):
        nonlocal completed, next_report
        async with sem:
            res = await task_func(item)
            completed += 1
            current_pct = (completed / total) * 100
            if current_pct >= next_report or completed == total:
                print(f"    [{step_name}] 进度: {completed:,}/{total:,} ({int(current_pct)}%)", flush=True)
                while next_report <= current_pct and next_report < 100:
                    next_report += step_percent
            return res

    tasks = [worker(item) for item in items]
    return await asyncio.gather(*tasks)

async def check_tcp_open_async(item):
    ip, port = item[0], item[1]
    try:
        conn = asyncio.open_connection(ip, port)
        _, writer = await asyncio.wait_for(conn, timeout=STAGE0_TIMEOUT)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False

async def check_tls_sni_1(item):
    ip, port = item[0], item[1]
    try:
        conn = asyncio.open_connection(ip, port, ssl=SSL_CTX, server_hostname=CF_SNI_1)
        _, writer = await asyncio.wait_for(conn, timeout=STAGE1_TIMEOUT)
        ssl_obj = writer.get_extra_info('ssl_object')
        der_cert = ssl_obj.getpeercert(binary_form=True) if ssl_obj else None
        writer.close()
        await writer.wait_closed()
        if not der_cert:
            return False
        cert_str = der_cert.decode('latin1', errors='ignore').lower()
        return CF_SNI_1.lower() in cert_str or "cloudflare" in cert_str
    except Exception:
        return False

async def check_http_async(item, sem):
    ip, port = item[0], item[1]
    async with sem:
        try:
            conn = asyncio.open_connection(ip, port, ssl=SSL_CTX, server_hostname=CF_HOST_TEST)
            reader, writer = await asyncio.wait_for(conn, timeout=STAGE2_TIMEOUT)
            req = f"GET / HTTP/1.1\r\nHost: {CF_HOST_TEST}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            writer.write(req.encode('latin1'))
            await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=STAGE2_TIMEOUT)
            writer.close()
            await writer.wait_closed()
            resp_str = data.decode('latin1', errors='ignore').lower()
            return ("301" in resp_str or "302" in resp_str) and "location:" in resp_str
        except Exception:
            return False

async def check_tls_custom_domain(item, sem):
    ip, port = item[0], item[1]
    async with sem:
        try:
            conn = asyncio.open_connection(ip, port, ssl=SSL_CTX, server_hostname=CUSTOM_CF_DOMAIN)
            _, writer = await asyncio.wait_for(conn, timeout=STAGE3_TIMEOUT)
            ssl_obj = writer.get_extra_info('ssl_object')
            der_cert = ssl_obj.getpeercert(binary_form=True) if ssl_obj else None
            writer.close()
            await writer.wait_closed()
            if not der_cert:
                return False
            cert_str = der_cert.decode('latin1', errors='ignore').lower()
            return CUSTOM_CF_DOMAIN.lower() in cert_str or "cloudflare" in cert_str
        except Exception:
            return False

async def main():
    ports = parse_ports_arg()
    print("[*] 正在解析 '优选asn段' 中的亚洲 IP 段...", flush=True)
    targets = parse_asn_files(ports)
    if not targets:
        print("[-] 未匹配到任何亚洲地区 IP，退出。", flush=True)
        return

    unique_ips_cnt = len(set(x[0] for x in targets))
    total_targets_cnt = len(targets)
    print(f"[*] 解析完成：{unique_ips_cnt:,} 个 IP × {len(ports)} 个端口 = 共 {total_targets_cnt:,} 个测试目标。", flush=True)

    # ---------------- 阶段 0: TCP 探活 (按 50,000 分批探活 + 10% 进度) ----------------
    print(f"\n[0/3 阶段 0] TCP 极速探活 (目标总数: {total_targets_cnt:,})...", flush=True)
    
    CHUNK_SIZE = 50000
    pass_0 = []
    target_chunks = [targets[i:i + CHUNK_SIZE] for i in range(0, len(targets), CHUNK_SIZE)]
    total_chunks = len(target_chunks)

    for idx, chunk in enumerate(target_chunks, 1):
        print(f"\n  ---> 正在执行第 {idx}/{total_chunks} 批次探活 ({len(chunk):,} 个目标)...", flush=True)
        res_chunk = await run_tasks_with_progress(check_tcp_open_async, chunk, f"批次 {idx}")
        passed = [chunk[i] for i, ok in enumerate(res_chunk) if ok]
        pass_0.extend(passed)
        print(f"  ---> 第 {idx} 批次完成，当前累计端口开放数: {len(pass_0):,}", flush=True)

    print(f"\n[+] 阶段 0 结束，端口开放总数: {len(pass_0):,}", flush=True)

    if not pass_0: return

    # ---------------- 阶段 1: TLS 校验 (带 10% 进度) ----------------
    print(f"\n[1/3 阶段 1] TLS 证书匹配...", flush=True)
    res1 = await run_tasks_with_progress(check_tls_sni_1, pass_0, "阶段 1")
    pass_1 = [pass_0[i] for i, ok in enumerate(res1) if ok]
    print(f"[+] TLS 校验通过数: {len(pass_1):,}", flush=True)

    if not pass_1: return

    # ---------------- 阶段 2: HTTP 校验 (快速直接运行，不打 10% 日志) ----------------
    print(f"\n[2/3 阶段 2] HTTP 重定向校验...", flush=True)
    sem_fast = asyncio.Semaphore(STAGE1_CONCURRENCY * CPU_CORES)
    tasks2 = [check_http_async(item, sem_fast) for item in pass_1]
    res2 = await asyncio.gather(*tasks2)
    pass_2 = [pass_1[i] for i, ok in enumerate(res2) if ok]
    print(f"[+] HTTP 校验通过数: {len(pass_2):,}", flush=True)

    if not pass_2: return

    # ---------------- 阶段 3: 自定义域名校验 (快速直接运行，不打 10% 日志) ----------------
    final_items = pass_2
    if CUSTOM_CF_DOMAIN:
        print(f"\n[3/3 阶段 3] 自定义域名校验 ({CUSTOM_CF_DOMAIN})...", flush=True)
        tasks3 = [check_tls_custom_domain(item, sem_fast) for item in pass_2]
        res3 = await asyncio.gather(*tasks3)
        final_items = [pass_2[i] for i, ok in enumerate(res3) if ok]
        print(f"[+] 最终有效数: {len(final_items):,}", flush=True)

    # ---------------- 分类保存到 自用/ 目录 ----------------
    output_dir = os.path.join(BASE_DIR, "自用")
    os.makedirs(output_dir, exist_ok=True)

    files_data = {"香港": [], "日本": [], "新加坡": [], "其他": []}
    
    for ip, port, isp, cat in final_items:
        if cat in files_data:
            files_data[cat].append((ip, port, isp))

    for cat_name, nodes in files_data.items():
        def sort_key(x):
            isp_order = 0 if "移动" in x[2] else (1 if "联通" in x[2] else 2)
            return (isp_order, ipaddress.ip_address(x[0]), x[1])

        sorted_nodes = sorted(nodes, key=sort_key)
        file_path = os.path.join(output_dir, f"{cat_name}.txt")
        
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

        print(f"[+] 已更新自用文件: {file_path}", flush=True)

if __name__ == "__main__":
    asyncio.run(main())
