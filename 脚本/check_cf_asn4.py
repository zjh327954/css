import asyncio
import ssl
import sys
import os
import re
import resource
import json
import ipaddress
import random
import socket
import multiprocessing
from concurrent.futures import ProcessPoolExecutor
from functools import lru_cache
from collections import defaultdict

# ==================== 路径修复 ====================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))

# ==================== 常见国家/地区别名映射表 ====================
REGION_ALIASES = {
    "hk": "香港", "hongkong": "香港", "hong kong": "香港",
    "tw": "台湾", "taiwan": "台湾",
    "jp": "日本", "japan": "日本",
    "sg": "新加坡", "singapore": "新加坡",
    "us": "美国", "usa": "美国", "united states": "美国",
    "uk": "英国", "united kingdom": "英国",
    "kr": "韩国", "korea": "韩国",
    "de": "德国", "germany": "德国",
    "fr": "法国", "france": "法国"
}

# ==================== 0. 自动优化系统内核与文件句柄限制 ====================
def optimize_system_limits():
    """自动化调优系统文件句柄限制 (ulimit) 与内核网络参数 (sysctl)"""
    print("[*] 正在尝试优化系统内核与文件描述符限制...", flush=True)

    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target_limit = max(65535, hard)
        resource.setrlimit(resource.RLIMIT_NOFILE, (target_limit, target_limit))
        new_soft, new_hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        print(f"[+] 文件描述符上限 (ulimit) 调整成功: {new_soft}", flush=True)
    except Exception as e:
        print(f"[-] 调整 ulimit 失败 (可能无权限): {e}", flush=True)

    if hasattr(os, "geteuid") and os.geteuid() == 0:
        sysctl_settings = {
            "/proc/sys/net/core/somaxconn": "65535",
            "/proc/sys/net/ipv4/tcp_tw_reuse": "1",
            "/proc/sys/net/ipv4/ip_local_port_range": "1024 65535",
        }

        for path, value in sysctl_settings.items():
            try:
                with open(path, "w") as f:
                    f.write(value)
                print(f"[+] 内核参数已优化: {path} -> {value}", flush=True)
            except Exception as e:
                print(f"[-] 设置 {path} 失败: {e}", flush=True)

optimize_system_limits()

try:
    import uvloop
    uvloop.install()
    UVLOOP_ENABLED = True
except ImportError:
    UVLOOP_ENABLED = False

# ==================== 极限性能配置区域 ====================
DEFAULT_TARGETS = os.getenv("TARGET_LIST", os.getenv("ASN_LIST", "AS36002"))
DEFAULT_PORTS = "443, 8443, 2053, 2083, 2096"
CUSTOM_CF_DOMAIN = os.getenv("CUSTOM_CF_DOMAIN", "327954.ccwu.cc")

CF_SNI_1 = "www.cloudflare.com"
STAGE1_CONCURRENCY = int(os.getenv("STAGE1_CONCURRENCY", "1500"))   # 单进程并发数
STAGE1_TIMEOUT = 2        # 超时时间

CF_HOST_TEST = "crypto.cloudflare.com"
STAGE2_TIMEOUT = 1.2
STAGE3_TIMEOUT = 1.2

CPU_CORES = max(1, os.cpu_count() or 1)

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE
SSL_CTX.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3

global_counter = None
global_pass_counter = None
global_lock = None
global_total = 0
global_step = 0
global_printed_milestones = None
# =========================================================

def parse_ports(port_str):
    if not port_str:
        return [443, 8443, 2053, 2083, 2096]
    
    ports = set()
    parts = re.split(r'[\s,]+', str(port_str).strip())
    
    for part in parts:
        if '-' in part:
            try:
                start, end = part.split('-')
                s_idx, e_idx = max(1, int(start)), min(65535, int(end))
                if s_idx <= e_idx:
                    ports.update(range(s_idx, e_idx + 1))
            except ValueError:
                continue
        elif part.isdigit():
            val = int(part)
            if 1 <= val <= 65535:
                ports.add(val)
                
    return sorted(list(ports)) if ports else [443, 8443, 2053, 2083, 2096]


def build_ip_region_map(target_input, target_region=""):
    """构建 (IP -> 地区/分类标题) 的查询映射字典"""
    ip_region_map = {}
    raw_targets = [t.strip() for t in re.split(r'[\s,;,]+', target_input) if t.strip()]
    mapped_region = REGION_ALIASES.get(target_region.strip().lower(), target_region.strip().lower())

    for item in raw_targets:
        asn_clean = item.upper().replace("AS", "")
        possible_paths = [
            os.path.join(BASE_DIR, "优选asn段", f"{asn_clean}.txt"),
            os.path.join(BASE_DIR, "优选asn段", f"AS{asn_clean}.txt")
        ]
        for p in possible_paths:
            if os.path.isfile(p):
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        current_region = "未归类"
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            
                            found_cidrs = re.findall(r'(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?', line)
                            if found_cidrs:
                                if mapped_region and mapped_region not in current_region.lower():
                                    continue
                                for c in found_cidrs:
                                    try:
                                        net = ipaddress.ip_network(c, strict=False)
                                        for ip in net:
                                            ip_region_map[str(ip)] = current_region
                                    except Exception:
                                        pass
                            else:
                                current_region = line
                except Exception as e:
                    print(f"[-] 读取地区映射失败: {e}", flush=True)
                break
    return ip_region_map


def load_masscan_targets(masscan_json_path, ip_region_map):
    """读取并解析 Masscan 输出的 JSON 文件"""
    targets = []
    if not os.path.exists(masscan_json_path):
        print(f"[-] 错误：找不到 Masscan 输出文件: {masscan_json_path}", flush=True)
        return targets

    try:
        with open(masscan_json_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                return targets
            
            if not content.endswith(']'):
                content = content.rstrip(',') + ']'
            
            data = json.loads(content)
            for entry in data:
                ip = entry.get('ip')
                ports = entry.get('ports', [])
                region = ip_region_map.get(ip, "未归类")
                for p in ports:
                    port = p.get('port')
                    if ip and port:
                        targets.append((ip, int(port), region))
    except Exception as e:
        print(f"[-] 解析 Masscan JSON 失败: {e}", flush=True)

    random.shuffle(targets)
    return targets


def match_domain_in_cert(sni_domain, cert_str):
    sni_domain = sni_domain.lower()
    cert_str = cert_str.lower()
    
    if sni_domain in cert_str:
        return True
        
    parts = sni_domain.split(".")
    if len(parts) >= 2:
        main_domain = ".".join(parts[-2:])
        wildcard_domain = f"*.{main_domain}"
        if main_domain in cert_str or wildcard_domain in cert_str:
            return True
            
    if "cloudflare" in sni_domain and "cloudflare" in cert_str:
        return True

    return False


async def check_tls_sni_async(ip, port, sni, timeout_val, sem):
    async with sem:
        writer = None
        try:
            conn = asyncio.open_connection(ip, port, ssl=SSL_CTX, server_hostname=sni)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout_val)
            
            sock = writer.get_extra_info('socket')
            if sock:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            ssl_obj = writer.get_extra_info('ssl_object')
            if not ssl_obj:
                return False

            der_cert = ssl_obj.getpeercert(binary_form=True)
            if not der_cert:
                return False
            
            cert_str = der_cert.decode('latin1', errors='ignore').lower()
            return match_domain_in_cert(sni, cert_str)
        except Exception:
            return False
        finally:
            if writer:
                writer.close()
                try:
                    writer.transport.abort()
                except Exception:
                    pass


async def check_http_async(ip, port, host, timeout_val, sem):
    async with sem:
        writer = None
        try:
            conn = asyncio.open_connection(ip, port, ssl=SSL_CTX, server_hostname=host)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout_val)
            
            sock = writer.get_extra_info('socket')
            if sock:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            req = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            writer.write(req.encode('latin1'))
            await writer.drain()

            data = await asyncio.wait_for(reader.read(512), timeout=timeout_val)

            if not data:
                return False

            resp_str = data.decode('latin1', errors='ignore').lower()
            return ("http/1.1 301" in resp_str or "http/1.1 302" in resp_str) and ("location:" in resp_str)
        except Exception:
            return False
        finally:
            if writer:
                writer.close()
                try:
                    writer.transport.abort()
                except Exception:
                    pass


def _init_process_worker(counter, pass_counter, lock, total, printed_array):
    global global_counter, global_pass_counter, global_lock, global_total, global_step, global_printed_milestones
    global_counter = counter
    global_pass_counter = pass_counter
    global_lock = lock
    global_total = total
    global_step = max(1, total // 10)
    global_printed_milestones = printed_array


def _process_worker_stage1(targets_chunk):
    if UVLOOP_ENABLED:
        uvloop.install()
        
    async def _run():
        sem = asyncio.Semaphore(STAGE1_CONCURRENCY)

        async def worker(ip, port, region):
            res = await check_tls_sni_async(ip, port, CF_SNI_1, STAGE1_TIMEOUT, sem)
            
            with global_lock:
                global_counter.value += 1
                if res:
                    global_pass_counter.value += 1
                    
                curr = global_counter.value
                passed = global_pass_counter.value
                
                milestone_idx = curr // global_step
                if 1 <= milestone_idx <= 10:
                    if global_printed_milestones[milestone_idx - 1] == 0:
                        global_printed_milestones[milestone_idx - 1] = 1
                        pct = min(100, milestone_idx * 10)
                        print(f"  [第一阶段 TLS 验证进度] {pct}% ({curr:,}/{global_total:,}) | 已通过: {passed:,} 个", flush=True)

            return res

        tasks = [worker(ip, port, region) for ip, port, region in targets_chunk]
        results = await asyncio.gather(*tasks)
        return [targets_chunk[i] for i, ok in enumerate(results) if ok]

    return asyncio.run(_run())


async def main():
    target_input = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGETS
    ports_input = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_PORTS
    masscan_json_path = sys.argv[3] if len(sys.argv) > 3 else "masscan_out.json"
    region_input = sys.argv[4] if len(sys.argv) > 4 else ""

    print(f"\n[*] 正在读取本地分类/地区映射表...", flush=True)
    ip_region_map = build_ip_region_map(target_input, region_input)

    print(f"[*] 正在从 Masscan JSON 导入探活结果: {masscan_json_path} ...", flush=True)
    pass_0 = load_masscan_targets(masscan_json_path, ip_region_map)

    if not pass_0:
        print("[-] Masscan 结果为空，无任何开放端口目标，程序退出。", flush=True)
        return

    # ==================== 1. 多进程 TLS 粗筛 ====================
    total_targets_count = len(pass_0)
    total_concurrency = STAGE1_CONCURRENCY * CPU_CORES
    print(f"[*] 引擎初始化：uvloop={UVLOOP_ENABLED} | 进程数={CPU_CORES} | 单进程并发={STAGE1_CONCURRENCY} | 总并发数={total_concurrency}", flush=True)
    print(f"\n[1/3 第一阶段 TLS 探测] 多进程并行校验 (Masscan 探活开放目标: {total_targets_count:,} 个)...", flush=True)
    
    num_chunks = CPU_CORES * 4
    chunk_size = max(1, total_targets_count // num_chunks)
    chunks = [pass_0[i:i + chunk_size] for i in range(0, total_targets_count, chunk_size)]

    manager = multiprocessing.Manager()
    counter = manager.Value('i', 0)
    pass_counter = manager.Value('i', 0)
    lock = manager.Lock()
    printed_array = manager.Array('i', [0] * 10)

    pass_1 = []
    loop = asyncio.get_running_loop()
    
    with ProcessPoolExecutor(
        max_workers=CPU_CORES,
        initializer=_init_process_worker,
        initargs=(counter, pass_counter, lock, total_targets_count, printed_array)
    ) as executor:
        futures = [loop.run_in_executor(executor, _process_worker_stage1, chunk) for chunk in chunks]
        results = await asyncio.gather(*futures)
        for res in results:
            pass_1.extend(res)

    print(f"[+] 第一阶段完成！匹配 CF 证书保留目标: {len(pass_1)} 个\n", flush=True)

    if not pass_1:
        print("[-] 无有效 IP:端口 通过第一阶段。", flush=True)
        return

    # ==================== 2. HTTP 严格 301/302 校验 ====================
    sem = asyncio.Semaphore(STAGE1_CONCURRENCY * CPU_CORES)
    print(f"[2/3 第二阶段 HTTP 校验] 正在快速校验 {len(pass_1)} 个候选目标...", flush=True)
    tasks2 = [check_http_async(ip, port, CF_HOST_TEST, STAGE2_TIMEOUT, sem) for ip, port, reg in pass_1]
    res2 = await asyncio.gather(*tasks2)
    pass_2 = [pass_1[i] for i, ok in enumerate(res2) if ok]
    print(f"[+] 第二阶段完成！可用 301 重定向目标: {len(pass_2)} 个\n", flush=True)

    if not pass_2:
        print("[-] 无有效 IP:端口 通过第二阶段。", flush=True)
        return

    # ==================== 3. 自定义托管域名反代校验 ====================
    final_items = pass_2
    if CUSTOM_CF_DOMAIN and CUSTOM_CF_DOMAIN.strip():
        domain = CUSTOM_CF_DOMAIN.strip()
        print(f"[3/3 第三阶段自定义域名校验] 正在校验域名 {domain}...", flush=True)
        tasks3 = [check_tls_sni_async(ip, port, domain, STAGE3_TIMEOUT, sem) for ip, port, reg in pass_2]
        res3 = await asyncio.gather(*tasks3)
        final_items = [pass_2[i] for i, ok in enumerate(res3) if ok]
        print(f"[+] 第三阶段完成！支持自定义托管域名的优选反代 IP: {len(final_items)} 个", flush=True)
    else:
        print("[3/3] 未检测到 CUSTOM_CF_DOMAIN，自动跳过第三阶段。", flush=True)

    # ==================== 按地区归类与导出结果 ====================
    print("\n==================== 扫描结束 ====================", flush=True)
    print(f"最终有效目标总数: {len(final_items)}", flush=True)

    grouped_results = defaultdict(list)
    for ip, port, region in final_items:
        grouped_results[region].append((ip, port))

    tag = f"_{region_input.strip()}" if region_input.strip() else ""
    clean_input = re.sub(r'[^\w\.-]', '_', target_input.strip())
    
    raw_filename = f"{clean_input}{tag}"
    filename = f"{raw_filename[:30]}_batch.txt" if len(raw_filename) > 30 else f"{raw_filename}.txt"

    output_dir = os.path.join(BASE_DIR, "优选反代ip")
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, filename)

    with open(output_path, "w", encoding="utf-8") as f:
        for region, nodes in grouped_results.items():
            sorted_nodes = sorted(nodes, key=lambda x: (ipaddress.ip_address(x[0]), x[1]))
            f.write(f"{region}\n")
            for ip, port in sorted_nodes:
                f.write(f"{ip}:{port}\n")
            f.write("\n")

    print(f"\n[+] 最终结果已按分类保存至：{output_path}", flush=True)

if __name__ == "__main__":
    asyncio.run(main())
