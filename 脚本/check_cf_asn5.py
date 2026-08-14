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
import glob
from concurrent.futures import ProcessPoolExecutor
from collections import defaultdict

# ==================== 路径修复 ====================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..")) if os.path.basename(SCRIPT_DIR) == "脚本" else SCRIPT_DIR

# ==================== 亚洲国家/地区关键词识别清单 ====================
ASIA_KEYWORDS = [
    "香港", "HK", "Hong Kong",
    "日本", "JP", "Japan",
    "新加坡", "SG", "Singapore",
    "台湾", "TW", "Taiwan",
    "韩国", "KR", "Korea",
    "马来西亚", "MY", "Malaysia",
    "泰国", "TH", "Thailand",
    "越南", "VN", "Vietnam",
    "菲律宾", "PH", "Philippines",
    "印度尼西亚", "印尼", "ID", "Indonesia",
    "印度", "IN", "India",
    "阿联酋", "迪拜", "AE", "Dubai", "UAE",
    "土耳其", "TR", "Turkey"
]

# ==================== 0. 自动优化系统内核与文件句柄限制 ====================
def optimize_system_limits():
    """自动化调优系统文件句柄限制 (ulimit) 与内核网络参数 (sysctl)"""
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target_limit = max(65535, hard)
        resource.setrlimit(resource.RLIMIT_NOFILE, (target_limit, target_limit))
        new_soft, new_hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        print(f"[+] 文件描述符上限 (ulimit) 调整成功: {new_soft}", flush=True)
    except Exception as e:
        print(f"[-] 调整 ulimit 失败: {e}", flush=True)

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
            except Exception:
                pass

optimize_system_limits()

try:
    import uvloop
    uvloop.install()
    UVLOOP_ENABLED = True
except ImportError:
    UVLOOP_ENABLED = False

# ==================== 参数解析与环境变量 ====================
MASSCAN_JSON_FILE = sys.argv[1] if len(sys.argv) > 1 else "masscan_out.json"
CUSTOM_CF_DOMAIN = os.getenv("CUSTOM_CF_DOMAIN", "327954.ccwu.cc")

# 阶段 1：TLS 粗筛 (www.cloudflare.com)
CF_SNI_1 = "www.cloudflare.com"
STAGE1_CONCURRENCY = int(os.getenv("STAGE1_CONCURRENCY", "1500"))
STAGE1_TIMEOUT = 2        

# 阶段 2：HTTP 验证 Host (crypto.cloudflare.com)
CF_HOST_TEST = "crypto.cloudflare.com"
STAGE2_TIMEOUT = 1.2

# 阶段 3：自定义域名校验超时
STAGE3_TIMEOUT = 1.2

# CPU 核心数
CPU_CORES = max(1, os.cpu_count() or 1)

# 优化 SSL Context
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE
SSL_CTX.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3

# 全局共享变量定义
global_counter = None
global_pass_counter = None
global_lock = None
global_total = 0
global_step = 0
global_printed_milestones = None


def silent_exception_handler(loop, context):
    """静默处理底层网络重置与握手报错"""
    exception = context.get("exception")
    if isinstance(exception, (ConnectionResetError, TimeoutError, OSError, ssl.SSLError)):
        return


def is_asia_label(label):
    """判断是否包含亚洲国家/地区关键词"""
    label_upper = label.upper()
    for kw in ASIA_KEYWORDS:
        if kw.upper() in label_upper:
            return True
    return False


def build_ip_region_map():
    """
    智能解析 `优选asn段` 下的所有 txt 文件。
    支持运营商层级（移动/联通）+ 国家层级缩进解析，只提取亚洲地区。
    """
    ip_region_map = {}
    asn_dir = os.path.join(BASE_DIR, "优选asn段")
    
    if not os.path.exists(asn_dir):
        print(f"[-] 错误: 找不到 `优选asn段` 目录: {asn_dir}", flush=True)
        return ip_region_map

    txt_files = glob.glob(os.path.join(asn_dir, "*.txt"))
    print(f"[*] 找到 {len(txt_files)} 个 ASN 段定义文件，准备读取...", flush=True)

    for p in txt_files:
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                operator = ""       # 记录顶级运营商（移动/联通等）
                country_region = "" # 记录二级国家/地区

                for line in f:
                    raw_line = line.rstrip()
                    if not raw_line.strip():
                        continue
                    
                    indent_level = len(raw_line) - len(raw_line.lstrip())
                    clean_line = raw_line.strip()
                    found_cidrs = re.findall(r'(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?', clean_line)

                    if not found_cidrs:
                        # 0 缩进通常是顶级运营商（移动/联通）或国家
                        if indent_level == 0:
                            if clean_line in ["移动", "联通", "电信"]:
                                operator = clean_line
                                country_region = ""
                            else:
                                operator = ""
                                country_region = clean_line
                        # 2格/4格缩进通常是国家/地区
                        elif indent_level in [2, 4]:
                            country_region = clean_line
                    else:
                        # 拼接完整标签，如 "移动 香港" 或 "香港"
                        full_label = f"{operator} {country_region}".strip() if operator else country_region
                        
                        # 筛选亚洲地区
                        if is_asia_label(country_region) or is_asia_label(full_label):
                            for c in found_cidrs:
                                try:
                                    net = ipaddress.ip_network(c, strict=False)
                                    for ip in net:
                                        ip_region_map[str(ip)] = full_label
                                except Exception:
                                    pass
        except Exception as e:
            print(f"[-] 读取文件失败 {p}: {e}", flush=True)

    print(f"[+] IP 映射构建完成，已加载 {len(ip_region_map):,} 个亚洲 IP 目标", flush=True)
    return ip_region_map


def load_masscan_targets(json_file, ip_region_map):
    """读取并解析 Masscan 输出的 JSON 文件"""
    targets = []
    if not os.path.exists(json_file):
        print(f"[-] 找不到 Masscan 文件: {json_file}", flush=True)
        return targets

    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                return targets
            if content.endswith(','):
                content = content[:-1]
            if not content.endswith(']'):
                content += ']'
            
            data = json.loads(content)
            for entry in data:
                ip = entry.get('ip')
                ports = entry.get('ports', [])
                
                if ip in ip_region_map:
                    region = ip_region_map[ip]
                    for p in ports:
                        port = p.get('port')
                        if ip and port:
                            targets.append((ip, int(port), region))
    except Exception as e:
        print(f"[-] 解析 Masscan 导出文件失败: {e}", flush=True)

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
    """异步 TLS 握手校验"""
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
    """阶段二：校验 HTTP 301/302 重定向"""
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
        loop = asyncio.get_running_loop()
        loop.set_exception_handler(silent_exception_handler)

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
                        print(f"  [第一阶段 TLS 进度] {pct}% ({curr:,}/{global_total:,}) | 已通过: {passed:,} 个", flush=True)

            return res

        tasks = [worker(ip, port, region) for ip, port, region in targets_chunk]
        results = await asyncio.gather(*tasks)
        return [targets_chunk[i] for i, ok in enumerate(results) if ok]

    return asyncio.run(_run())


def get_operator_priority(region_label):
    """排序依据：移动在前(0)，联通在后(1)，其他(2)"""
    if "移动" in region_label:
        return 0
    elif "联通" in region_label:
        return 1
    return 2


async def main():
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(silent_exception_handler)

    print(f"[*] 读取 `优选asn段` 并加载亚洲国家/地区段...", flush=True)
    ip_region_map = build_ip_region_map()

    print(f"[*] 正在从 Masscan JSON 导入探活结果: {MASSCAN_JSON_FILE} ...", flush=True)
    pass_0 = load_masscan_targets(MASSCAN_JSON_FILE, ip_region_map)

    if not pass_0:
        print("[-] Masscan 结果中无任何匹配的亚洲开放端口目标，程序退出。", flush=True)
        return

    # 1. 第一阶段 TLS 证书匹配
    total_targets_count = len(pass_0)
    total_concurrency = STAGE1_CONCURRENCY * CPU_CORES
    print(f"[*] 引擎初始化：uvloop={UVLOOP_ENABLED} | 进程数={CPU_CORES} | 单进程并发={STAGE1_CONCURRENCY} | 总并发数={total_concurrency}", flush=True)
    print(f"\n[1/3 第一阶段 TLS 探测] 多进程并行校验 (符合条件目标: {total_targets_count:,} 个)...", flush=True)

    manager = multiprocessing.Manager()
    global_counter_var = manager.Value('i', 0)        
    global_pass_counter_var = manager.Value('i', 0)   
    global_lock_var = manager.Lock()
    global_printed_array = manager.Array('i', [0] * 10) 

    num_chunks = CPU_CORES * 4
    chunk_size = max(1, total_targets_count // num_chunks)
    chunks = [pass_0[i:i + chunk_size] for i in range(0, total_targets_count, chunk_size)]

    pass_1 = []
    with ProcessPoolExecutor(
        max_workers=CPU_CORES,
        initializer=_init_process_worker,
        initargs=(global_counter_var, global_pass_counter_var, global_lock_var, total_targets_count, global_printed_array)
    ) as executor:
        futures = [loop.run_in_executor(executor, _process_worker_stage1, chunk) for chunk in chunks]
        results = await asyncio.gather(*futures)
        for res in results:
            pass_1.extend(res)

    print(f"[+] 第一阶段完成！匹配 CF 证书保留目标: {len(pass_1)} 个\n", flush=True)

    if not pass_1:
        print("[-] 无有效 IP:端口 通过第一阶段。", flush=True)
        return

    sem = asyncio.Semaphore(STAGE1_CONCURRENCY * CPU_CORES)

    # 2. 第二阶段 HTTP 校验
    print(f"[2/3 第二阶段 HTTP 校验] 正在快速校验 {len(pass_1)} 个候选目标...", flush=True)
    tasks2 = [check_http_async(ip, port, CF_HOST_TEST, STAGE2_TIMEOUT, sem) for ip, port, reg in pass_1]
    res2 = await asyncio.gather(*tasks2)
    pass_2 = [pass_1[i] for i, ok in enumerate(res2) if ok]
    print(f"[+] 第二阶段完成！可用 301 重定向目标: {len(pass_2)} 个\n", flush=True)

    if not pass_2:
        print("[-] 无有效 IP:端口 通过第二阶段。", flush=True)
        return

    # 3. 第三阶段 自定义托管域名校验
    final_items = pass_2
    if CUSTOM_CF_DOMAIN and CUSTOM_CF_DOMAIN.strip():
        domain = CUSTOM_CF_DOMAIN.strip()
        print(f"[3/3 第三阶段自定义域名校验] 正在校验域名 {domain}...", flush=True)
        tasks3 = [check_tls_sni_async(ip, port, domain, STAGE3_TIMEOUT, sem) for ip, port, reg in pass_2]
        res3 = await asyncio.gather(*tasks3)
        final_items = [pass_2[i] for i, ok in enumerate(res3) if ok]
        print(f"[+] 第三阶段完成！支持自定义托管域名的优选反代 IP: {len(final_items)} 个", flush=True)

    # 4. 结果分类与输出保存
    print("\n==================== 扫描结束 ====================", flush=True)
    print(f"最终有效目标总数: {len(final_items)}", flush=True)

    # 按照四个维度归类：香港, 日本, 新加坡, 其他
    file_groups = {
        "香港": defaultdict(list),
        "日本": defaultdict(list),
        "新加坡": defaultdict(list),
        "其他": defaultdict(list)
    }

    for ip, port, region in final_items:
        if "香港" in region or "HK" in region.upper():
            file_groups["香港"][region].append((ip, port))
        elif "日本" in region or "JP" in region.upper():
            file_groups["日本"][region].append((ip, port))
        elif "新加坡" in region or "SG" in region.upper():
            file_groups["新加坡"][region].append((ip, port))
        else:
            file_groups["其他"][region].append((ip, port))

    # 设置输出目录为 根目录/自用/
    output_dir = os.path.join(BASE_DIR, "自用")
    os.makedirs(output_dir, exist_ok=True)

    # 写入文件（移动在前，联通在后）
    for category_name, grouped_data in file_groups.items():
        output_path = os.path.join(output_dir, f"{category_name}.txt")
        
        # 按照“移动 -> 联通 -> 其他”对 Region 组进行排序
        sorted_regions = sorted(grouped_data.keys(), key=lambda r: (get_operator_priority(r), r))
        
        with open(output_path, "w", encoding="utf-8") as f:
            for region in sorted_regions:
                nodes = grouped_data[region]
                # 对 IP:Port 按 IP 地址字典顺序排列
                sorted_nodes = sorted(nodes, key=lambda x: (ipaddress.ip_address(x[0]), x[1]))
                
                f.write(f"{region}\n")
                for ip, port in sorted_nodes:
                    f.write(f"{ip}:{port}\n")
                f.write("\n")

        print(f"[+] 已写入: {output_path} (节点数: {sum(len(v) for v in grouped_data.values())})", flush=True)

if __name__ == "__main__":
    asyncio.run(main())
