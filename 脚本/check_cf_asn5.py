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
from collections import defaultdict

# ==================== 路径修复 ====================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..")) if os.path.basename(SCRIPT_DIR) in ["脚本", "scripts"] else SCRIPT_DIR

# 目标输出目录：根目录/自用
OUTPUT_DIR = os.path.join(BASE_DIR, "自用")
ASN_DIR = os.path.join(BASE_DIR, "优选asn段")

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

# 阶段 1：TLS 粗筛
CF_SNI_1 = "www.cloudflare.com"
STAGE1_CONCURRENCY = int(os.getenv("STAGE1_CONCURRENCY", "200"))
STAGE1_TIMEOUT = 2        

# 阶段 2：HTTP 验证
CF_HOST_TEST = "crypto.cloudflare.com"
STAGE2_TIMEOUT = 1.2

# 阶段 3：自定义域名校验
STAGE3_TIMEOUT = 1.2

CPU_CORES = max(1, os.cpu_count() or 1)

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE
SSL_CTX.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3

# 全局共享变量
global_counter = None
global_pass_counter = None
global_lock = None
global_total = 0
global_step = 0
global_printed_milestones = None

ASIA_KEYWORDS = [
    "香港", "日本", "新加坡", "韩国", "台湾", "澳门", "马来西亚", "泰国", "越南",
    "菲律宾", "印度尼西亚", "印尼", "柬埔寨", "老挝", "缅甸", "文莱", "印度", 
    "巴基斯坦", "孟加拉", "阿联酋", "迪拜", "土耳其", "沙特", "卡塔尔", "科威特", 
    "阿曼", "以色列", "哈萨克斯坦", "hk", "hongkong", "jp", "japan", "sg", "singapore", 
    "kr", "korea", "tw", "taiwan", "mo", "macau"
]

def silent_exception_handler(loop, context):
    exception = context.get("exception")
    if isinstance(exception, (ConnectionResetError, TimeoutError, OSError, ssl.SSLError)):
        return

def is_asia_region(region_name):
    """判断地区名称是否属于亚洲"""
    reg_lower = region_name.lower()
    return any(kw in reg_lower for kw in ASIA_KEYWORDS)

def parse_asn_file(file_path, ip_info_map):
    """解析单个 ASN 文本文件，完美支持 运营商 -> 地区 -> CIDR 多层缩进结构"""
    if not os.path.isfile(file_path):
        return

    current_isp = "未知运营商"
    current_region = "未知地区"
    is_asia = False

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                raw_line = line.strip()
                if not raw_line:
                    continue

                # 1. 判断 ISP 标记
                if raw_line in ["移动", "联通", "电信"]:
                    current_isp = raw_line
                    continue

                # 2. 提取 CIDR
                found_cidrs = re.findall(r'(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?', raw_line)
                
                if found_cidrs:
                    # 只有当前地区处于亚洲关键字范围内时，才写入 IP 字典
                    if is_asia:
                        for c in found_cidrs:
                            try:
                                net = ipaddress.ip_network(c, strict=False)
                                for ip in net:
                                    ip_info_map[str(ip)] = (current_isp, current_region)
                            except Exception:
                                pass
                else:
                    # 3. 如果不是 CIDR 也不是 ISP，则为地区标记
                    current_region = raw_line
                    is_asia = is_asia_region(current_region)

    except Exception as e:
        print(f"[-] 解析文件失败 {file_path}: {e}", flush=True)


def build_asia_ip_map():
    """递归遍历 优选asn段 目录下所有的 txt 文件并构建 IP 归属映射"""
    ip_info_map = {}
    
    if not os.path.exists(ASN_DIR):
        print(f"[-] 警告: 未找到 ASN 目录 {ASN_DIR}", flush=True)
        return ip_info_map

    print(f"[*] 正在扫描并解析 '{ASN_DIR}' 目录下所有 txt 文件中的亚洲段...", flush=True)
    
    # 自动加载 优选asn段/ 目录下的每一个 .txt 文件 (包括 140227.txt 等所有文件)
    for root, _, files in os.walk(ASN_DIR):
        for file in files:
            if file.endswith(".txt"):
                file_path = os.path.join(root, file)
                parse_asn_file(file_path, ip_info_map)

    print(f"[+] 亚洲 IP 字典构建完成，已加载 {len(ip_info_map):,} 个 IP 的归属信息。", flush=True)
    return ip_info_map


def load_masscan_targets(json_file, ip_info_map):
    """从 Masscan JSON 加载探活目标并附带 ISP/地区 信息"""
    targets = []
    if not os.path.exists(json_file):
        print(f"[-] 找不到 Masscan 输出文件: {json_file}", flush=True)
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
                isp, region = ip_info_map.get(ip, ("未知运营商", "未知地区"))
                for p in ports:
                    port = p.get('port')
                    if ip and port:
                        targets.append((ip, int(port), isp, region))
    except Exception as e:
        print(f"[-] 解析 Masscan 文件失败: {e}", flush=True)

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
        loop = asyncio.get_running_loop()
        loop.set_exception_handler(silent_exception_handler)

        sem = asyncio.Semaphore(STAGE1_CONCURRENCY)

        async def worker(ip, port, isp, region):
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

        tasks = [worker(ip, port, isp, region) for ip, port, isp, region in targets_chunk]
        results = await asyncio.gather(*tasks)
        return [targets_chunk[i] for i, ok in enumerate(results) if ok]

    return asyncio.run(_run())


def save_results_by_region_and_isp(final_items):
    """按地区分类（香港、日本、新加坡、其他），并且移动在前、联通在后写入"""
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    category_map = {
        "香港": defaultdict(list),
        "日本": defaultdict(list),
        "新加坡": defaultdict(list),
        "其他": defaultdict(list)
    }

    for ip, port, isp, region in final_items:
        file_key = "其他"
        if "香港" in region or "hk" in region.lower() or "hongkong" in region.lower():
            file_key = "香港"
        elif "日本" in region or "jp" in region.lower() or "japan" in region.lower():
            file_key = "日本"
        elif "新加坡" in region or "sg" in region.lower() or "singapore" in region.lower():
            file_key = "新加坡"

        category_map[file_key][isp].append((ip, port))

    isp_priority = ["移动", "联通"]

    for cat_name, isps_dict in category_map.items():
        file_path = os.path.join(OUTPUT_DIR, f"{cat_name}.txt")
        
        all_isps = list(isps_dict.keys())
        sorted_isps = [isp for isp in isp_priority if isp in all_isps]
        for isp in all_isps:
            if isp not in sorted_isps:
                sorted_isps.append(isp)

        with open(file_path, "w", encoding="utf-8") as f:
            for isp in sorted_isps:
                nodes = isps_dict[isp]
                if not nodes:
                    continue
                
                sorted_nodes = sorted(nodes, key=lambda x: (ipaddress.ip_address(x[0]), x[1]))
                
                f.write(f"[{isp}]\n")
                for ip, port in sorted_nodes:
                    f.write(f"{ip}:{port}\n")
                f.write("\n")

        total_cat_count = sum(len(v) for v in isps_dict.values())
        print(f"[+] 保存 [{cat_name}.txt] 完成 (共 {total_cat_count} 个 IP:端口) -> {file_path}", flush=True)


async def main():
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(silent_exception_handler)

    print(f"[*] 正在加载亚洲段 ASN 映射表...", flush=True)
    ip_info_map = build_asia_ip_map()

    print(f"[*] 正在从 Masscan JSON 导入目标: {MASSCAN_JSON_FILE} ...", flush=True)
    pass_0 = load_masscan_targets(MASSCAN_JSON_FILE, ip_info_map)

    if not pass_0:
        print("[-] Masscan 结果为空，程序退出。", flush=True)
        return

    # 1. 第一阶段 TLS 探测
    total_targets_count = len(pass_0)
    total_concurrency = STAGE1_CONCURRENCY * CPU_CORES
    print(f"[*] 引擎初始化：uvloop={UVLOOP_ENABLED} | 进程数={CPU_CORES} | 单进程并发={STAGE1_CONCURRENCY} | 总并发数={total_concurrency}", flush=True)
    print(f"\n[1/3 第一阶段 TLS 探测] 多进程并行校验 (总目标数: {total_targets_count:,} 个)...", flush=True)

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

    print(f"[+] 第一阶段完成！保留目标: {len(pass_1)} 个\n", flush=True)

    if not pass_1:
        print("[-] 无有效目标通过第一阶段。", flush=True)
        return

    sem = asyncio.Semaphore(STAGE1_CONCURRENCY * CPU_CORES)

    # 2. 第二阶段 HTTP 校验
    print(f"[2/3 第二阶段 HTTP 校验] 校验 {len(pass_1)} 个候选目标...", flush=True)
    tasks2 = [check_http_async(ip, port, CF_HOST_TEST, STAGE2_TIMEOUT, sem) for ip, port, isp, reg in pass_1]
    res2 = await asyncio.gather(*tasks2)
    pass_2 = [pass_1[i] for i, ok in enumerate(res2) if ok]
    print(f"[+] 第二阶段完成！可用 301 重定向目标: {len(pass_2)} 个\n", flush=True)

    if not pass_2:
        print("[-] 无有效目标通过第二阶段。", flush=True)
        return

    # 3. 第三阶段 自定义托管域名校验
    final_items = pass_2
    if CUSTOM_CF_DOMAIN and CUSTOM_CF_DOMAIN.strip():
        domain = CUSTOM_CF_DOMAIN.strip()
        print(f"[3/3 第三阶段自定义域名校验] 正在校验域名 {domain}...", flush=True)
        tasks3 = [check_tls_sni_async(ip, port, domain, STAGE3_TIMEOUT, sem) for ip, port, isp, reg in pass_2]
        res3 = await asyncio.gather(*tasks3)
        final_items = [pass_2[i] for i, ok in enumerate(res3) if ok]
        print(f"[+] 第三阶段完成！支持自定义托管域名的 IP: {len(final_items)} 个", flush=True)

    # 导出归类结果
    print("\n==================== 扫描结束 & 正在分类导出 ====================", flush=True)
    save_results_by_region_and_isp(final_items)
    print("\n[+] 所有扫描结果已成功导出至【自用】文件夹！", flush=True)

if __name__ == "__main__":
    asyncio.run(main())
