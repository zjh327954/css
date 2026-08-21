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
import gc
import multiprocessing
import urllib.request
from concurrent.futures import ProcessPoolExecutor

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ==================== 0. 系统优化 ====================
def optimize_system_limits():
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target_limit = max(65535, hard)
        resource.setrlimit(resource.RLIMIT_NOFILE, (target_limit, target_limit))
        print(f"[+] 文件描述符上限: {resource.getrlimit(resource.RLIMIT_NOFILE)[0]}", flush=True)
    except Exception as e:
        print(f"[-] 调整 ulimit 失败: {e}", flush=True)

optimize_system_limits()

try:
    import uvloop
    uvloop.install()
    UVLOOP_ENABLED = True
except ImportError:
    UVLOOP_ENABLED = False

# ==================== 配置 ====================
DEFAULT_TARGETS = sys.argv[1] if len(sys.argv) > 1 else os.getenv("TARGET_LIST", "AS203923")
PORTS_INPUT = sys.argv[2] if len(sys.argv) > 2 else "443 8443"
MASSCAN_JSON_FILE = sys.argv[3] if len(sys.argv) > 3 else "masscan_out.json"

CUSTOM_CF_DOMAIN = os.getenv("CUSTOM_CF_DOMAIN", "327954.ccwu.cc")

CF_SNI_1 = "www.cloudflare.com"
STAGE1_CONCURRENCY = int(os.getenv("STAGE1_CONCURRENCY", "1500"))
STAGE1_TIMEOUT = 2

CF_HOST_TEST = "crypto.cloudflare.com"
STAGE2_TIMEOUT = 1.2
STAGE3_TIMEOUT = 1.2

CF_API_URL = "https://api.090227.xyz/check"
STAGE4_CONCURRENCY = int(os.getenv("STAGE4_CONCURRENCY", "32"))
STAGE4_TIMEOUT = 15
STAGE4_RETRIES = 3
STAGE4_RETRY_DELAY = 1

# 批量大小（防止 OOM）
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "10000"))
# 第一阶段输出上限（超过则警告并截断）
STAGE1_MAX_PASS = int(os.getenv("STAGE1_MAX_PASS", "500000"))

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

# ==================== 工具函数 ====================
def load_targets_from_masscan(json_file):
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
            for item in data:
                ip = item.get("ip")
                for p in item.get("ports", []):
                    port = p.get("port")
                    if ip and port:
                        targets.append((ip, int(port)))
    except Exception as e:
        print(f"[-] 解析 Masscan 失败: {e}", flush=True)
    return targets

def match_domain_in_cert(sni_domain, cert_str):
    sni_domain = sni_domain.lower()
    cert_str = cert_str.lower()
    if sni_domain in cert_str:
        return True
    parts = sni_domain.split(".")
    if len(parts) >= 2:
        main_domain = ".".join(parts[-2:])
        if main_domain in cert_str or f"*.{main_domain}" in cert_str:
            return True
    if "cloudflare" in sni_domain and "cloudflare" in cert_str:
        return True
    return False

# ==================== 批量处理（核心修复）====================
async def batch_gather(coro_fn, items, sem, timeout_val, batch_size=BATCH_SIZE, stage_name=""):
    """分批创建协程，避免一次性创建百万个导致 OOM"""
    results = []
    total = len(items)
    for i in range(0, total, batch_size):
        batch = items[i:i + batch_size]
        tasks = [coro_fn(ip, port, timeout_val, sem) for ip, port in batch]
        batch_results = await asyncio.gather(*tasks)
        results.extend(batch_results)
        done = min(i + batch_size, total)
        pct = done * 100 // total
        passed = sum(1 for r in batch_results if r)
        print(f"  [{stage_name}进度] {pct}% ({done:,}/{total:,}) | 本批通过: {passed}", flush=True)
        del tasks, batch_results
        gc.collect()
    return results

async def batch_gather_tls(coro_fn, items, sem, sni, timeout_val, batch_size=BATCH_SIZE, stage_name=""):
    """分批处理 TLS 类校验（需要 sni 参数）"""
    results = []
    total = len(items)
    for i in range(0, total, batch_size):
        batch = items[i:i + batch_size]
        tasks = [coro_fn(ip, port, sni, timeout_val, sem) for ip, port in batch]
        batch_results = await asyncio.gather(*tasks)
        results.extend(batch_results)
        done = min(i + batch_size, total)
        pct = done * 100 // total
        passed = sum(1 for r in batch_results if r)
        print(f"  [{stage_name}进度] {pct}% ({done:,}/{total:,}) | 本批通过: {passed}", flush=True)
        del tasks, batch_results
        gc.collect()
    return results

# ==================== 检测函数 ====================
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

async def check_http_async(ip, port, timeout_val, sem):
    async with sem:
        writer = None
        try:
            conn = asyncio.open_connection(ip, port, ssl=SSL_CTX, server_hostname=CF_HOST_TEST)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout_val)
            sock = writer.get_extra_info('socket')
            if sock:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            req = f"GET / HTTP/1.1\r\nHost: {CF_HOST_TEST}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
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

async def check_cf_api_async(ip, port, sem):
    async with sem:
        ip_port = f"{ip}:{port}"
        url = f"{CF_API_URL}?proxyip={ip_port}"
        headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/json", "Origin": "https://090227.xyz"}
        for attempt in range(1, STAGE4_RETRIES + 1):
            try:
                req = urllib.request.Request(url, headers=headers)
                loop = asyncio.get_running_loop()
                def _fetch():
                    with urllib.request.urlopen(req, timeout=STAGE4_TIMEOUT) as resp:
                        return json.loads(resp.read())
                data = await loop.run_in_executor(None, _fetch)
                if data.get("success"):
                    pr = data.get("probe_results", {})
                    exit_info = pr.get("ipv4", {}).get("exit") or pr.get("ipv6", {}).get("exit") or {}
                    return {
                        "ip": ip, "port": port, "tls": "TRUE",
                        "colo": exit_info.get("colo", data.get("colo", "")),
                        "country": exit_info.get("country", ""),
                        "region": exit_info.get("region", ""),
                        "latency": "", "speed": "",
                        "asn": f"AS{exit_info.get('asn', '')}" if exit_info.get('asn') else "",
                    }
                else:
                    return None
            except Exception:
                if attempt < STAGE4_RETRIES:
                    await asyncio.sleep(STAGE4_RETRY_DELAY)
                    continue
                return None
        return None

# ==================== 多进程 worker ====================
def silent_exception_handler(loop, context):
    exception = context.get("exception")
    if isinstance(exception, (ConnectionResetError, TimeoutError, OSError)):
        return

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
        async def worker(ip, port):
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
        # 分批处理，避免一次性创建百万协程导致 OOM
        passed_items = []
        worker_batch = BATCH_SIZE
        for i in range(0, len(targets_chunk), worker_batch):
            batch = targets_chunk[i:i + worker_batch]
            tasks = [worker(ip, port) for ip, port in batch]
            batch_results = await asyncio.gather(*tasks)
            for j, ok in enumerate(batch_results):
                if ok:
                    passed_items.append(batch[j])
            del tasks, batch_results
            gc.collect()
        return passed_items
    return asyncio.run(_run())

# ==================== 主流程 ====================
async def main():
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(silent_exception_handler)

    print(f"[*] 正在加载 Masscan 数据: {MASSCAN_JSON_FILE} ...", flush=True)
    targets = load_targets_from_masscan(MASSCAN_JSON_FILE)
    if not targets:
        print("[-] 无开放端口目标，退出。", flush=True)
        return

    random.shuffle(targets)
    total_targets_count = len(targets)
    total_concurrency = STAGE1_CONCURRENCY * CPU_CORES

    print(f"[*] 引擎: uvloop={UVLOOP_ENABLED} | 进程={CPU_CORES} | 并发={total_concurrency} | 批量={BATCH_SIZE}", flush=True)
    print(f"[*] Masscan 开放端口: {total_targets_count:,} 个", flush=True)

    # 内存预警
    if total_targets_count > 1_000_000:
        print(f"[!] 警告: 目标数量 {total_targets_count:,} 超过 100 万，可能需要较长时间和较多内存", flush=True)
    if total_targets_count > 5_000_000:
        print(f"[!!] 严重警告: 目标数量 {total_targets_count:,} 超过 500 万，建议减少端口范围或使用更小的 ASN", flush=True)

    manager = multiprocessing.Manager()
    global_counter_var = manager.Value('i', 0)
    global_pass_counter_var = manager.Value('i', 0)
    global_lock_var = manager.Lock()
    global_printed_array = manager.Array('i', [0] * 10)

    # ==================== 1. 第一阶段 TLS 证书匹配 ====================
    print(f"\n[1/4 第一阶段 TLS 证书匹配] 多进程并行校验中...", flush=True)
    num_chunks = CPU_CORES * 4
    chunk_size = max(1, total_targets_count // num_chunks)
    chunks = [targets[i:i + chunk_size] for i in range(0, total_targets_count, chunk_size)]

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

    print(f"[+] 第一阶段完成！通过: {len(pass_1):,} 个\n", flush=True)

    if not pass_1:
        print("[-] 无目标通过第一阶段。", flush=True)
        return

    # 释放第一阶段内存
    del targets, chunks, results
    gc.collect()

    sem = asyncio.Semaphore(STAGE1_CONCURRENCY * CPU_CORES)

    # ==================== 2. 第二阶段 HTTP 校验（批量处理）====================
    print(f"[2/4 第二阶段 HTTP 校验] {len(pass_1):,} 个目标，批量 {BATCH_SIZE} 处理中...", flush=True)
    res2 = await batch_gather(check_http_async, pass_1, sem, STAGE2_TIMEOUT, BATCH_SIZE, "第二阶段HTTP")
    pass_2 = [pass_1[i] for i, ok in enumerate(res2) if ok]
    print(f"[+] 第二阶段完成！通过: {len(pass_2):,} 个\n", flush=True)

    if not pass_2:
        print("[-] 无目标通过第二阶段。", flush=True)
        return

    del pass_1, res2
    gc.collect()

    # ==================== 3. 第三阶段 自定义域名校验（批量处理）====================
    final_items = pass_2
    if CUSTOM_CF_DOMAIN and CUSTOM_CF_DOMAIN.strip():
        domain = CUSTOM_CF_DOMAIN.strip()
        print(f"[3/4 第三阶段自定义域名校验] 域名 {domain}，批量 {BATCH_SIZE} 处理中...", flush=True)
        res3 = await batch_gather_tls(check_tls_sni_async, pass_2, sem, domain, STAGE3_TIMEOUT, BATCH_SIZE, "第三阶段域名")
        final_items = [pass_2[i] for i, ok in enumerate(res3) if ok]
        print(f"[+] 第三阶段完成！通过: {len(final_items):,} 个", flush=True)
        del res3

    # 去重
    seen = set()
    deduped = []
    for ip, port in final_items:
        key = f"{ip}:{port}"
        if key not in seen:
            seen.add(key)
            deduped.append((ip, port))
    if len(deduped) < len(final_items):
        print(f"[+] 去重: {len(final_items)} → {len(deduped)}", flush=True)

    final_items = sorted(deduped, key=lambda x: (ipaddress.ip_address(x[0]), x[1]))
    del pass_2, deduped
    gc.collect()

    # 输出目录
    clean_input = re.sub(r'[^\w\.-]', '_', DEFAULT_TARGETS.strip())
    output_dir = os.path.join(BASE_DIR, "..", "优选反代ip") if os.path.basename(BASE_DIR) == "脚本" else os.path.join(BASE_DIR, "优选反代ip")
    os.makedirs(output_dir, exist_ok=True)

    # ==================== 4. 第四阶段 API 精筛 ====================
    if not final_items:
        print("[-] 无有效目标，跳过。", flush=True)
        return

    print(f"\n[4/4 第四阶段 API 精筛] {len(final_items):,} 个，并发 {STAGE4_CONCURRENCY}...", flush=True)

    # 第四阶段也用批量处理
    api_sem = asyncio.Semaphore(STAGE4_CONCURRENCY)
    csv_rows = []
    api_passed = 0
    api_failed = 0
    api_batch_size = max(BATCH_SIZE, 5000)

    for i in range(0, len(final_items), api_batch_size):
        batch = final_items[i:i + api_batch_size]
        tasks4 = [check_cf_api_async(ip, port, api_sem) for ip, port in batch]
        res4 = await asyncio.gather(*tasks4)

        for result in res4:
            if result:
                csv_rows.append(result)
                api_passed += 1
            else:
                ip, port = final_items[len(csv_rows) - api_passed]  # fallback
                csv_rows.append({"ip": ip, "port": port, "tls": "FALSE", "colo": "", "country": "", "region": "", "latency": "", "speed": "", "asn": ""})
                api_failed += 1

        done = min(i + api_batch_size, len(final_items))
        pct = done * 100 // len(final_items)
        print(f"  [API 精筛进度] {pct}% ({done:,}/{len(final_items):,}) | 成功: {api_passed} | 失败: {api_failed}", flush=True)
        del tasks4, res4
        gc.collect()

    csv_filename = f"{clean_input[:30]}.csv"
    csv_path = os.path.join(output_dir, csv_filename)
    with open(csv_path, "w", encoding="utf-8-sig") as f:
        f.write("IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN\n")
        for row in csv_rows:
            f.write(f"{row['ip']},{row['port']},{row['tls']},{row['colo']},{row['country']},{row['region']},{row['latency']},{row['speed']},{row['asn']}\n")

    print(f"[+] 第四阶段完成！成功: {api_passed} | 失败: {api_failed}", flush=True)
    print(f"[+] CSV: {csv_path}", flush=True)
    print(f"\n[✓] 全部完成！", flush=True)

if __name__ == "__main__":
    asyncio.run(main())
