import os
import re
import sys
import asyncio
import ssl
import random
import socket
import multiprocessing
import logging
from concurrent.futures import ProcessPoolExecutor
from functools import lru_cache

# 静默 uvloop / asyncio 底层 SSL 连接断开刷屏报错
logging.getLogger("asyncio").setLevel(logging.CRITICAL)

# 获取当前脚本所在的绝对路径（仓库根目录）
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 阶段 1：TLS 粗筛 (www.cloudflare.com)
CF_SNI_1 = "www.cloudflare.com"
STAGE1_CONCURRENCY = int(os.getenv("STAGE1_CONCURRENCY", "1500"))   # 单进程并发数（第一阶段）
STAGE1_TIMEOUT = 2        # 超时时间

# 阶段 2：HTTP 验证并发数（硬件平滑控速，固定为 200 并发）
STAGE2_CONCURRENCY = 200
CF_HOST_TEST = "crypto.cloudflare.com"
STAGE2_TIMEOUT = 1.2

# 阶段 3：自定义域名校验超时
STAGE3_TIMEOUT = 1.2

# CPU 核心数 (决定多进程并行数量)
CPU_CORES = max(1, os.cpu_count() or 1)

async def main():
    target_input = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGETS
    ports_input = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_PORTS

    target_ports = parse_ports(ports_input)
    
    print(f"\n[*] 正在解析目标地址/ASN: {target_input} ...", flush=True)
    all_ips = await parse_targets_async(target_input)

    if not all_ips:
        print("[-] 未能获取到任何待测 IP，程序退出。", flush=True)
        return

    targets = [(ip, port) for ip in all_ips for port in target_ports]
    total_targets_count = len(targets)

    total_concurrency = STAGE1_CONCURRENCY * CPU_CORES
    print(f"[*] 引擎初始化：uvloop={UVLOOP_ENABLED} | 进程数={CPU_CORES} | 第一阶段并发={total_concurrency} | 第二阶段速率=200", flush=True)
    print(f"[*] 解析完成：{len(all_ips)} 个 IP × {len(target_ports)} 个端口 = 共 {total_targets_count:,} 个测试目标。", flush=True)

    # ==================== 1. 多进程 TLS 粗筛 ====================
    print(f"\n[1/3 第一阶段 TLS 探测] 多进程并行并发中...", flush=True)
    
    num_chunks = CPU_CORES * 4
    chunk_size = max(1, total_targets_count // num_chunks)
    chunks = [targets[i:i + chunk_size] for i in range(0, total_targets_count, chunk_size)]

    manager = multiprocessing.Manager()
    counter = manager.Value('i', 0)        # 已测试总数
    pass_counter = manager.Value('i', 0)   # 匹配通过总数
    lock = manager.Lock()
    printed_array = manager.Array('i', [0] * 10) # 记录 10% ~ 100% 打印标记位

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
    # 单独建立第二阶段信号量，强行限定并发上限为 200，防崩溃
    sem_stage2 = asyncio.Semaphore(STAGE2_CONCURRENCY)
    print(f"[2/3 第二阶段 HTTP 校验] 正在以 {STAGE2_CONCURRENCY} 并发平滑校验 {len(pass_1)} 个候选目标...", flush=True)
    tasks2 = [check_http_async(ip, port, CF_HOST_TEST, STAGE2_TIMEOUT, sem_stage2) for ip, port in pass_1]
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
        print(f"[3/3 第三阶段自定义域名校验] 正在以 {STAGE2_CONCURRENCY} 并发校验域名 {domain}...", flush=True)
        tasks3 = [check_tls_sni_async(ip, port, domain, STAGE3_TIMEOUT, sem_stage2) for ip, port in pass_2]
        res3 = await asyncio.gather(*tasks3)
        final_items = [pass_2[i] for i, ok in enumerate(res3) if ok]
        print(f"[+] 第三阶段完成！支持自定义托管域名的优选反代 IP: {len(final_items)} 个", flush=True)
    else:
        print("[3/3] 未检测到 CUSTOM_CF_DOMAIN，自动跳过第三阶段。", flush=True)

    final_items = sorted(final_items, key=lambda x: (ipaddress.ip_address(x[0]), x[1]))

    # ==================== 导出结果 ====================
    print("\n==================== 扫描结束 ====================", flush=True)
    print(f"最终有效目标总数: {len(final_items)}", flush=True)

    match_asn = re.search(r'(?:AS)?(\d+)', target_input, re.IGNORECASE)
    if match_asn:
        filename = f"AS{match_asn.group(1)}.txt"
    else:
        clean_input = re.sub(r'[^\w\.-]', '_', target_input.strip())
        filename = f"{clean_input[:30]}.txt"

    # 指定输出路径为仓库根目录下的 '优选反代ip' 目录
    output_dir = os.path.join(BASE_DIR, "优选反代ip")
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, filename)

    with open(output_path, "w", encoding="utf-8") as f:
        for ip, port in final_items:
            f.write(f"{ip}:{port}\n")

    print(f"\n[+] 最终结果已排序保存至：{output_path} (格式为 IP:PORT)", flush=True)

if __name__ == "__main__":
    asyncio.run(main())
