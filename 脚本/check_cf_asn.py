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

# 获取当前脚本所在的绝对路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ==================== 0. 自动优化系统内核与文件句柄限制 ====================
def optimize_system_limits():
    """自动化调优系统文件句柄限制 (ulimit) 与内核网络参数 (sysctl)"""
    print("[*] 正在尝试优化系统内核与文件描述符限制...", flush=True)

    # 1. 自动提升文件句柄限制 (ulimit -n)
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target_limit = max(65535, hard)
        resource.setrlimit(resource.RLIMIT_NOFILE, (target_limit, target_limit))
        new_soft, new_hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        print(f"[+] 文件描述符上限 (ulimit) 调整成功: {new_soft}", flush=True)
    except Exception as e:
        print(f"[-] 调整 ulimit 失败 (可能无权限): {e}", flush=True)

    # 2. 修改内核网络参数 (需要 Root 权限)
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
    else:
        print("[!] 提示: 当前非 Root 用户，跳过 sysctl 内核参数优化（若在 GitHub Actions 中默认是 Root）", flush=True)

# 启动第一时间执行系统调优
optimize_system_limits()

# 尝试加载 uvloop 替代 Python 原生 asyncio 循环 (IO 性能提升 2~4 倍)
try:
    import uvloop
    uvloop.install()
    UVLOOP_ENABLED = True
except ImportError:
    UVLOOP_ENABLED = False

# ==================== 极限性能配置区域 ====================
DEFAULT_TARGETS = os.getenv("TARGET_LIST", os.getenv("ASN_LIST", "AS36002"))
DEFAULT_PORTS = "443, 8443, 2053, 2083, 2096"

# SNI 仅用于 TLS 握手协商
CF_SNI = "www.cloudflare.com"
STAGE1_CONCURRENCY = int(os.getenv("STAGE1_CONCURRENCY", "1500"))   # 单进程并发数
STAGE1_TIMEOUT = 2        # TLS 握手超时 2s

# CPU 核心数 (决定多进程并行数量)
CPU_CORES = max(1, os.cpu_count() or 1)

# 优化 SSL Context 避免不必要的握手开销
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE
SSL_CTX.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3

# 全局共享变量定义 (多进程进度与通过数同步)
global_counter = None
global_pass_counter = None
global_lock = None
global_total = 0
global_step = 0
global_printed_milestones = None
# =========================================================

def parse_ports(port_str):
    """支持 443,8443 或 1-65535 范围解析"""
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


@lru_cache(maxsize=32)
def get_cidrs_from_asn_sync(asn_clean):
    """同步阻塞获取 ASN 的 IP 段 CIDR 列表 (带 lru_cache)"""
    import urllib.request
    cidrs = []
    
    # 源 1: RIPE
    try:
        ripe_url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_clean}"
        req = urllib.request.Request(ripe_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=8) as response:
            data = json.loads(response.read().decode())
            prefixes = data.get("data", {}).get("prefixes", [])
            for p in prefixes:
                prefix = p.get("prefix")
                if prefix and ":" not in prefix:
                    cidrs.append(prefix)
    except Exception:
        pass

    # 源 2: BGPView 兜底
    if not cidrs:
        try:
            bgp_url = f"https://api.bgpview.io/asn/{asn_clean}/prefixes"
            req = urllib.request.Request(bgp_url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=8) as response:
                data = json.loads(response.read().decode())
                ipv4_prefixes = data.get("data", {}).get("ipv4_prefixes", [])
                for p in ipv4_prefixes:
                    prefix = p.get("prefix")
                    if prefix:
                        cidrs.append(prefix)
        except Exception:
            pass

    return cidrs


def sample_ips_per_24(net, count=3):
    """
    接收一个 ipaddress.IPv4Network 对象：
    - 若网络掩码 <= 24 (比如 /16, /20, /24)，拆分成多个 /24 段，在每个 /24 段内随机抽取 count(默认3) 个 IP；
    - 若网络掩码 > 24 (比如 /25, /32)，最多随机抽取 count 个可用 IP。
    """
    sampled_ips = []
    if net.prefixlen <= 24:
        subnets_24 = list(net.subnets(new_prefix=24))
        for sub in subnets_24:
            hosts = [str(ip) for ip in sub.hosts()]
            if hosts:
                # 若可用 IP 不够 count 个则全取，否则随机抽取 count 个
                num_to_sample = min(len(hosts), count)
                sampled_ips.extend(random.sample(hosts, num_to_sample))
            else:
                sampled_ips.append(str(sub.network_address))
    else:
        hosts = [str(ip) for ip in net.hosts()]
        if hosts:
            num_to_sample = min(len(hosts), count)
            sampled_ips.extend(random.sample(hosts, num_to_sample))
        else:
            sampled_ips.append(str(net.network_address))
            
    return sampled_ips


async def parse_targets_async(input_str):
    """解析输入，拆分为 /24 并在每个 /24 段内随机抽取 3 个 IP"""
    loop = asyncio.get_running_loop()
    raw_targets = [t.strip() for t in re.split(r'[\s,]+', input_str) if t.strip()]
    sampled_ips = []

    for item in raw_targets:
        # 尝试作为 CIDR/单个 IP 解析
        try:
            net = ipaddress.ip_network(item, strict=False)
            sampled_ips.extend(sample_ips_per_24(net, count=3))
            continue
        except ValueError:
            pass

        # 尝试作为 ASN 解析
        asn_clean = item.upper().replace("AS", "")
        if asn_clean.isdigit():
            cidrs = await loop.run_in_executor(None, get_cidrs_from_asn_sync, asn_clean)
            for cidr in cidrs:
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    sampled_ips.extend(sample_ips_per_24(net, count=3))
                except ValueError:
                    continue

    # 去重并打乱顺序
    unique_ips = list(dict.fromkeys(sampled_ips))
    random.shuffle(unique_ips)
    return unique_ips


async def check_has_cert_async(ip, port, sni, timeout_val, sem):
    """仅检测目标端口是否能正常完成 TLS 握手并返回证书"""
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
            # 只要成功返回证书（二进制内容不为空）即判定有效
            return bool(der_cert)
        except Exception:
            return False
        finally:
            if writer:
                writer.close()
                try:
                    writer.transport.abort()
                except Exception:
                    pass


# ==================== 多进程共享变量初始化 ====================
def _init_process_worker(counter, pass_counter, lock, total, printed_array):
    """初始化子进程的全局锁与共享内存计数器"""
    global global_counter, global_pass_counter, global_lock, global_total, global_step, global_printed_milestones
    global_counter = counter
    global_pass_counter = pass_counter
    global_lock = lock
    global_total = total
    global_step = max(1, total // 10)  # 全局总量的 10% 步长
    global_printed_milestones = printed_array


def _process_worker_stage1(targets_chunk):
    """子进程内部运行独立的 uvloop/asyncio 事件循环，同步全局 10% 进度及通过数"""
    if UVLOOP_ENABLED:
        uvloop.install()
        
    async def _run():
        sem = asyncio.Semaphore(STAGE1_CONCURRENCY)

        async def worker(ip, port):
            res = await check_has_cert_async(ip, port, CF_SNI, STAGE1_TIMEOUT, sem)
            
            # 使用原子锁更新全局共享计数器
            with global_lock:
                global_counter.value += 1
                if res:
                    global_pass_counter.value += 1
                    
                curr = global_counter.value
                passed = global_pass_counter.value
                
                # 计算当前处于全局第几个 10% 节点
                milestone_idx = curr // global_step
                if 1 <= milestone_idx <= 10:
                    # 确保每个 10% 阶段全局只会被一个进程打印一次
                    if global_printed_milestones[milestone_idx - 1] == 0:
                        global_printed_milestones[milestone_idx - 1] = 1
                        pct = min(100, milestone_idx * 10)
                        print(f"  [检测进度] {pct}% ({curr:,}/{global_total:,}) | 含有证书 IP: {passed:,} 个", flush=True)

            return res

        tasks = [worker(ip, port) for ip, port in targets_chunk]
        results = await asyncio.gather(*tasks)
        return [targets_chunk[i] for i, ok in enumerate(results) if ok]

    return asyncio.run(_run())


async def main():
    target_input = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGETS
    ports_input = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_PORTS

    target_ports = parse_ports(ports_input)
    
    print(f"\n[*] 正在解析目标地址/ASN: {target_input} (提取规则: 每个 /24 段抽取 3 个 IP) ...", flush=True)
    all_ips = await parse_targets_async(target_input)

    if not all_ips:
        print("[-] 未能获取到任何待测 IP，程序退出。", flush=True)
        return

    targets = [(ip, port) for ip in all_ips for port in target_ports]
    total_targets_count = len(targets)
    
    total_concurrency = STAGE1_CONCURRENCY * CPU_CORES
    print(f"[*] 引擎初始化：uvloop={UVLOOP_ENABLED} | 进程数={CPU_CORES} | 单进程并发={STAGE1_CONCURRENCY} | 总并发数={total_concurrency}", flush=True)
    print(f"[*] 解析完成：共提取出 {len(all_ips)} 个代表 IP × {len(target_ports)} 个端口 = 共 {total_targets_count:,} 个测试目标。", flush=True)

    # ==================== TLS 证书探测 ====================
    print(f"\n[*] 正在检测 TLS 证书握手...", flush=True)
    
    num_chunks = CPU_CORES * 4
    chunk_size = max(1, total_targets_count // num_chunks)
    chunks = [targets[i:i + chunk_size] for i in range(0, total_targets_count, chunk_size)]

    # 创建跨进程共享内存对象
    manager = multiprocessing.Manager()
    counter = manager.Value('i', 0)        # 已测试总数
    pass_counter = manager.Value('i', 0)   # 匹配通过总数
    lock = manager.Lock()
    printed_array = manager.Array('i', [0] * 10) # 记录 10% ~ 100% 打印标记位

    passed_targets = []
    loop = asyncio.get_running_loop()
    
    # 传入 initializer 将共享锁与共享变量注入各个子进程
    with ProcessPoolExecutor(
        max_workers=CPU_CORES,
        initializer=_init_process_worker,
        initargs=(counter, pass_counter, lock, total_targets_count, printed_array)
    ) as executor:
        futures = [loop.run_in_executor(executor, _process_worker_stage1, chunk) for chunk in chunks]
        results = await asyncio.gather(*futures)
        for res in results:
            passed_targets.extend(res)

    print(f"[+] TLS 证书检测完成！成功返回证书的目标: {len(passed_targets)} 个\n", flush=True)

    if not passed_targets:
        print("[-] 未检测到任何支持 TLS 证书的 IP:端口。", flush=True)
        return

    # 排序导出的最终结果
    final_items = sorted(passed_targets, key=lambda x: (ipaddress.ip_address(x[0]), x[1]))

    # ==================== 导出结果 ====================
    print("==================== 扫描结束 ====================", flush=True)
    print(f"含有证书的有效目标总数: {len(final_items)}", flush=True)

    # 替换非法字符
    clean_input = re.sub(r'[^\w\.-]', '_', target_input.strip())
    
    # 防止文件名超过 Linux 255 字节限制
    if len(clean_input) > 30:
        filename = f"{clean_input[:30]}_batch.txt"
    else:
        filename = f"{clean_input}.txt"

    # 自动定位仓库根目录
    repo_root = BASE_DIR
    if os.path.exists(os.path.join(os.path.dirname(BASE_DIR), ".git")):
        repo_root = os.path.dirname(BASE_DIR)
    elif os.path.basename(BASE_DIR) == "脚本":
        repo_root = os.path.dirname(BASE_DIR)

    # 指定输出保存路径为仓库根目录下的 '优选反代ip'
    output_dir = os.path.join(repo_root, "优选反代ip")
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, filename)

    with open(output_path, "w", encoding="utf-8") as f:
        for ip, port in final_items:
            f.write(f"{ip}:{port}\n")

    print(f"\n[+] 最终结果已排序保存至：{output_path} (格式为 IP:PORT)", flush=True)

if __name__ == "__main__":
    asyncio.run(main())
