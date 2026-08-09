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

# ==================== 0. 自动优化系统内核与文件句柄限制 ====================
def optimize_system_limits():
    """自动化调优系统文件句柄限制 (ulimit) 与内核网络参数 (sysctl)"""
    print("[*] 正在尝试优化系统内核与文件描述符限制...", flush=True)
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target_limit = max(65535, hard)
        resource.setrlimit(resource.RLIMIT_NOFILE, (target_limit, target_limit))
        new_soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
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
    else:
        print("[!] 提示: 当前非 Root 用户，跳过 sysctl 内核参数优化 (若在 GitHub Actions 中默认是 Root)", flush=True)

optimize_system_limits()

try:
    import uvloop
    uvloop.install()
    UVLOOP_ENABLED = True
except ImportError:
    UVLOOP_ENABLED = False

# ==================== 配置区域 ====================
DEFAULT_PORTS = "443, 8443, 2053, 2083, 287, 2096"
CUSTOM_CF_DOMAIN = os.getenv("CUSTOM_CF_DOMAIN", "")

STAGE0_TIMEOUT = 0.8
CF_SNI_1 = "www.cloudflare.com"
STAGE1_CONCURRENCY = int(os.getenv("STAGE1_CONCURRENCY", "100"))
STAGE1_TIMEOUT = 2

CF_HOST_TEST = "crypto.cloudflare.com"
STAGE2_TIMEOUT = 1.2
STAGE3_TIMEOUT = 1.2

CPU_CORES = max(1, os.cpu_count() or 1)

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE
SSL_CTX.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3

# 原始文本数据解析
RAW_IP_DATA = """
----------------------------------------------------------------------
AS979  — 亚洲 IP 小计: 7,168
----------------------------------------------------------------------
  移动
    日本 (1 段, 512 IPs):
      154.36.156.0/23
    香港 (5 段, 4,864 IPs):
      154.64.252.0/22
      189.24.97.0/24
      189.24.98.0/23
      189.24.100.0/22
      189.24.104.0/21
  联通
    香港 (6 段, 1,792 IPs):
      64.83.1.0/24
      64.178.112.0/23
      155.103.119.0/24
      189.24.96.0/24
      199.68.217.0/24
      212.17.238.0/24

----------------------------------------------------------------------
AS3258  — 亚洲 IP 小计: 5,376
----------------------------------------------------------------------
  移动
    日本 (17 段, 5,376 IPs):
      45.11.46.0/24
      45.14.70.0/24
      45.89.234.0/23
      45.94.40.0/24
      45.128.211.0/24
      45.129.10.0/23
      45.149.157.0/24
      45.153.244.0/24
      45.153.247.0/24
      94.124.116.0/23
      147.78.244.0/24
      147.78.247.0/24
      176.119.148.0/24
      185.200.67.0/24
      185.213.150.0/23
      185.254.72.0/24
      193.17.91.0/24

----------------------------------------------------------------------
AS8888  — 亚洲 IP 小计: 3,072
----------------------------------------------------------------------
  移动
    新加坡 (11 段, 3,072 IPs):
      45.14.107.0/24
      45.89.216.0/24
      45.89.219.0/24
      45.94.41.0/24
      45.135.40.0/24
      45.135.42.0/23
      157.119.101.0/24
      185.37.255.0/24
      185.194.54.0/24
      185.222.223.0/24
      194.169.55.0/24

----------------------------------------------------------------------
AS9678  — 亚洲 IP 小计: 3,840
----------------------------------------------------------------------
  移动
    台湾 (2 段, 512 IPs):
      2.58.241.0/24
      103.131.189.0/24
  联通
    台湾 (8 段, 3,072 IPs):
      2.58.242.0/23
      45.123.117.0/24
      103.98.73.0/24
      103.98.74.0/23
      103.150.36.0/23
      103.152.150.0/23
      203.66.151.0/24
      223.26.0.0/24
    香港 (1 段, 256 IPs):
      103.37.4.0/24

----------------------------------------------------------------------
AS32135  — 亚洲 IP 小计: 768
----------------------------------------------------------------------
  移动
    新加坡 (1 段, 512 IPs):
      209.248.48.0/23
    日本 (1 段, 256 IPs):
      209.248.47.0/24

----------------------------------------------------------------------
AS54801  — 亚洲 IP 小计: 4,096
----------------------------------------------------------------------
  移动
    台湾 (4 段, 1,280 IPs):
      207.56.137.0/24
      207.56.217.0/24
      207.56.218.0/24
      207.56.220.0/23
    新加坡 (3 段, 1,280 IPs):
      103.40.10.0/23
      156.245.144.0/23
      156.245.147.0/24
    菲律宾 (2 段, 768 IPs):
      156.225.76.0/23
      156.225.78.0/24
    香港 (3 段, 768 IPs):
      154.218.0.0/24
      156.245.233.0/24
      156.245.236.0/24

----------------------------------------------------------------------
AS61112  — 亚洲 IP 小计: 1,280
----------------------------------------------------------------------
  移动
    香港 (4 段, 1,280 IPs):
      45.192.204.0/23
      151.242.125.0/24
      154.16.10.0/24
      185.155.235.0/24

----------------------------------------------------------------------
AS62468  — 亚洲 IP 小计: 7,680
----------------------------------------------------------------------
  联通
    日本 (1 段, 256 IPs):
      43.250.175.0/24
    菲律宾 (3 段, 4,864 IPs):
      45.204.208.0/20
      103.68.194.0/24
      121.54.190.0/23
    香港 (8 段, 2,560 IPs):
      43.225.57.0/24
      103.42.31.0/24
      103.68.192.0/23
      103.68.195.0/24
      121.54.188.0/23
      156.245.244.0/24
      198.44.183.0/24
      198.44.184.0/24

----------------------------------------------------------------------
AS137535  — 亚洲 IP 小计: 13,312
----------------------------------------------------------------------
  移动
    日本 (7 段, 12,288 IPs):
      103.110.220.0/23
      103.127.242.0/23
      142.248.136.0/22
      177.2.184.0/21
      177.3.88.0/21
      177.4.80.0/20
      207.56.224.0/21
  联通
    日本 (2 段, 1,024 IPs):
      38.47.192.0/23
      38.47.198.0/23

----------------------------------------------------------------------
AS137897  — 亚洲 IP 小计: 4,608
----------------------------------------------------------------------
  移动
    香港 (9 段, 4,096 IPs):
      38.76.140.0/23
      45.66.148.0/24
      103.182.96.0/24
      103.182.97.0/24
      151.242.180.0/22
      175.29.22.0/23
      187.54.48.0/23
      187.54.50.0/24
      216.38.170.0/23
  联通
    香港 (1 段, 512 IPs):
      154.203.204.0/23

----------------------------------------------------------------------
AS138997  — 亚洲 IP 小计: 1,280
----------------------------------------------------------------------
  移动
    香港 (3 段, 1,024 IPs):
      103.169.126.0/23
      169.128.54.0/24
      216.195.221.0/24
  联通
    香港 (1 段, 256 IPs):
      216.236.60.0/24

----------------------------------------------------------------------
AS139659  — 亚洲 IP 小计: 18,944
----------------------------------------------------------------------
  联通
    新加坡 (5 段, 2,560 IPs):
      83.229.120.0/23
      83.229.122.0/24
      149.104.25.0/24
      149.104.26.0/23
      149.104.28.0/22
    香港 (18 段, 16,384 IPs):
      38.55.192.0/22
      38.55.198.0/23
      38.147.170.0/23
      38.147.172.0/23
      38.207.176.0/22
      45.136.12.0/22
      45.144.136.0/23
      45.144.138.0/24
      45.145.228.0/23
      45.152.64.0/22
      68.64.176.0/21
      83.229.123.0/24
      83.229.124.0/22
      103.143.80.0/23
      103.148.58.0/23
      193.134.208.0/22
      207.57.120.0/21
      207.57.128.0/21

----------------------------------------------------------------------
AS139923  — 亚洲 IP 小计: 1,536
----------------------------------------------------------------------
  移动
    香港 (1 段, 1,024 IPs):
      156.235.104.0/22
    马来西亚 (1 段, 512 IPs):
      138.252.248.0/23

----------------------------------------------------------------------
AS151338  — 亚洲 IP 小计: 2,304
----------------------------------------------------------------------
  移动
    香港 (3 段, 768 IPs):
      103.49.61.0/24
      141.11.238.0/24
      208.75.134.0/24
  联通
    香港 (6 段, 1,536 IPs):
      82.139.221.0/24
      82.139.242.0/24
      82.139.246.0/24
      85.237.70.0/24
      213.145.82.0/24
      213.145.87.0/24

----------------------------------------------------------------------
AS151419  — 亚洲 IP 小计: 256
----------------------------------------------------------------------
  移动
    香港 (1 段, 256 IPs):
      103.158.117.0/24

----------------------------------------------------------------------
AS203923  — 亚洲 IP 小计: 512
----------------------------------------------------------------------
  移动
    香港 (2 段, 512 IPs):
      103.49.61.0/24
      141.11.238.0/24

----------------------------------------------------------------------
AS206300  — 亚洲 IP 小计: 768
----------------------------------------------------------------------
  移动
    香港 (1 段, 512 IPs):
      103.193.172.0/23
  联通
    香港 (1 段, 256 IPs):
      212.17.238.0/24

----------------------------------------------------------------------
AS400618  — 亚洲 IP 小计: 10,240
----------------------------------------------------------------------
  移动
    新加坡 (2 段, 768 IPs):
      23.249.26.0/23
      198.176.55.0/24
    日本 (10 段, 4,352 IPs):
      23.249.16.0/23
      23.249.23.0/24
      23.249.25.0/24
      82.40.32.0/22
      104.251.231.0/24
      104.251.233.0/24
      104.251.234.0/24
      104.251.238.0/24
      177.5.52.0/22
      198.176.52.0/24
    香港 (10 段, 5,120 IPs):
      23.249.18.0/23
      23.249.22.0/24
      104.251.239.0/24
      177.2.20.0/22
      177.2.24.0/22
      198.176.48.0/22
      198.176.53.0/24
      198.176.54.0/24
      198.176.56.0/24
      198.176.58.0/24
"""

def parse_structured_ip_data():
    target_regions = ["日本", "香港", "新加坡"]
    ip_records = []
    current_isp = ""
    current_region = ""
    
    for line in RAW_IP_DATA.splitlines():
        line = line.strip()
        if not line or line.startswith("-") or line.startswith("AS"):
            continue
            
        if line in ["移动", "联通"]:
            current_isp = line
            continue
            
        reg_match = re.match(r'^(日本|香港|新加坡|台湾|马来西亚|菲律宾)', line)
        if reg_match:
            current_region = reg_match.group(1)
            continue
            
        cidr_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', line)
        if cidr_match:
            cidr = cidr_match.group(1)
            if current_region in target_regions and current_isp in ["移动", "联通"]:
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    hosts = list(net) if net.prefixlen >= 31 else list(net.hosts())
                    for ip in hosts:
                        ip_records.append({
                            "ip": str(ip),
                            "isp": current_isp,
                            "region": current_region
                        })
                except Exception:
                    pass
    return ip_records

def parse_ports(port_str):
    if not port_str:
        return [443, 8443, 2053, 2083, 287, 2096]
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
    return sorted(list(ports)) if ports else [443, 8443, 2053, 2083, 287, 2096]

async def check_tcp_open_async(ip, port, timeout_val, sem):
    async with sem:
        writer = None
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout_val)
            return True
        except Exception:
            return False
        finally:
            if writer:
                writer.close()
                try:
                    writer.transport.abort()
                except Exception:
                    pass

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

def _process_worker_stage1(targets_chunk):
    if UVLOOP_ENABLED:
        uvloop.install()
        
    async def _run():
        sem = asyncio.Semaphore(STAGE1_CONCURRENCY)
        async def worker(item):
            res = await check_tls_sni_async(item["ip"], item["port"], CF_SNI_1, STAGE1_TIMEOUT, sem)
            return res

        tasks = [worker(item) for item in targets_chunk]
        results = await asyncio.gather(*tasks)
        return [targets_chunk[i] for i, ok in enumerate(results) if ok]

    return asyncio.run(_run())

async def main():
    ports_input = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_PORTS
    target_ports = parse_ports(ports_input)
    
    print("[*] 正在解析内置列表中 (日本、香港、新加坡) 的 IP 段...", flush=True)
    all_ip_records = parse_structured_ip_data()
    
    if not all_ip_records:
        print("[-] 未能解析出任何符合条件的 IP，程序退出。", flush=True)
        return

    # 构建全局测试列表
    targets = []
    for item in all_ip_records:
        for port in target_ports:
            targets.append({
                "ip": item["ip"],
                "port": port,
                "isp": item["isp"],
                "region": item["region"]
            })

    total_targets_count = len(targets)
    total_concurrency = STAGE1_CONCURRENCY * CPU_CORES
    print(f"[*] 引擎初始化: uvloop={UVLOOP_ENABLED} | 进程数={CPU_CORES} | 单进程并发={STAGE1_CONCURRENCY} | 总并发数={total_concurrency}", flush=True)
    print(f"[*] 解析完成: {len(all_ip_records)} 个 IP × {len(target_ports)} 个端口 = 共 {total_targets_count:,} 个测试目标。", flush=True)

    # ==================== 0. TCP 极速分批探活 (防御 OOM 崩溃) ====================
    sem_tcp = asyncio.Semaphore(total_concurrency)
    print(f"\n[0/3] TCP 极速分批探测中...", flush=True)

    pass_0 = []
    chunk_size = 20000  # 每次仅投递 20,000 个任务到内存，防止 GitHub Actions OOM 报错

    for i in range(0, total_targets_count, chunk_size):
        chunk = targets[i:i + chunk_size]
        tasks0 = [check_tcp_open_async(item["ip"], item["port"], STAGE0_TIMEOUT, sem_tcp) for item in chunk]
        res0 = await asyncio.gather(*tasks0)
        
        for idx, ok in enumerate(res0):
            if ok:
                pass_0.append(chunk[idx])
                
        completed = min(i + chunk_size, total_targets_count)
        pct = int(completed / total_targets_count * 100)
        print(f"  [TCP 探测进度] {pct}% ({completed:,}/{total_targets_count:,}) | 当前存活: {len(pass_0):,} 个", flush=True)

    print(f"[+] TCP 开放节点: {len(pass_0):,} 个", flush=True)

    if not pass_0:
        print("[-] 无任何开放节点，退出。", flush=True)
        return

    # ==================== 1. 多进程 TLS 过滤 ====================
    print(f"\n[1/3] TLS 证书匹配中 (待测目标: {len(pass_0):,} 个)...", flush=True)
    num_chunks = CPU_CORES * 4
    chunk_size_stage1 = max(1, len(pass_0) // num_chunks)
    chunks = [pass_0[i:i + chunk_size_stage1] for i in range(0, len(pass_0), chunk_size_stage1)]

    pass_1 = []
    loop = asyncio.get_running_loop()
    with ProcessPoolExecutor(max_workers=CPU_CORES) as executor:
        futures = [loop.run_in_executor(executor, _process_worker_stage1, chunk) for chunk in chunks]
        results = await asyncio.gather(*futures)
        for res in results:
            pass_1.extend(res)

    print(f"[+] TLS 匹配保留: {len(pass_1):,} 个", flush=True)
    if not pass_1:
        print("[-] 无有效 IP 通过第一阶段。", flush=True)
        return

    # ==================== 2. HTTP 校验 ====================
    sem = asyncio.Semaphore(total_concurrency)
    print(f"\n[2/3] HTTP 重定向校验中...", flush=True)
    tasks2 = [check_http_async(item["ip"], item["port"], CF_HOST_TEST, STAGE2_TIMEOUT, sem) for item in pass_1]
    res2 = await asyncio.gather(*tasks2)
    pass_2 = [pass_1[i] for i, ok in enumerate(res2) if ok]
    print(f"[+] HTTP 301/302 通过: {len(pass_2):,} 个", flush=True)

    # ==================== 3. 自定义域名校验 ====================
    final_items = pass_2
    if CUSTOM_CF_DOMAIN and CUSTOM_CF_DOMAIN.strip():
        print(f"\n[3/3] 自定义域名反代校验中 ({CUSTOM_CF_DOMAIN})...", flush=True)
        tasks3 = [check_tls_sni_async(item["ip"], item["port"], CUSTOM_CF_DOMAIN.strip(), STAGE3_TIMEOUT, sem) for item in pass_2]
        res3 = await asyncio.gather(*tasks3)
        final_items = [pass_2[i] for i, ok in enumerate(res3) if ok]
        print(f"[+] 自定义域名支持节点: {len(final_items):,} 个", flush=True)

    # ==================== 结果归类与导出 ====================
    print("\n==================== 扫描完毕，正在生成文件 ====================")
    
    region_data = {
        "日本": defaultdict(list),
        "香港": defaultdict(list),
        "新加坡": defaultdict(list)
    }

    unique_set = set()
    for item in final_items:
        key = (item["region"], item["isp"], item["ip"], item["port"])
        if key not in unique_set:
            unique_set.add(key)
            region_data[item["region"]][item["isp"]].append(f"{item['ip']}:{item['port']}")

    output_dir = os.getcwd()

    for reg in ["日本", "香港", "新加坡"]:
        out_file = os.path.join(output_dir, f"{reg}.txt")
        isp_dict = region_data[reg]
        
        cmcc_list = sorted(isp_dict.get("移动", []), key=lambda x: (ipaddress.ip_address(x.split(":")[0]), int(x.split(":")[1])))
        cucc_list = sorted(isp_dict.get("联通", []), key=lambda x: (ipaddress.ip_address(x.split(":")[0]), int(x.split(":")[1])))
        
        with open(out_file, "w", encoding="utf-8") as f:
            if cmcc_list:
                f.write("移动\n")
                for node in cmcc_list:
                    f.write(f"{node}\n")
                f.write("\n")
                
            if cucc_list:
                f.write("联通\n")
                for node in cucc_list:
                    f.write(f"{node}\n")
                f.write("\n")
                
        print(f"[+] 文件生成成功: {reg}.txt (移动: {len(cmcc_list)} 个, 联通: {len(cucc_list)} 个)")

if __name__ == "__main__":
    asyncio.run(main())
