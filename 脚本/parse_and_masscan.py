import sys, json, urllib.request, os, re, subprocess

# 接收输入参数
target = sys.argv[1].strip()
raw_region = sys.argv[2].strip() if len(sys.argv) > 2 else ''
ports = sys.argv[3].strip() if len(sys.argv) > 3 else '443 8443 2053 2083 2096'
rate = sys.argv[4].strip() if len(sys.argv) > 4 else '10000'

asn_clean = target.upper().replace('AS', '')
cidrs = []

aliases = {
    'hk': ['hk', 'hongkong', '香港'],
    'tw': ['tw', 'taiwan', '台湾'],
    'jp': ['jp', 'japan', '日本'],
    'sg': ['sg', 'singapore', '新加坡'],
    'us': ['us', 'usa', '美国'],
    'uk': ['uk', 'united kingdom', '英国'],
    'kr': ['kr', 'korea', '韩国'],
    'de': ['de', 'germany', '德国'],
    'fr': ['fr', 'france', '法国'],
    'in': ['in', 'india', '印度'],
    'th': ['th', 'thailand', '泰国'],
    'vn': ['vn', 'vietnam', '越南'],
    'my': ['my', 'malaysia', '马来西亚'],
    'ph': ['ph', 'philippines', '菲律宾'],
    'id': ['id', 'indonesia', '印尼', '印度尼西亚']
}

asia_keywords = ['hk', 'tw', 'jp', 'sg', 'kr', 'in', 'th', 'vn', 'my', 'ph', 'id', '香港', '台湾', '日本', '新加坡', '韩国', '亚洲', '印度', '泰国', '越南', '马来西亚', '菲律宾', '印尼']

target_keywords = set()
if raw_region:
    tokens = re.split(r'[\s,;|]+', raw_region)
    for t in tokens:
        if not t:
            continue
        t_lower = t.lower()
        if t_lower in ['亚洲', 'asia']:
            target_keywords.update(asia_keywords)
        elif t_lower in aliases:
            target_keywords.update(aliases[t_lower])
        else:
            target_keywords.add(t_lower)

local_paths = [
    f'优选asn段/{asn_clean}.txt',
    f'优选asn段/AS{asn_clean}.txt'
]
found_local = False
for p in local_paths:
    if os.path.isfile(p):
        found_local = True
        print(f'[*] 发现本地文件 {p}，开始筛选关键词 {list(target_keywords) or "[全部]"} 的 IP 段...')
        
        current_section = ''
        with open(p, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line_str = line.strip()
                if not line_str:
                    continue
                
                found_cidrs = re.findall(r'(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?', line_str)
                if found_cidrs:
                    if target_keywords:
                        sec_lower = current_section.lower()
                        if any(k in sec_lower for k in target_keywords):
                            cidrs.extend(found_cidrs)
                    else:
                        cidrs.extend(found_cidrs)
                else:
                    current_section = line_str
        break

if not found_local and asn_clean.isdigit():
    print(f'[*] 本地无该 ASN 文件，发起 API 提取全局 AS{asn_clean}...')
    try:
        url = f'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_clean}'
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            for p in data.get('data', {}).get('prefixes', []):
                prefix = p.get('prefix')
                if prefix and ':' not in prefix:
                    cidrs.append(prefix)
    except Exception as e:
        print(f'获取 ASN 失败: {e}')
elif not found_local:
    cidrs.append(target)

unique_cidrs = list(set(cidrs))
with open('targets.txt', 'w') as f:
    for c in unique_cidrs:
        f.write(c + '\n')
print(f'[+] 过滤完成！成功向 targets.txt 写入 {len(unique_cidrs)} 个精准 CIDR 段')

if not os.path.exists('targets.txt') or os.path.getsize('targets.txt') == 0:
    print("[-] 未匹配到符合条件的 IP 段，退出扫描！")
    sys.exit(1)

ports_fmt = ports.replace(' ', ',')
print(f'[*] 正在运行 Masscan 探活 (速率: {rate} pps)...')

cmd = ['sudo', 'masscan', '-iL', 'targets.txt', '-p', ports_fmt, '--rate', rate, '--wait', '0', '-oJ', 'masscan_out.json']
process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

last_milestone = 0
pattern = re.compile(r'([\d\.]+)%\s+done.*found=(\d+)')

for line in process.stdout:
    match = pattern.search(line)
    if match:
        pct = float(match.group(1))
        found = match.group(2)
        milestone = int(pct // 10) * 10
        if milestone > last_milestone and milestone <= 100:
            print(f'  [Masscan 探活进度] {milestone}% | 已发现开放端口: {found} 个', flush=True)
            last_milestone = milestone

process.wait()
print('[+] Masscan 探活完成！')
