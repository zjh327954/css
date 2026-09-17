import sys
import json
import urllib.request
import ipaddress
import re

if len(sys.argv) < 2:
    print("[-] 请提供扫描目标 (ASN 或 CIDR)")
    sys.exit(1)

target_raw = sys.argv[1].strip()
cidrs = []
asn_info = target_raw

if target_raw.upper().startswith("AS"):
    asn = target_raw.upper().replace("AS", "").strip()
    asn_info = f"AS{asn}"
    try:
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            for p in data.get("data", {}).get("prefixes", []):
                prefix = p.get("prefix")
                if prefix and ":" not in prefix:
                    cidrs.append(prefix)
    except Exception as e:
        print(f"[-] 获取 ASN {asn} 网段失败: {e}")
else:
    cidrs.append(target_raw)

total_ips = 0
valid_cidrs = []
for c in cidrs:
    try:
        net = ipaddress.ip_network(c, strict=False)
        total_ips += net.num_addresses
        valid_cidrs.append(str(net))
    except Exception:
        pass

with open(".tmp/targets.txt", "w", encoding="utf-8") as f:
    for c in valid_cidrs:
        f.write(c + "\n")

with open(".tmp/scan_info.json", "w", encoding="utf-8") as f:
    json.dump({"total_ips": total_ips, "asn": asn_info}, f)

print(f"[+] 目标解析完成: {asn_info} | 包含有效 IP: {total_ips} 个")
