import os
import sys
import json

# 参数解析
MASSCAN_JSON_FILE = sys.argv[3] if len(sys.argv) > 3 else "masscan_out.json"

def load_and_print_masscan_targets(json_file):
    """读取 Masscan 生成的 JSON 结果，提取并直接输出 IP:Port"""
    if not os.path.exists(json_file):
        print(f"[-] 找不到 Masscan 文件: {json_file}", file=sys.stderr)
        return
        
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                return
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
                        print(f"{ip}:{port}")
    except Exception as e:
        print(f"[-] 解析 Masscan 文件失败: {e}", file=sys.stderr)

if __name__ == "__main__":
    load_and_print_masscan_targets(MASSCAN_JSON_FILE)
