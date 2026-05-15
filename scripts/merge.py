import requests
import re
import os
import json
import ipaddress 

def parse_core_payload(entry, payload_type):
    """
    深度清理规则，剥离 Clash/v2ray/Mihomo 的各类前缀和后缀，提取最核心的 IP 或 Domain
    """
    # 1. 清理基础符号
    entry = entry.strip().strip("'").strip('"')
    if not entry or entry.startswith('#') or entry.lower() == 'payload:':
        return None

    # 2. 处理包含逗号的 Classical 格式 (如 DOMAIN-SUFFIX,google.com,no-resolve)
    parts = entry.split(',')
    if len(parts) > 1 and parts[0].upper() in ['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR', 'IP-CIDR6', 'IP-ASN']:
        core_value = parts[1].strip()
    else:
        core_value = parts[0].strip()
        # 处理可能的 V2Ray 或特定带冒号的前缀 (如 full:google.com)
        core_value = re.sub(r'^(DOMAIN(-SUFFIX|-KEYWORD)?|IP-CIDR6?|CIDR6?|FULL|DOMAIN):', '', core_value, flags=re.IGNORECASE)

    # 3. 严格格式校验与返回
    if payload_type == "ipcidr":
        try:
            # strict=False 允许处理主机位不为 0 的网段，并自动转换为标准 CIDR
            net = ipaddress.ip_network(core_value, strict=False)
            return str(net) # 返回纯净、标准化的 IP/CIDR (去除了 ,no-resolve)
        except ValueError:
            return None
    else:
        return core_value if core_value else None

def process_content(content, payload_type):
    merged = set()
    # 捕获可能的 yaml 列表项或直接纯文本行
    entries = re.findall(r"^\s*(?:-\s+)?(['\"]?)([^'\"\s#]+)\1", content, re.MULTILINE)
    
    for _, e in entries:
        cleaned_payload = parse_core_payload(e, payload_type)
        if cleaned_payload:
            merged.add(cleaned_payload)
            
    return merged

def save_source(name, entries, ptype):
    if not entries: return
    
    os.makedirs("source/mihomo", exist_ok=True)
    os.makedirs("source/sing-box", exist_ok=True)
    
    entry_list = sorted(list(entries))

    # --- 1. 生成 Mihomo 源文件 (.list) ---
    with open(f"source/mihomo/{name}.list", "w", encoding='utf-8') as f:
        for entry in entry_list:
            f.write(f"{entry}\n")
    with open(f"source/mihomo/{name}.type", "w", encoding='utf-8') as f:
        f.write(ptype)

    # --- 2. 生成 Sing-box 源文件 (.json) ---
    sbox_rule = {}
    if ptype == "ipcidr":
        sbox_rule["ip_cidr"] = entry_list
    else:
        sbox_rule["domain_suffix"] = entry_list

    # Sing-box Headless Rule 标准格式 (版本 2 支持 rule-set 编译)
    sbox_json = {
        "version": 2,
        "rules": [sbox_rule]
    }

    with open(f"source/sing-box/{name}.json", "w", encoding='utf-8') as f:
        json.dump(sbox_json, f, indent=2, ensure_ascii=False)

def main():
    if not os.path.exists('config.json'): return
    with open('config.json', 'r', encoding='utf-8') as f:
        config = json.load(f)

    print("Processing config.json categories...")
    for cat, settings in config.get('categories', {}).items():
        is_ip = any(x in cat.lower() for x in ['cidr', 'lan', 'ip']) and 'fakeip' not in cat.lower()
        payload_type = "ipcidr" if is_ip else "domain"
        merged_entries = set()
        
        for url in settings.get('remote_urls', []):
            try:
                # 增加请求重试或简单的错误日志有助于排查网络阻塞
                resp = requests.get(url, timeout=10)
                resp.raise_for_status() # 非 200 状态码直接抛出异常被 catch 拦截
                merged_entries.update(process_content(resp.text, payload_type))
            except Exception as e:
                print(f"Warning: Failed to fetch {url} - {e}")
        
        if settings.get('merge_local', False):
            local_path = os.path.join("custom", f"{cat}.txt")
            if os.path.exists(local_path):
                with open(local_path, "r", encoding='utf-8') as f:
                    merged_entries.update(process_content(f.read(), payload_type))
                    
        save_source(cat, merged_entries, payload_type)

    print("Processing all local files in 'custom' folder independently...")
    if os.path.exists("custom"):
        for file in os.listdir("custom"):
            if file.endswith(".txt"):
                base_name = file.replace(".txt", "")
                is_ip = any(x in base_name.lower() for x in ['cidr', 'lan', 'ip']) and 'fakeip' not in base_name.lower()
                payload_type = "ipcidr" if is_ip else "domain"
                
                target_name = f"custom_{base_name}"
                with open(os.path.join("custom", file), "r", encoding='utf-8') as f:
                    local_entries = process_content(f.read(), payload_type)
                
                save_source(target_name, local_entries, payload_type)

if __name__ == "__main__":
    main()
