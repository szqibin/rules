import requests
import re
import os
import json

def clean_entry(entry):
    entry = re.sub(r'^(CIDR6|CIDR|IP-CIDR|IP-CIDR6):', '', entry, flags=re.IGNORECASE)
    return entry.strip().strip("'").strip('"')

def is_valid_ip_or_cidr(entry):
    has_digit = any(char.isdigit() for char in entry)
    is_ip_format = ('.' in entry or ':' in entry)
    return has_digit and is_ip_format

def process_content(content, payload_type):
    merged = set()
    # 兼容多种格式提取域名或IP
    entries = re.findall(r"(?:^-\s*|payload:\s*-\s*|^\s*)(['\"]?)([^'\"\s#]+)\1", content, re.MULTILINE)
    for _, e in entries:
        cleaned = clean_entry(e)
        if not cleaned or cleaned.startswith('#'): continue
        if payload_type == "ipcidr":
            if is_valid_ip_or_cidr(cleaned):
                merged.add(cleaned)
        else:
            # 自动处理某些库带有的 +. 前缀，统一转为纯域名以提高兼容性
            cleaned = cleaned.lstrip('+.')
            merged.add(cleaned)
    return merged

def save_source(name, entries, ptype):
    if not entries: return
    # 所有生成的原始文件放在 source 目录下
    os.makedirs("source", exist_ok=True)
    
    # 保存为纯文本格式，方便 Mihomo 编译
    with open(f"source/{name}.list", "w", encoding='utf-8') as f:
        for entry in sorted(list(entries)):
            f.write(f"{entry}\n")
    
    # 记录类型，供 build.yml 使用
    with open(f"source/{name}.type", "w", encoding='utf-8') as f:
        f.write(ptype)

def main():
    # 读取配置
    with open('config.json', 'r', encoding='utf-8') as f:
        config = json.load(f)

    # --- 流程 1：处理 config.json 中的分类 ---
    for cat, settings in config.get('categories', {}).items():
        print(f"Processing category: {cat}")
        is_ip = any(x in cat.lower() for x in ['cidr', 'lan', 'ip'])
        payload_type = "ipcidr" if is_ip else "domain"
        merged_entries = set()

        for url in settings.get('remote_urls', []):
            try:
                resp = requests.get(url, timeout=10)
                if resp.status_code == 200:
                    merged_entries.update(process_content(resp.text, payload_type))
            except Exception as e:
                print(f"  Error fetching {url}: {e}")

        if settings.get('merge_local', False):
            local_path = os.path.join("custom", f"{cat}.list")
            if os.path.exists(local_path):
                with open(local_path, "r", encoding='utf-8') as f:
                    merged_entries.update(process_content(f.read(), payload_type))
        
        save_source(cat, merged_entries, payload_type)

    # --- 流程 2：处理 custom 文件夹下所有 .list 文件 ---
    if os.path.exists("custom"):
        for file in os.listdir("custom"):
            if file.endswith(".list"):
                base_name = file.replace(".list", "")
                # 避免重复处理流程1已处理过的基础分类
                if base_name in config.get('categories', {}): continue
                
                is_ip = any(x in base_name.lower() for x in ['cidr', 'lan', 'ip'])
                payload_type = "ipcidr" if is_ip else "domain"
                target_name = f"custom_{base_name}"
                
                with open(os.path.join("custom", file), "r", encoding='utf-8') as f:
                    local_entries = process_content(f.read(), payload_type)
                
                save_source(target_name, local_entries, payload_type)

if __name__ == "__main__":
    main()
