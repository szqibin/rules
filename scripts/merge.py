import requests
import re
import os
import json

def clean_entry(entry):
    # 移除前缀并清理不可见字符
    entry = re.sub(r'^(CIDR6|CIDR|IP-CIDR|IP-CIDR6):', '', entry, flags=re.IGNORECASE)
    return entry.strip().strip("'").strip('"')

def is_valid_ip_or_cidr(entry):
    return any(char.isdigit() for char in entry) and ('.' in entry or ':' in entry)

def process_content(content, payload_type):
    merged = set()
    # 提取域名或IP，支持多种格式（兼容带 - 的 YAML 或 纯文本行）
    entries = re.findall(r"(?:^-\s*|payload:\s*-\s*|^\s*)(['\"]?)([^'\"\s#]+)\1", content, re.MULTILINE)
    for _, e in entries:
        cleaned = clean_entry(e)
        if not cleaned or cleaned.startswith('#'): continue
        if payload_type == "ipcidr":
            if is_valid_ip_or_cidr(cleaned):
                merged.add(cleaned)
        else:
            # 自动去掉可能导致匹配失败的 +. 前缀
            cleaned = cleaned.lstrip('+.')
            merged.add(cleaned)
    return merged

def save_source(name, entries, ptype):
    if not entries: return
    os.makedirs("source", exist_ok=True)
    # 统一保存为 .list 纯文本供编译使用
    with open(f"source/{name}.list", "w", encoding='utf-8') as f:
        for entry in sorted(list(entries)):
            f.write(f"{entry}\n")
    # 保存类型供 Action 读取
    with open(f"source/{name}.type", "w", encoding='utf-8') as f:
        f.write(ptype)

def main():
    if not os.path.exists('config.json'):
        print("config.json not found!")
        return
    with open('config.json', 'r', encoding='utf-8') as f:
        config = json.load(f)

    # 1. 处理 config.json 定义的分类
    for cat, settings in config.get('categories', {}).items():
        is_ip = any(x in cat.lower() for x in ['cidr', 'lan', 'ip'])
        payload_type = "ipcidr" if is_ip else "domain"
        merged_entries = set()
        
        # 远程获取
        for url in settings.get('remote_urls', []):
            try:
                resp = requests.get(url, timeout=10)
                if resp.status_code == 200:
                    merged_entries.update(process_content(resp.text, payload_type))
            except: pass
        
        # 本地合并 (支持从 custom/{cat}.txt 读取)
        if settings.get('merge_local', False):
            local_path = os.path.join("custom", f"{cat}.txt") # 已修改为 .txt
            if os.path.exists(local_path):
                with open(local_path, "r", encoding='utf-8') as f:
                    merged_entries.update(process_content(f.read(), payload_type))
        
        save_source(cat, merged_entries, payload_type)

    # 2. 处理 custom 文件夹下所有其他 .txt 文件
    if os.path.exists("custom"):
        for file in os.listdir("custom"):
            if file.endswith(".txt"): # 已修改为 .txt
                base_name = file.replace(".txt", "")
                # 如果已经在第一步处理过了，则跳过
                if base_name in config.get('categories', {}): continue
                
                is_ip = any(x in base_name.lower() for x in ['cidr', 'lan', 'ip'])
                payload_type = "ipcidr" if is_ip else "domain"
                
                with open(os.path.join("custom", file), "r", encoding='utf-8') as f:
                    local_entries = process_content(f.read(), payload_type)
                
                save_source(f"custom_{base_name}", local_entries, payload_type)

if __name__ == "__main__":
    main()
