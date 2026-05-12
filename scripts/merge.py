import requests
import re
import os
import json

def clean_entry(entry):
    # 移除指令前缀并清理引号
    entry = re.sub(r'^(CIDR6|CIDR|IP-CIDR|IP-CIDR6):', '', entry, flags=re.IGNORECASE)
    return entry.strip().strip("'").strip('"')

def is_valid_ip_or_cidr(entry):
    # 判断是否为合法的 IP 或 CIDR 格式
    return any(char.isdigit() for char in entry) and ('.' in entry or ':' in entry)

def process_content(content, payload_type):
    merged = set()
    
    # ^\s* : 匹配行首可能存在的缩进空格
    # (?:-\s+)?   : 匹配可能存在的 yaml 列表符 "- "（非捕获且设为可选）
    # (['\"]?)    : 捕获可能存在的单双引号 (Group 1)
    # ([^'\"\s#]+): 捕获实际的域名或 IP 内容 (Group 2)，遇到引号、空格、#号则停止
    # \1          : 匹配闭合的引号
    entries = re.findall(r"^\s*(?:-\s+)?(['\"]?)([^'\"\s#]+)\1", content, re.MULTILINE)
    
    for _, e in entries:
        cleaned = clean_entry(e)
        
        # 过滤掉空的、带注释的以及 YAML 的 payload 关键字
        if not cleaned or cleaned.startswith('#') or cleaned.lower() == 'payload:': 
            continue
            
        if payload_type == "ipcidr":
            if is_valid_ip_or_cidr(cleaned):
                merged.add(cleaned)
        else:
            merged.add(cleaned)
            
    return merged

def save_source(name, entries, ptype):
    if not entries: return
    
    # 创建 Mihomo 和 Sing-box 的源文件临时目录
    os.makedirs("source/mihomo", exist_ok=True)
    os.makedirs("source/sing-box", exist_ok=True)
    
    # 转换为列表并排序，保证每次生成的顺序一致
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
        # 将域名统一放入 domain_suffix，兼容通配行为
        sbox_rule["domain_suffix"] = entry_list

    # 构建 Sing-box Headless Rule 标准格式 (版本 2)
    sbox_json = {
        "version": 2,
        "rules": [sbox_rule]
    }

    with open(f"source/sing-box/{name}.json", "w", encoding='utf-8') as f:
        json.dump(sbox_json, f, indent=2, ensure_ascii=False)

def fetch_fakeip_filter():
    """新增模块：直接从上游获取 fakeip-filter.list 并注入 Mihomo 源文件夹"""
    print("Fetching upstream fakeip-filter.list...")
    try:
        url = "https://raw.githubusercontent.com/wwqgtxx/clash-rules/release/fakeip-filter.list"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            os.makedirs("source/mihomo", exist_ok=True)
            # 写入 Mihomo 源码目录，依靠原有的 Action 循环自动完成 mrs 编译
            with open("source/mihomo/fakeip-filter.list", "w", encoding='utf-8') as f:
                f.write(resp.text)
            with open("source/mihomo/fakeip-filter.type", "w", encoding='utf-8') as f:
                f.write("domain")
            print("Successfully added fakeip-filter to Mihomo source.")
    except Exception as e:
        print(f"Failed to fetch fakeip-filter: {e}")

def main():
    # 优先执行独立抓取任务
    fetch_fakeip_filter()
    
    if not os.path.exists('config.json'): return
    with open('config.json', 'r', encoding='utf-8') as f:
        config = json.load(f)

    # 处理 config.json
    print("Processing config.json categories...")
    for cat, settings in config.get('categories', {}).items():
        is_ip = any(x in cat.lower() for x in ['cidr', 'lan', 'ip'])
        payload_type = "ipcidr" if is_ip else "domain"
        merged_entries = set()
        
        for url in settings.get('remote_urls', []):
            try:
                resp = requests.get(url, timeout=10)
                if resp.status_code == 200:
                    merged_entries.update(process_content(resp.text, payload_type))
            except: pass
        
        if settings.get('merge_local', False):
            local_path = os.path.join("custom", f"{cat}.txt")
            if os.path.exists(local_path):
                with open(local_path, "r", encoding='utf-8') as f:
                    merged_entries.update(process_content(f.read(), payload_type))
        save_source(cat, merged_entries, payload_type)

    # 处理 custom 独立文件
    print("Processing all local files in 'custom' folder independently...")
    if os.path.exists("custom"):
        for file in os.listdir("custom"):
            if file.endswith(".txt"):
                base_name = file.replace(".txt", "")
                is_ip = any(x in base_name.lower() for x in ['cidr', 'lan', 'ip'])
                payload_type = "ipcidr" if is_ip else "domain"
                
                target_name = f"custom_{base_name}"
                
                with open(os.path.join("custom", file), "r", encoding='utf-8') as f:
                    local_entries = process_content(f.read(), payload_type)
                
                save_source(target_name, local_entries, payload_type)

if __name__ == "__main__":
    main()
