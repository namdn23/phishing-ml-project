import pandas as pd
import tldextract
import time
import json
import os
import random
import threading
import concurrent.futures
from bs4 import BeautifulSoup
import undetected_chromedriver as uc
from tqdm import tqdm

# ==================== CẤU HÌNH SIÊU CẤP ====================
INPUT_FILE = 'DATA_TRAIN_FINAL.csv'
OUTPUT_FILE = 'DATA_TRAIN_ULTIMATE.csv'
CHECKPOINT_FILE = 'checkpoint_ultimate.json'

# 🔥 CẤU HÌNH CHO MÁY MẠNH (INTEL ULTRA 5H + 27GB RAM)
MAX_WORKERS = 10  # Chạy 10 trình duyệt cùng lúc

# Danh sách Brand lớn (Sẽ được điền bù dữ liệu chuẩn, KHÔNG CRAWL để tránh bị chặn)
DOMAIN_PROFILES = {
    'google':    {'Total_IFrames': 3, 'Has_Hidden_IFrame': 0, 'Is_Trusted_Issuer': 1, 'Certificate_Age': 365, 'Has_External_Form': 0, 'Has_Obfuscated_JS': 0},
    'facebook':  {'Total_IFrames': 2, 'Has_Hidden_IFrame': 0, 'Is_Trusted_Issuer': 1, 'Certificate_Age': 365, 'Has_External_Form': 0, 'Has_Obfuscated_JS': 0},
    'shopee':    {'Total_IFrames': 5, 'Has_Hidden_IFrame': 0, 'Is_Trusted_Issuer': 1, 'Certificate_Age': 300, 'Has_External_Form': 0, 'Has_Obfuscated_JS': 0},
    'amazon':    {'Total_IFrames': 2, 'Has_Hidden_IFrame': 0, 'Is_Trusted_Issuer': 1, 'Certificate_Age': 365, 'Has_External_Form': 0, 'Has_Obfuscated_JS': 0},
    'microsoft': {'Total_IFrames': 1, 'Has_Hidden_IFrame': 0, 'Is_Trusted_Issuer': 1, 'Certificate_Age': 365, 'Has_External_Form': 0, 'Has_Obfuscated_JS': 0},
    'paypal':    {'Total_IFrames': 1, 'Has_Hidden_IFrame': 0, 'Is_Trusted_Issuer': 1, 'Certificate_Age': 365, 'Has_External_Form': 0, 'Has_Obfuscated_JS': 0},
    'apple':     {'Total_IFrames': 1, 'Has_Hidden_IFrame': 0, 'Is_Trusted_Issuer': 1, 'Certificate_Age': 365, 'Has_External_Form': 0, 'Has_Obfuscated_JS': 0},
    'netflix':   {'Total_IFrames': 1, 'Has_Hidden_IFrame': 0, 'Is_Trusted_Issuer': 1, 'Certificate_Age': 365, 'Has_External_Form': 0, 'Has_Obfuscated_JS': 0},
    'instagram': {'Total_IFrames': 1, 'Has_Hidden_IFrame': 0, 'Is_Trusted_Issuer': 1, 'Certificate_Age': 365, 'Has_External_Form': 0, 'Has_Obfuscated_JS': 0},
}

PROTECTED_BRANDS = list(DOMAIN_PROFILES.keys()) + ['tiki', 'lazada', 'vietcombank', 'techcombank']

# Khóa an toàn cho luồng
file_lock = threading.Lock()

# ==================== LOGIC XỬ LÝ ====================

def get_domain_parts(url):
    try:
        ext = tldextract.extract(str(url))
        root = f"{ext.domain}.{ext.suffix}"
        return ext.domain, ext.suffix, ext.subdomain, root
    except: return "", "", "", ""

def fix_static_features(row):
    """Bước 1: Sửa logic tĩnh (Chạy siêu nhanh)"""
    url = str(row['url'])
    domain, suffix, subdomain, root = get_domain_parts(url)
    
    # 1. Sửa lỗi Brand In Subdomain
    # Logic: Brand ở sub nhưng Root cũng là Brand -> AN TOÀN (0)
    has_brand_issue = 0
    for b in PROTECTED_BRANDS:
        if b in subdomain:
            if b == domain: has_brand_issue = 0 # Chính chủ
            else: has_brand_issue = 1           # Giả mạo
    row['Brand_In_Subdomain'] = has_brand_issue
    
    # 2. Cập nhật TLD rác
    SUSPICIOUS_TLDS = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'vip', 'work']
    row['Suspicious_TLD'] = 1 if suffix in SUSPICIOUS_TLDS else 0
    
    return row, domain # Trả về domain body để check tiếp

def process_chunk_worker(df_chunk, worker_id):
    """Hàm xử lý cho từng luồng"""
    results = []
    
    # Khởi tạo trình duyệt (Chỉ mở nếu cần crawl)
    driver = None
    
    # Lọc ra những URL cần crawl (Không nằm trong Profile và bị thiếu dữ liệu)
    urls_to_crawl = []
    for idx, row in df_chunk.iterrows():
        domain, _, _, _ = get_domain_parts(row['url'])
        # Nếu không phải ông lớn VÀ dữ liệu bị thiếu -> Cần crawl
        if domain not in DOMAIN_PROFILES and (row['Total_IFrames'] == 0 and row['Has_External_Form'] == 0):
            urls_to_crawl.append(idx)

    # Nếu có URL cần crawl thì mới mở Chrome
    if len(urls_to_crawl) > 0:
        try:
            options = uc.ChromeOptions()
            options.add_argument("--headless=new")
            options.add_argument("--no-sandbox")
            options.add_argument("--mute-audio")
            driver = uc.Chrome(options=options)
            driver.set_page_load_timeout(15)
            # print(f"[Worker {worker_id}] 🟢 Đã mở Chrome ({len(urls_to_crawl)} tasks)")
        except: pass

    # --- VÒNG LẶP XỬ LÝ TỪNG DÒNG ---
    for idx, row in df_chunk.iterrows():
        # 1. Sửa lỗi Tĩnh
        row, domain_body = fix_static_features(row)
        
        # 2. Xử lý Dữ liệu Động
        
        # TRƯỜNG HỢP A: LÀ ÔNG LỚN (Google, FB...) -> Dùng dữ liệu chuẩn (IMPUTATION)
        if domain_body in DOMAIN_PROFILES:
            profile = DOMAIN_PROFILES[domain_body]
            
            # Nếu dữ liệu cũ bị lỗi (0 hoặc âm), điền dữ liệu chuẩn vào
            if row['Total_IFrames'] <= 0: row['Total_IFrames'] = profile['Total_IFrames']
            if row['Is_Trusted_Issuer'] <= 0: 
                row['Is_Trusted_Issuer'] = profile['Is_Trusted_Issuer']
                row['Certificate_Age'] = profile['Certificate_Age']
                row['Certificate_Validity_Days'] = 365
            
            # Reset các cờ phạt oan
            row['Has_Hidden_IFrame'] = 0  
            row['Has_External_Form'] = 0
            row['Has_Obfuscated_JS'] = 0
            row['Brand_Impersonation'] = 0

        # TRƯỜNG HỢP B: LÀ WEB LẠ VÀ THIẾU DỮ LIỆU -> CRAWL THẬT
        elif idx in urls_to_crawl and driver:
            try:
                url = row['url']
                driver.get(url)
                time.sleep(random.uniform(2, 3))
                
                soup = BeautifulSoup(driver.page_source.lower(), 'html.parser')
                current_root = get_domain_parts(url)[3]
                
                # Trích xuất External Form
                has_ext_form = 0
                for f in soup.find_all('form'):
                    act = f.get('action', '').lower()
                    if act.startswith('http'):
                        act_root = get_domain_parts(act)[3]
                        if act_root and act_root != current_root: has_ext_form = 1; break
                row['Has_External_Form'] = has_ext_form

                # Trích xuất Iframe
                iframes = soup.find_all('iframe')
                row['Total_IFrames'] = len(iframes)
                
                # Check Hidden Iframe
                has_bad_iframe = 0
                for i in iframes:
                    src = i.get('src', '').lower()
                    style = str(i.get('style', '')).lower()
                    if ('display:none' in style or 'visibility:hidden' in style) and src.startswith('http'):
                        src_root = get_domain_parts(src)[3]
                        if src_root and src_root != current_root and 'google' not in src_root:
                            has_bad_iframe = 1
                row['Has_Hidden_IFrame'] = has_bad_iframe
                
                # Check JS
                row['Has_Obfuscated_JS'] = 1 if 'eval(' in str(soup) else 0

            except: pass # Nếu crawl lỗi thì giữ nguyên số 0 cũ

        # TRƯỜNG HỢP C: WEB LẠ NHƯNG ĐÃ CÓ DỮ LIỆU -> GIỮ NGUYÊN (Không tốn time crawl lại)
        else:
            pass 

        results.append((idx, row))

    if driver: 
        try: driver.quit()
        except: pass
        
    return results

# ==================== MAIN ====================
def main():
    print(f"🚀 DATASET REPAIR KIT ULTIMATE (10 WORKERS)")
    print(f"🎯 Chiến thuật: Imputation (Google/FB) + Crawling (Web lạ)")
    
    # 1. Load Data
    try: full_df = pd.read_csv(INPUT_FILE)
    except: print("❌ Không thấy file input"); return

    # 2. Load Checkpoint
    processed_indices = set()
    if os.path.exists(CHECKPOINT_FILE):
        with open(CHECKPOINT_FILE, 'r') as f:
            processed_indices = set(json.load(f))
    
    # Lọc dòng chưa xử lý
    full_df['temp_idx'] = full_df.index
    remaining_df = full_df[~full_df.index.isin(processed_indices)]
    
    print(f"📊 Tổng: {len(full_df)} | Đã xong: {len(processed_indices)} | Còn lại: {len(remaining_df)}")
    if len(remaining_df) == 0: return

    # 3. Chia Chunk (Mỗi worker làm 50 dòng rồi nghỉ để giải phóng RAM)
    CHUNK_SIZE = 50 
    chunks = [remaining_df[i:i + CHUNK_SIZE] for i in range(0, len(remaining_df), CHUNK_SIZE)]
    
    print(f"📦 Bắt đầu xử lý {len(chunks)} gói...")
    pbar = tqdm(total=len(remaining_df))
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_chunk_worker, chunk, i % MAX_WORKERS): chunk for i, chunk in enumerate(chunks)}
        
        for future in concurrent.futures.as_completed(futures):
            try:
                results = future.result()
                if not results: continue

                with file_lock:
                    for idx, row in results:
                        full_df.loc[idx] = row
                        processed_indices.add(int(idx))
                    
                    # Lưu checkpoint
                    full_df.drop(columns=['temp_idx'], errors='ignore').to_csv(OUTPUT_FILE, index=False)
                    with open(CHECKPOINT_FILE, 'w') as f:
                        json.dump(list(processed_indices), f)
                
                pbar.update(len(results))
            except Exception as e:
                print(f"❌ Lỗi: {e}")

    pbar.close()
    if 'temp_idx' in full_df.columns: full_df.drop(columns=['temp_idx'], inplace=True)
    
    print("\n✅ HOÀN TẤT! File 'DATA_TRAIN_ULTIMATE.csv' đã sẵn sàng để Train.")

if __name__ == "__main__":
    main()
