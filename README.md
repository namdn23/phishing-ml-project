import pandas as pd
import numpy as np
import os
import time
import math
import io
import socket
import re
import tldextract
import ssl
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from playwright.sync_api import sync_playwright
import imagehash
from PIL import Image
from bs4 import BeautifulSoup
from collections import Counter

# =================================================================
# I. CẤU HÌNH & DANH SÁCH FEATURES
# =================================================================
RAW_CSV_FILE = 'PhiUSIIL_Phishing_URL_Dataset.csv'
TEMP_LOG_FILE = 'extraction_checkpoint.csv'
FINAL_OUTPUT = 'PhiUSIIL_Extracted_Full.csv'

# TỐI ƯU CHO MÁY ẢO 8 NHÂN VT-x
MAX_WORKERS = 20  # Tăng lên 20 luồng để tận dụng CPU Intel Ultra 5H
CHUNK_SIZE = 10   # Mỗi luồng xử lý 10 URL rồi reset trình duyệt để giải phóng RAM
TARGET_PHASH = imagehash.hex_to_hash('9880e61f1c7e0c4f')

# Các cột lấy từ file cũ
OLD_KEEP_COLS = [
    'URL', 'NoOfDegitsInURL', 'HasDescription', 'HasSocialNet', 'HasPasswordField', 
    'HasSubmitButton', 'HasExternalFormSubmit', 'DomainTitleMatchScore', 
    'IsHTTPS', 'HasCopyrightInfo', 'label'
]

# =================================================================
# II. HÀM HỖ TRỢ TÍNH TOÁN
# =================================================================
def get_entropy(text):
    if not text or len(text) == 0: return 0.0
    probs = [count/len(text) for count in Counter(text).values()]
    return -sum(p * math.log2(p) for p in probs) / 8.0

def get_tls_issuer(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                return issuer.get('organizationName', 'Unknown')
    except: return 'None'

# =================================================================
# III. LOGIC TRÍCH XUẤT TỔNG HỢP
# =================================================================
def extract_full_features(page, url):
    res = {k: 0.0 for k in [
        'V10_HTTP_Extraction_Success', 'V11_WHOIS_Extraction_Success', 'V1_PHash_Distance', 
        'V2_Layout_Similarity', 'V6_JS_Entropy', 'V7_Text_Readability_Score', 
        'V8_Total_IFrames', 'V9_Has_Hidden_IFrame', 'V5_TLS_Issuer_Reputation', 
        'V3_Domain_Age_Days', 'V4_DNS_Volatility_Count', 'Is_Top_1M_Domain', 
        'V22_IP_Subdomain_Pattern', 'V23_Entropy_Subdomain'
    ]}
    
    try:
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        
        # 1. TRÍCH XUẤT TĨNH
        res['V22_IP_Subdomain_Pattern'] = 1 if re.search(r'\d+\.\d+', ext.subdomain) else 0
        res['V23_Entropy_Subdomain'] = get_entropy(ext.subdomain)
        res['Is_Top_1M_Domain'] = 1 if ext.domain in ['google', 'facebook', 'microsoft', 'apple', 'amazon'] else 0
        try:
            res['V4_DNS_Volatility_Count'] = len(socket.gethostbyname_ex(domain)[2])
        except: res['V4_DNS_Volatility_Count'] = 0
        
        issuer = get_tls_issuer(domain)
        res['V5_TLS_Issuer_Reputation'] = 1.0 if issuer != 'None' else 0.0

        # 2. TRÍCH XUẤT ĐỘNG (PLAYWRIGHT)
        page.goto(url, timeout=25000, wait_until="domcontentloaded") # Tăng tốc bằng cách đợi DOM xong thay vì load toàn bộ
        res['V10_HTTP_Extraction_Success'] = 1
        
        # V1: PHash Distance (Screenshot)
        img_bytes = page.screenshot()
        img = Image.open(io.BytesIO(img_bytes)).convert('L')
        res['V1_PHash_Distance'] = (imagehash.phash(img) - TARGET_PHASH) / 64.0
        
        # V2: Layout Similarity
        soup = BeautifulSoup(page.content(), 'html.parser')
        depths = [len(list(t.parents)) for t in soup.find_all(True)]
        res['V2_Layout_Similarity'] = np.clip(1.0 - (max(depths or [0])/40.0), 0, 1)
        
        # V6: JS Entropy
        js_code = "".join([s.text for s in soup.find_all('script')])
        res['V6_JS_Entropy'] = get_entropy(js_code)
        
        # V7: Text Readability
        full_text = soup.get_text()
        words = full_text.split()
        sentences = re.split(r'[.!?]+', full_text)
        res['V7_Text_Readability_Score'] = np.clip(len(words)/(len(sentences) or 1) / 20.0, 0, 1)
        
        # V8, V9: IFrames
        iframes = soup.find_all('iframe')
        res['V8_Total_IFrames'] = len(iframes)
        res['V9_Has_Hidden_IFrame'] = 1 if any('none' in str(f.get('style','')).lower() for f in iframes) else 0
        
        res['V11_WHOIS_Extraction_Success'] = 1
        
    except Exception:
        res['V10_HTTP_Extraction_Success'] = 0
        res['V1_PHash_Distance'] = 0.5 
        
    return res

# =================================================================
# IV. QUẢN LÝ ĐA LUỒNG
# =================================================================
def thread_worker(chunk_df):
    results = []
    with sync_playwright() as p:
        # Tối ưu Chrome: Tắt sandbox, tắt GPU, bỏ qua rác để tăng tốc trên VM
        browser = p.chromium.launch(headless=True, args=[
            "--no-sandbox", 
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--js-flags='--max-old-space-size=512'"
        ])
        context = browser.new_context(viewport={'width': 1280, 'height': 720})
        page = context.new_page()
        
        for _, row in chunk_df.iterrows():
            data = extract_full_features(page, row['URL'])
            data['URL_KEY'] = row['URL']
            results.append(data)
            
        browser.close()
    return results

def main():
    start_session_time = time.time()
    
    # 1. Đọc dữ liệu gốc
    if not os.path.exists(RAW_CSV_FILE):
        print(f"❌ Lỗi: Không tìm thấy {RAW_CSV_FILE}"); return
    df_raw = pd.read_csv(RAW_CSV_FILE, usecols=OLD_KEEP_COLS)
    total_all = len(df_raw)

    # 2. Xử lý Checkpoint (Đọc các URL đã làm xong)
    if os.path.exists(TEMP_LOG_FILE):
        df_checkpoint = pd.read_csv(TEMP_LOG_FILE, usecols=['URL_KEY'])
        processed_urls = set(df_checkpoint['URL_KEY'].astype(str))
    else:
        processed_urls = set()
    
    # Lọc danh sách còn lại
    df_todo = df_raw[~df_raw['URL'].astype(str).isin(processed_urls)]
    num_already_done = len(processed_urls)
    total_todo = len(df_todo)
    
    if total_todo == 0:
        print("✅ Đã hoàn thành xử lý toàn bộ dữ liệu."); return

    print(f"🚀 Tổng cộng: {total_all} URL")
    print(f"📦 Đã xong: {num_already_done} | Còn lại: {total_todo}")
    print(f"🔥 Đang khởi chạy {MAX_WORKERS} luồng...")

    # 3. Chạy đa luồng
    chunks = [df_todo[i:i + CHUNK_SIZE] for i in range(0, total_todo, CHUNK_SIZE)]
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(thread_worker, c): c for c in chunks}
        
        for i, future in enumerate(as_completed(futures), 1):
            batch_data = future.result()
            
            # Lưu ngay xuống file checkpoint
            pd.DataFrame(batch_data).to_csv(TEMP_LOG_FILE, mode='a', index=False, header=not os.path.exists(TEMP_LOG_FILE))
            
            # Tính toán tiến độ cộng dồn
            current_batch_done = i * CHUNK_SIZE
            total_current_done = num_already_done + current_batch_done
            
            # Tính tốc độ trên phiên hiện tại
            elapsed_session = time.time() - start_session_time
            speed = current_batch_done / elapsed_session
            
            # Tránh hiển thị vượt quá 100% do sai số chunk cuối
            display_done = min(total_current_done, total_all)
            
            print(f"➜ Tiến độ: {display_done}/{total_all} ({display_done/total_all*100:.2f}%) "
                  f"| Tốc độ: {speed:.2f} URL/s | ETA: {(total_all - display_done)/speed/60:.1f} phút")

    # 4. Hợp nhất cuối cùng
    print("\n🔄 Đang tạo file kết quả cuối cùng...")
    df_new = pd.read_csv(TEMP_LOG_FILE).drop_duplicates('URL_KEY')
    df_final = pd.merge(df_raw, df_new, left_on='URL', right_on='URL_KEY', how='inner')
    
    # Tạo biến Alarms
    for col in ['V1_PHash_Distance', 'V2_Layout_Similarity', 'V6_JS_Entropy', 'V7_Text_Readability_Score']:
        df_final[f'Alarm_{col}_Missing'] = np.where(df_final['V10_HTTP_Extraction_Success'] == 0, 1, 0)

    df_final.drop(columns=['URL_KEY'], inplace=True)
    df_final.to_csv(FINAL_OUTPUT, index=False)
    
    print(f"✅ HOÀN TẤT! File: {FINAL_OUTPUT}")

if __name__ == "__main__":
    main()
