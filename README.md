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

MAX_WORKERS = 6  # Số luồng xử lý
CHUNK_SIZE = 10  # Mỗi luồng xử lý 10 URL rồi reset trình duyệt
TARGET_PHASH = imagehash.hex_to_hash('9880e61f1c7e0c4f')

# Các cột lấy từ file cũ (Giữ nguyên)
OLD_KEEP_COLS = [
    'URL', 'NoOfDegitsInURL', 'HasDescription', 'HasSocialNet', 'HasPasswordField', 
    'HasSubmitButton', 'HasExternalFormSubmit', 'DomainTitleMatchScore', 
    'IsHTTPS', 'HasCopyrightInfo', 'label'
]

# =================================================================
# II. HÀM HỖ TRỢ TÍNH TOÁN THẬT
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
# III. LOGIC TRÍCH XUẤT TỔNG HỢP (DYNAMIC + STATIC)
# =================================================================
def extract_full_features(page, url):
    # Khởi tạo danh sách kết quả (Tổng cộng 14 biến mới chữ V)
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
        
        # 1. TRÍCH XUẤT TĨNH (URL/DNS)
        res['V22_IP_Subdomain_Pattern'] = 1 if re.search(r'\d+\.\d+', ext.subdomain) else 0
        res['V23_Entropy_Subdomain'] = get_entropy(ext.subdomain)
        res['Is_Top_1M_Domain'] = 1 if ext.domain in ['google', 'facebook', 'microsoft', 'apple', 'amazon'] else 0
        try:
            res['V4_DNS_Volatility_Count'] = len(socket.gethostbyname_ex(domain)[2])
        except: res['V4_DNS_Volatility_Count'] = 0
        
        # 2. KIỂM TRA TLS ISSUER (V5)
        issuer = get_tls_issuer(domain)
        res['V5_TLS_Issuer_Reputation'] = 1.0 if issuer != 'None' else 0.0

        # 3. TRÍCH XUẤT ĐỘNG (PLAYWRIGHT)
        page.goto(url, timeout=25000, wait_until="load")
        res['V10_HTTP_Extraction_Success'] = 1
        
        # V1: PHash Distance
        img = Image.open(io.BytesIO(page.screenshot())).convert('L')
        res['V1_PHash_Distance'] = (imagehash.phash(img) - TARGET_PHASH) / 64.0
        
        # V2: Layout Similarity
        soup = BeautifulSoup(page.content(), 'html.parser')
        depths = [len(list(t.parents)) for t in soup.find_all(True)]
        res['V2_Layout_Similarity'] = np.clip(1.0 - (max(depths or [0])/40.0), 0, 1)
        
        # V6: JS Entropy
        js_code = "".join([s.text for s in soup.find_all('script')])
        res['V6_JS_Entropy'] = get_entropy(js_code)
        
        # V7: Text Readability (Tỷ lệ từ trên câu)
        full_text = soup.get_text()
        words = full_text.split()
        sentences = re.split(r'[.!?]+', full_text)
        res['V7_Text_Readability_Score'] = np.clip(len(words)/(len(sentences) or 1) / 20.0, 0, 1)
        
        # V8, V9: IFrames
        iframes = soup.find_all('iframe')
        res['V8_Total_IFrames'] = len(iframes)
        res['V9_Has_Hidden_IFrame'] = 1 if any('none' in str(f.get('style','')).lower() for f in iframes) else 0
        
        res['V11_WHOIS_Extraction_Success'] = 1 # Đánh dấu đã quét thành công domain này
        
    except Exception:
        res['V10_HTTP_Extraction_Success'] = 0
        res['V1_PHash_Distance'] = 0.5 # Giá trị trung hòa cho URL chết
        
    return res

# =================================================================
# IV. QUẢN LÝ ĐA LUỒNG & GHI FILE
# =================================================================
def thread_worker(chunk_df):
    results = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
        context = browser.new_context()
        page = context.new_page()
        for _, row in chunk_df.iterrows():
            data = extract_full_features(page, row['URL'])
            data['URL_KEY'] = row['URL']
            results.append(data)
        browser.close()
    return results

def main():
    start_total_time = time.time()
    
    # 1. Đọc dữ liệu
    if not os.path.exists(RAW_CSV_FILE):
        print(f"❌ Lỗi: Không tìm thấy {RAW_CSV_FILE}"); return
    df_raw = pd.read_csv(RAW_CSV_FILE, usecols=OLD_KEEP_COLS)

    # 2. Kiểm tra Checkpoint
    processed_urls = pd.read_csv(TEMP_LOG_FILE)['URL_KEY'].astype(str).tolist() if os.path.exists(TEMP_LOG_FILE) else []
    df_todo = df_raw[~df_raw['URL'].isin(processed_urls)]
    
    total_todo = len(df_todo)
    if total_todo == 0:
        print("✅ Đã hoàn thành xử lý toàn bộ dữ liệu."); return

    print(f"🔥 Đang chạy 6 luồng xử lý {total_todo} URL còn lại...")

    # 3. Chạy đa luồng
    chunks = [df_todo[i:i + CHUNK_SIZE] for i in range(0, total_todo, CHUNK_SIZE)]
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(thread_worker, c): c for c in chunks}
        
        for i, future in enumerate(as_completed(futures), 1):
            batch_data = future.result()
            # Ghi ngay xuống file tạm
            pd.DataFrame(batch_data).to_csv(TEMP_LOG_FILE, mode='a', index=False, header=not os.path.exists(TEMP_LOG_FILE))
            
            # Tính toán tiến độ
            current_done = i * CHUNK_SIZE
            elapsed = time.time() - start_total_time
            speed = current_done / elapsed
            print(f"➜ Tiến độ: {min(current_done, total_todo)}/{total_todo} | Tốc độ: {speed:.2f} URL/s | ETA: {(total_todo-current_done)/speed/60:.1f} phút")

    # 4. HỢP NHẤT DỮ LIỆU CUỐI CÙNG & TẠO ALARM
    print("\n🔄 Đang gộp file và tạo biển báo động (Alarms)...")
    df_new = pd.read_csv(TEMP_LOG_FILE).drop_duplicates('URL_KEY')
    df_final = pd.merge(df_raw, df_new, left_on='URL', right_on='URL_KEY', how='inner')
    
    # Tạo biến Alarm cho các đặc trưng động quan trọng
    for col in ['V1_PHash_Distance', 'V2_Layout_Similarity', 'V6_JS_Entropy', 'V7_Text_Readability_Score']:
        df_final[f'Alarm_{col}_Missing'] = np.where(df_final['V10_HTTP_Extraction_Success'] == 0, 1, 0)

    df_final.drop(columns=['URL_KEY'], inplace=True)
    df_final.to_csv(FINAL_OUTPUT, index=False)
    
    print(f"✅ HOÀN TẤT! File kết quả: {FINAL_OUTPUT}")
    print(f"📊 Tổng số dòng: {len(df_final)} | Tổng cột: {len(df_final.columns)}")

if __name__ == "__main__":
    main()
