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
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from playwright.sync_api import sync_playwright
import imagehash
from PIL import Image
from bs4 import BeautifulSoup
from collections import Counter

# =================================================================
# I. CẤU HÌNH HỆ THỐNG
# =================================================================
RAW_CSV_FILE = 'PhiUSIIL_Phishing_URL_Dataset.csv'
TEMP_LOG_FILE = 'extraction_checkpoint.csv'
FINAL_OUTPUT = 'PhiUSIIL_Extracted_Full.csv'

# THÔNG SỐ VẬN HÀNH TỐI ƯU
MAX_WORKERS = 15    # 15 luồng để ổn định CPU trên Kali
CHUNK_SIZE = 25     # Ghi file sau mỗi 25 URL mỗi luồng
TIMEOUT_MS = 12000  # 12 giây cho mỗi URL
TARGET_PHASH = imagehash.hex_to_hash('9880e61f1c7e0c4f')

OLD_KEEP_COLS = [
    'URL', 'NoOfDegitsInURL', 'HasDescription', 'HasSocialNet', 'HasPasswordField', 
    'HasSubmitButton', 'HasExternalFormSubmit', 'DomainTitleMatchScore', 
    'IsHTTPS', 'HasCopyrightInfo', 'label'
]

# =================================================================
# II. CÔNG CỤ HỆ THỐNG
# =================================================================
def clear_linux_cache():
    try: os.system('sync; echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null')
    except: pass

def get_entropy(text):
    if not text or len(text) == 0: return 0.0
    probs = [count/len(text) for count in Counter(text).values()]
    return -sum(p * math.log2(p) for p in probs) / 8.0

def get_tls_issuer(hostname):
    try:
        context = ssl.create_default_context()
        context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                return issuer.get('organizationName', 'Unknown')
    except: return 'None'

# =================================================================
# III. LOGIC TRÍCH XUẤT SIÊU TỐC (GIỮ NGUYÊN ĐẶC TRƯNG)
# =================================================================
def extract_full_features(page, url):
    res = {k: 0.0 for k in [
        'V10_HTTP_Extraction_Success', 'V11_WHOIS_Extraction_Success', 'V1_PHash_Distance', 
        'V2_Layout_Similarity', 'V6_JS_Entropy', 'V7_Text_Readability_Score', 
        'V8_Total_IFrames', 'V9_Has_Hidden_IFrame', 'V5_TLS_Issuer_Reputation', 
        'V3_Domain_Age_Days', 'V4_DNS_Volatility_Count', 'Is_Top_1M_Domain', 
        'V22_IP_Subdomain_Pattern', 'V23_Entropy_Subdomain'
    ]}

    # Handler chặn tài nguyên để tăng tốc nhưng không làm hỏng DOM
    def block_resources(route):
        try:
            if route.request.resource_type in ["image", "media", "font", "stylesheet", "other"]:
                route.abort()
            else:
                route.continue_()
        except: pass

    try:
        page.route("**/*", block_resources)
        
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        res['V22_IP_Subdomain_Pattern'] = 1 if re.search(r'\d+\.\d+', ext.subdomain) else 0
        res['V23_Entropy_Subdomain'] = get_entropy(ext.subdomain)
        res['Is_Top_1M_Domain'] = 1 if ext.domain in ['google', 'facebook', 'microsoft', 'apple', 'amazon'] else 0
        
        try: res['V4_DNS_Volatility_Count'] = len(socket.gethostbyname_ex(domain)[2])
        except: pass
        res['V5_TLS_Issuer_Reputation'] = 1.0 if get_tls_issuer(domain) != 'None' else 0.0

        # Mở trang
        page.goto(url, timeout=TIMEOUT_MS, wait_until="commit") 
        res['V10_HTTP_Extraction_Success'] = 1
        
        # pHash - Tính trên layout (vẫn đảm bảo đặc trưng cấu trúc)
        try:
            img_bytes = page.screenshot(timeout=4000)
            img = Image.open(io.BytesIO(img_bytes)).convert('L')
            res['V1_PHash_Distance'] = (imagehash.phash(img) - TARGET_PHASH) / 64.0
        except:
            res['V1_PHash_Distance'] = 0.5

        # Phân tích nội dung (Dùng lxml để cực nhanh)
        content = page.content()
        soup = BeautifulSoup(content, 'lxml') 
        full_text = soup.get_text().strip()
        
        depths = [len(list(t.parents)) for t in soup.find_all(True)]
        res['V2_Layout_Similarity'] = np.clip(1.0 - (max(depths or [0])/40.0), 0, 1)
        js_code = "".join([s.text for s in soup.find_all('script')])
        res['V6_JS_Entropy'] = get_entropy(js_code)
        
        words, sentences = full_text.split(), re.split(r'[.!?]+', full_text)
        res['V7_Text_Readability_Score'] = np.clip(len(words)/(len(sentences) or 1) / 20.0, 0, 1)
        
        iframes = soup.find_all('iframe')
        res['V8_Total_IFrames'] = len(iframes)
        res['V9_Has_Hidden_IFrame'] = 1 if any('none' in str(f.get('style','')).lower() for f in iframes) else 0
        res['V11_WHOIS_Extraction_Success'] = 1
    except:
        res['V10_HTTP_Extraction_Success'] = 0
        res['V1_PHash_Distance'] = 0.5 
    return res

def thread_worker(chunk_df):
    results = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
        context = browser.new_context(viewport={'width': 1280, 'height': 720})
        page = context.new_page()
        for _, row in chunk_df.iterrows():
            data = extract_full_features(page, row['URL'])
            data['URL_KEY'] = str(row['URL'])
            results.append(data)
        browser.close()
    return results

# =================================================================
# IV. QUẢN LÝ TIẾN TRÌNH
# =================================================================
def main():
    start_session_time = time.time()
    df_raw = pd.read_csv(RAW_CSV_FILE, usecols=OLD_KEEP_COLS)
    
    if os.path.exists(TEMP_LOG_FILE):
        print("🔄 Đang quét checkpoint...")
        check_df = pd.read_csv(TEMP_LOG_FILE, usecols=['URL_KEY'], on_bad_lines='skip').dropna()
        processed_urls = set(check_df['URL_KEY'].astype(str))
    else:
        processed_urls = set()

    df_todo = df_raw[~df_raw['URL'].astype(str).isin(processed_urls)]
    total_todo = len(df_todo)
    
    if total_todo == 0:
        print("✅ Đã xử lý xong toàn bộ!"); return

    print(f"🚀 Chạy tiếp: {len(processed_urls)} | Còn lại: {total_todo} URL")
    chunks = [df_todo[i:i + CHUNK_SIZE] for i in range(0, total_todo, CHUNK_SIZE)]
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(thread_worker, c): c for c in chunks}
        for i, future in enumerate(as_completed(futures), 1):
            try:
                batch = future.result()
                if batch:
                    with open(TEMP_LOG_FILE, 'a', encoding='utf-8') as f:
                        pd.DataFrame(batch).to_csv(f, header=f.tell()==0, index=False)
                
                if i % 20 == 0: # Dọn RAM sau mỗi 20 batch
                    clear_linux_cache()
                    os.system('pkill -f chromium')

                done = min(i * CHUNK_SIZE, total_todo)
                elapsed = time.time() - start_session_time
                speed = done / elapsed if elapsed > 0 else 0
                rem_sec = (total_todo - done) / speed if speed > 0 else 0
                
                print(f"➜ [{datetime.now().strftime('%H:%M:%S')}] {len(processed_urls)+done}/{len(df_raw)} "
                      f"| {speed:.1f} URL/s | Còn: {str(timedelta(seconds=int(rem_sec)))}")
            except Exception: pass

    # Gộp dữ liệu lần cuối
    print("\n🔄 Đang tiến hành gộp dữ liệu...")
    df_new = pd.read_csv(TEMP_LOG_FILE, on_bad_lines='skip').drop_duplicates('URL_KEY')
    df_final = pd.merge(df_raw, df_new, left_on='URL', right_on='URL_KEY', how='inner')
    df_final.drop(columns=['URL_KEY']).to_csv(FINAL_OUTPUT, index=False)
    print(f"✅ HOÀN TẤT! File lưu tại: {FINAL_OUTPUT}")

if __name__ == "__main__":
    main()
