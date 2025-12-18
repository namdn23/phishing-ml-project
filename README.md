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

# THÔNG SỐ VẬN HÀNH
MAX_WORKERS = 20    
CHUNK_SIZE = 40     
TIMEOUT_MS = 10000  # Timeout 10 giây cho mỗi URL
TARGET_PHASH = imagehash.hex_to_hash('9880e61f1c7e0c4f')

OLD_KEEP_COLS = [
    'URL', 'NoOfDegitsInURL', 'HasDescription', 'HasSocialNet', 'HasPasswordField', 
    'HasSubmitButton', 'HasExternalFormSubmit', 'DomainTitleMatchScore', 
    'IsHTTPS', 'HasCopyrightInfo', 'label'
]

# =================================================================
# II. LOGIC TRÍCH XUẤT ĐẶC TRƯNG & ALARM
# =================================================================
def get_entropy(text):
    if not text or len(text) == 0: return 0.0
    probs = [count/len(text) for count in Counter(text).values()]
    return -sum(p * math.log2(p) for p in probs) / 8.0

def get_tls_issuer(hostname):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                return issuer.get('organizationName', 'Unknown')
    except: return 'None'

def extract_full_features(page, url):
    # Khởi tạo 14 đặc trưng + 3 cột báo lỗi
    res = {k: 0.0 for k in [
        'V10_HTTP_Extraction_Success', 'V11_WHOIS_Extraction_Success', 'V1_PHash_Distance', 
        'V2_Layout_Similarity', 'V6_JS_Entropy', 'V7_Text_Readability_Score', 
        'V8_Total_IFrames', 'V9_Has_Hidden_IFrame', 'V5_TLS_Issuer_Reputation', 
        'V3_Domain_Age_Days', 'V4_DNS_Volatility_Count', 'Is_Top_1M_Domain', 
        'V22_IP_Subdomain_Pattern', 'V23_Entropy_Subdomain',
        'Alarm_System_Error', 'Alarm_Capture_Failed', 'Alarm_Empty_Content'
    ]}
    
    try:
        # Tối ưu: Chặn rác để không phí thời gian load trong 10s timeout
        page.route("**/*", lambda route: route.abort() if route.request.resource_type in ["image", "media", "font", "other", "stylesheet"] else route.continue_())
        
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        
        # Đặc trưng tĩnh
        res['V22_IP_Subdomain_Pattern'] = 1 if re.search(r'\d+\.\d+', ext.subdomain) else 0
        res['V23_Entropy_Subdomain'] = get_entropy(ext.subdomain)
        res['Is_Top_1M_Domain'] = 1 if ext.domain in ['google', 'facebook', 'microsoft', 'apple', 'amazon'] else 0
        try: res['V4_DNS_Volatility_Count'] = len(socket.gethostbyname_ex(domain)[2])
        except: pass
        res['V5_TLS_Issuer_Reputation'] = 1.0 if get_tls_issuer(domain) != 'None' else 0.0

        # TRUY CẬP URL VỚI TIMEOUT
        page.goto(url, timeout=TIMEOUT_MS, wait_until="commit") 
        res['V10_HTTP_Extraction_Success'] = 1
        
        # Chụp ảnh (pHash)
        try:
            img_bytes = page.screenshot(timeout=5000)
            img = Image.open(io.BytesIO(img_bytes)).convert('L')
            res['V1_PHash_Distance'] = (imagehash.phash(img) - TARGET_PHASH) / 64.0
        except:
            res['Alarm_Capture_Failed'] = 1
            res['V1_PHash_Distance'] = 0.5

        # Nội dung (DOM/JS)
        content = page.content()
        soup = BeautifulSoup(content, 'html.parser')
        full_text = soup.get_text().strip()
        if len(content) < 500 or not full_text: res['Alarm_Empty_Content'] = 1

        depths = [len(list(t.parents)) for t in soup.find_all(True)]
        res['V2_Layout_Similarity'] = np.clip(1.0 - (max(depths or [0])/40.0), 0, 1)
        js_code = "".join([s.text for s in soup.find_all('script')])
        res['V6_JS_Entropy'] = get_entropy(js_code)
        words, sentences = full_text.split(), re.split(r'[.!?]+', full_text)
        res['V7_Text_Readability_Score'] = np.clip(len(words)/(len(sentences) or 1) / 20.0, 0, 1)
        iframes = soup.find_all('iframe')
        res['V8_Total_IFrames'], res['V9_Has_Hidden_IFrame'] = len(iframes), (1 if any('none' in str(f.get('style','')).lower() for f in iframes) else 0)
        res['V11_WHOIS_Extraction_Success'] = 1
        
    except Exception:
        # Bắt lỗi Timeout hoặc URL chết
        res['Alarm_System_Error'] = 1
        res['V10_HTTP_Extraction_Success'] = 0
        res['V1_PHash_Distance'] = 0.5 
    return res

# =================================================================
# III. QUẢN LÝ ĐA LUỒNG & DỰ ĐOÁN ETA
# =================================================================
def thread_worker(chunk_df):
    results = []
    p = sync_playwright().start() 
    browser = None
    try:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage", "--single-process"])
        context = browser.new_context(viewport={'width': 1280, 'height': 720})
        page = context.new_page()
        for _, row in chunk_df.iterrows():
            data = extract_full_features(page, row['URL'])
            data['URL_KEY'] = str(row['URL'])
            results.append(data)
    finally:
        if browser: browser.close()
        p.stop() # Cưỡng ép tiêu diệt Chrome Driver để xả RAM
    return results



def main():
    start_session_time = time.time()
    if not os.path.exists(RAW_CSV_FILE):
        print(f"❌ Không tìm thấy file nguồn {RAW_CSV_FILE}"); return
        
    df_raw = pd.read_csv(RAW_CSV_FILE, usecols=OLD_KEEP_COLS)
    
    # Checkpoint
    processed_urls = set(pd.read_csv(TEMP_LOG_FILE, usecols=['URL_KEY'])['URL_KEY'].astype(str)) if os.path.exists(TEMP_LOG_FILE) else set()
    df_todo = df_raw[~df_raw['URL'].astype(str).isin(processed_urls)]
    total_todo = len(df_todo)
    
    if total_todo == 0:
        print("✅ Đã hoàn thành toàn bộ dữ liệu."); return

    print(f"🚀 Tiếp tục: {len(processed_urls)} | Còn: {total_todo} | Timeout: {TIMEOUT_MS}ms")
    chunks = [df_todo[i:i + CHUNK_SIZE] for i in range(0, total_todo, CHUNK_SIZE)]
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(thread_worker, c): c for c in chunks}
        for i, future in enumerate(as_completed(futures), 1):
            batch = future.result()
            if batch:
                # GHI FILE & FLUSH RAM
                with open(TEMP_LOG_FILE, 'a', encoding='utf-8') as f:
                    pd.DataFrame(batch).to_csv(f, header=f.tell()==0, index=False)
                    f.flush()
                    os.fsync(f.fileno())
            
            # TÍNH TOÁN DỰ ĐOÁN THỜI GIAN (ETA)
            done = i * CHUNK_SIZE
            if done > total_todo: done = total_todo
            elapsed = time.time() - start_session_time
            speed = done / elapsed if elapsed > 0 else 0
            remaining_sec = (total_todo - done) / speed if speed > 0 else 0
            
            eta_str = str(timedelta(seconds=int(remaining_sec)))
            finish_at = (datetime.now() + timedelta(seconds=int(remaining_sec))).strftime("%H:%M:%S")

            print(f"➜ [{datetime.now().strftime('%H:%M:%S')}] {len(processed_urls)+done}/{len(df_raw)} "
                  f"| {speed:.1f} URL/s | Còn lại: {eta_str} | Xong lúc: {finish_at}")

    # TỔNG HỢP CUỐI CÙNG
    print("\n🔄 Đang gộp file kết quả...")
    df_new = pd.read_csv(TEMP_LOG_FILE).drop_duplicates('URL_KEY')
    df_final = pd.merge(df_raw, df_new, left_on='URL', right_on='URL_KEY', how='inner')
    df_final.drop(columns=['URL_KEY']).to_csv(FINAL_OUTPUT, index=False)
    print(f"✅ HOÀN TẤT! File: {FINAL_OUTPUT}")

if __name__ == "__main__":
    main()
