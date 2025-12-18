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

# Tối ưu cho độ chính xác và chống chặn
MAX_WORKERS = 15    
CHUNK_SIZE = 40     
TIMEOUT_MS = 15000  # 15 giây để trang kịp load khi có bảo mật
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
# III. LOGIC TRÍCH XUẤT CHỐNG CHẶN (ADAPTIVE RETRY)
# =================================================================
def extract_full_features(page, url, retry_count=0):
    res = {k: 0.0 for k in [
        'V10_HTTP_Extraction_Success', 'V11_WHOIS_Extraction_Success', 'V1_PHash_Distance', 
        'V2_Layout_Similarity', 'V6_JS_Entropy', 'V7_Text_Readability_Score', 
        'V8_Total_IFrames', 'V9_Has_Hidden_IFrame', 'V5_TLS_Issuer_Reputation', 
        'V3_Domain_Age_Days', 'V4_DNS_Volatility_Count', 'Is_Top_1M_Domain', 
        'V22_IP_Subdomain_Pattern', 'V23_Entropy_Subdomain'
    ]}

    # Handler chặn rác để tăng tốc
    def block_resources(route):
        try:
            # Nếu là lần thử lại (retry), cho phép tải CSS để vượt qua check-bot sâu
            bad_types = ["image", "media", "font"] if retry_count > 0 else ["image", "media", "font", "stylesheet"]
            if route.request.resource_type in bad_types:
                route.abort()
            else:
                route.continue_()
        except: pass

    try:
        page.route("**/*", block_resources)
        
        # Đặc trưng Domain (Không cần mạng)
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        res['V22_IP_Subdomain_Pattern'] = 1 if re.search(r'\d+\.\d+', ext.subdomain) else 0
        res['V23_Entropy_Subdomain'] = get_entropy(ext.subdomain)
        res['Is_Top_1M_Domain'] = 1 if ext.domain in ['google', 'facebook', 'microsoft', 'apple', 'amazon'] else 0
        
        try: res['V4_DNS_Volatility_Count'] = len(socket.gethostbyname_ex(domain)[2])
        except: pass
        res['V5_TLS_Issuer_Reputation'] = 1.0 if get_tls_issuer(domain) != 'None' else 0.0

        # Truy cập trang với cơ chế giả lập người dùng
        response = page.goto(url, timeout=TIMEOUT_MS, wait_until="load")
        
        # Kiểm tra nếu bị chặn bởi Cloudflare hoặc lỗi server
        if not response or response.status in [403, 503, 429]:
            raise Exception("Blocked")

        res['V10_HTTP_Extraction_Success'] = 1
        
        # Chụp ảnh tính pHash
        try:
            img_bytes = page.screenshot(timeout=5000)
            img = Image.open(io.BytesIO(img_bytes)).convert('L')
            res['V1_PHash_Distance'] = (imagehash.phash(img) - TARGET_PHASH) / 64.0
        except:
            res['V1_PHash_Distance'] = 0.5

        # BeautifulSoup xử lý nội dung
        content = page.content()
        soup = BeautifulSoup(content, 'lxml') 
        text_content = soup.get_text()
        
        depths = [len(list(t.parents)) for t in soup.find_all(True)]
        res['V2_Layout_Similarity'] = np.clip(1.0 - (max(depths or [0])/40.0), 0, 1)
        res['V6_JS_Entropy'] = get_entropy("".join([s.text for s in soup.find_all('script')]))
        
        words, sents = text_content.split(), re.split(r'[.!?]+', text_content)
        res['V7_Text_Readability_Score'] = np.clip(len(words)/(len(sents) or 1) / 20.0, 0, 1)
        
        iframes = soup.find_all('iframe')
        res['V8_Total_IFrames'] = len(iframes)
        res['V9_Has_Hidden_IFrame'] = 1 if any('none' in str(f.get('style','')).lower() for f in iframes) else 0
        res['V11_WHOIS_Extraction_Success'] = 1

    except Exception:
        # Nếu bị lỗi/chặn và chưa retry, tiến hành thử lại 1 lần duy nhất
        if retry_count < 1:
            time.sleep(2) # Nghỉ 2s trước khi thử lại
            return extract_full_features(page, url, retry_count=1)
        
        res['V10_HTTP_Extraction_Success'] = 0
        res['V1_PHash_Distance'] = 0.5 
    return res

def thread_worker(chunk_df):
    results = []
    with sync_playwright() as p:
        # Khởi chạy với chế độ ẩn danh và giả lập người dùng
        browser = p.chromium.launch(headless=True, args=[
            "--no-sandbox", 
            "--disable-dev-shm-usage",
            "--disable-blink-features=AutomationControlled"
        ])
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            viewport={'width': 1280, 'height': 720}
        )
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
        print("✅ Hoàn tất 100%!"); return

    print(f"🚀 STEALTH MODE ON | Workers: {MAX_WORKERS} | Còn lại: {total_todo}")
    chunks = [df_todo[i:i + CHUNK_SIZE] for i in range(0, total_todo, CHUNK_SIZE)]
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(thread_worker, c): c for c in chunks}
        for i, future in enumerate(as_completed(futures), 1):
            try:
                batch = future.result()
                if batch:
                    with open(TEMP_LOG_FILE, 'a', encoding='utf-8') as f:
                        pd.DataFrame(batch).to_csv(f, header=f.tell()==0, index=False)
                
                if i % 10 == 0: 
                    clear_linux_cache()
                    os.system('pkill -f chromium')

                done = min(i * CHUNK_SIZE, total_todo)
                elapsed = time.time() - start_session_time
                speed = done / elapsed if elapsed > 0 else 0
                rem_sec = (total_todo - done) / speed if speed > 0 else 0
                
                print(f"➜ [{datetime.now().strftime('%H:%M:%S')}] {len(processed_urls)+done}/{len(df_raw)} "
                      f"| {speed:.2f} URL/s | Còn: {str(timedelta(seconds=int(rem_sec)))}")
            except Exception: pass

    print("\n🔄 Đang hoàn thiện file tổng hợp...")
    df_new = pd.read_csv(TEMP_LOG_FILE, on_bad_lines='skip').drop_duplicates('URL_KEY')
    df_final = pd.merge(df_raw, df_new, left_on='URL', right_on='URL_KEY', how='inner')
    df_final.drop(columns=['URL_KEY']).to_csv(FINAL_OUTPUT, index=False)
    print(f"✅ XONG! Kết quả tại: {FINAL_OUTPUT}")

if __name__ == "__main__":
    main()
