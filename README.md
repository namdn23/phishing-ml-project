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
# I. CẤU HÌNH HỆ THỐNG (TỐI ƯU CHO 32GB RAM)
# =================================================================
RAW_CSV_FILE = 'PhiUSIIL_Phishing_URL_Dataset.csv'
TEMP_LOG_FILE = 'extraction_checkpoint.csv'
FINAL_OUTPUT = 'PhiUSIIL_Extracted_Full.csv'

# THÔNG SỐ VẬN HÀNH AN TOÀN
MAX_WORKERS = 20    # Số luồng đồng thời (Giảm từ 35 xuống 20 để tránh tràn RAM)
CHUNK_SIZE = 40     # Số URL mỗi luồng xử lý trước khi reset trình duyệt
TIMEOUT_MS = 10000  # 10 giây cho mỗi trang web
TARGET_PHASH = imagehash.hex_to_hash('9880e61f1c7e0c4f')

# Các cột giữ lại từ file gốc
OLD_KEEP_COLS = [
    'URL', 'NoOfDegitsInURL', 'HasDescription', 'HasSocialNet', 'HasPasswordField', 
    'HasSubmitButton', 'HasExternalFormSubmit', 'DomainTitleMatchScore', 
    'IsHTTPS', 'HasCopyrightInfo', 'label'
]

# =================================================================
# II. CÁC HÀM TÍNH TOÁN FEATURE (LOGIC GIỮ NGUYÊN)
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

# =================================================================
# III. HÀM TRÍCH XUẤT CHI TIẾT
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
        # Tối ưu tốc độ: Bỏ qua các tài nguyên không cần thiết
        page.route("**/*", lambda route: route.abort() 
                   if route.request.resource_type in ["image", "media", "font", "other", "stylesheet"] 
                   else route.continue_())

        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        
        # Features tĩnh
        res['V22_IP_Subdomain_Pattern'] = 1 if re.search(r'\d+\.\d+', ext.subdomain) else 0
        res['V23_Entropy_Subdomain'] = get_entropy(ext.subdomain)
        res['Is_Top_1M_Domain'] = 1 if ext.domain in ['google', 'facebook', 'microsoft', 'apple', 'amazon'] else 0
        try:
            res['V4_DNS_Volatility_Count'] = len(socket.gethostbyname_ex(domain)[2])
        except: pass
        res['V5_TLS_Issuer_Reputation'] = 1.0 if get_tls_issuer(domain) != 'None' else 0.0

        # Features động (Playwright)
        page.goto(url, timeout=TIMEOUT_MS, wait_until="commit") 
        res['V10_HTTP_Extraction_Success'] = 1
        
        # pHash
        img_bytes = page.screenshot()
        img = Image.open(io.BytesIO(img_bytes)).convert('L')
        res['V1_PHash_Distance'] = (imagehash.phash(img) - TARGET_PHASH) / 64.0
        
        soup = BeautifulSoup(page.content(), 'html.parser')
        
        # DOM Depth
        depths = [len(list(t.parents)) for t in soup.find_all(True)]
        res['V2_Layout_Similarity'] = np.clip(1.0 - (max(depths or [0])/40.0), 0, 1)
        
        # JS & Text
        js_code = "".join([s.text for s in soup.find_all('script')])
        res['V6_JS_Entropy'] = get_entropy(js_code)
        
        full_text = soup.get_text()
        words = full_text.split()
        sentences = re.split(r'[.!?]+', full_text)
        res['V7_Text_Readability_Score'] = np.clip(len(words)/(len(sentences) or 1) / 20.0, 0, 1)
        
        # IFrames
        iframes = soup.find_all('iframe')
        res['V8_Total_IFrames'] = len(iframes)
        res['V9_Has_Hidden_IFrame'] = 1 if any('none' in str(f.get('style','')).lower() for f in iframes) else 0
        res['V11_WHOIS_Extraction_Success'] = 1
        
    except Exception:
        res['V10_HTTP_Extraction_Success'] = 0
        res['V1_PHash_Distance'] = 0.5 
    return res

# =================================================================
# IV. QUẢN LÝ LUỒNG VÀ DỌN DẸP TIẾN TRÌNH
# =================================================================
def thread_worker(chunk_df):
    results = []
    p = sync_playwright().start() # Khởi động Playwright driver cho riêng luồng này
    browser = None
    try:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
        context = browser.new_context(viewport={'width': 1280, 'height': 720})
        page = context.new_page()
        
        for _, row in chunk_df.iterrows():
            data = extract_full_features(page, row['URL'])
            data['URL_KEY'] = str(row['URL'])
            results.append(data)
    except Exception as e:
        print(f"⚠️ Error in thread: {e}")
    finally:
        # BẮT BUỘC: Dọn dẹp để không bị tràn RAM
        if browser: browser.close()
        p.stop() 
    return results

def main():
    start_session_time = time.time()
    if not os.path.exists(RAW_CSV_FILE):
        print(f"❌ File {RAW_CSV_FILE} không tồn tại."); return
        
    df_raw = pd.read_csv(RAW_CSV_FILE, usecols=OLD_KEEP_COLS)
    
    # Kiểm tra checkpoint
    if os.path.exists(TEMP_LOG_FILE):
        processed_urls = set(pd.read_csv(TEMP_LOG_FILE, usecols=['URL_KEY'])['URL_KEY'].astype(str))
    else:
        processed_urls = set()
    
    df_todo = df_raw[~df_raw['URL'].astype(str).isin(processed_urls)]
    total_todo = len(df_todo)
    
    if total_todo == 0:
        print("✅ Đã xử lý xong toàn bộ dữ liệu."); return

    print(f"🚀 Tiếp tục từ: {len(processed_urls)} | Còn lại: {total_todo} | Chạy {MAX_WORKERS} luồng")

    chunks = [df_todo[i:i + CHUNK_SIZE] for i in range(0, total_todo, CHUNK_SIZE)]
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(thread_worker, c): c for c in chunks}
        
        for i, future in enumerate(as_completed(futures), 1):
            batch_data = future.result()
            if batch_data:
                pd.DataFrame(batch_data).to_csv(TEMP_LOG_FILE, mode='a', index=False, header=not os.path.exists(TEMP_LOG_FILE))
            
            # Cập nhật tiến độ
            done_in_session = i * CHUNK_SIZE
            speed = done_in_session / (time.time() - start_session_time)
            print(f"➜ [{datetime.now().strftime('%H:%M:%S')}] {len(processed_urls) + done_in_session}/{len(df_raw)} | Tốc độ: {speed:.2f} URL/s")

    # V. HỢP NHẤT KẾT QUẢ CUỐI CÙNG
    print("\n🔄 Đang tạo file kết quả cuối cùng...")
    df_new = pd.read_csv(TEMP_LOG_FILE).drop_duplicates('URL_KEY')
    df_final = pd.merge(df_raw, df_new, left_on='URL', right_on='URL_KEY', how='inner')
    
    # Tạo các cột Alarm báo lỗi trích xuất
    for col in ['V1_PHash_Distance', 'V2_Layout_Similarity', 'V6_JS_Entropy', 'V7_Text_Readability_Score']:
        df_final[f'Alarm_{col}_Missing'] = (df_final['V10_HTTP_Extraction_Success'] == 0).astype(int)

    df_final.drop(columns=['URL_KEY'], inplace=True)
    df_final.to_csv(FINAL_OUTPUT, index=False)
    print(f"✅ HOÀN TẤT! File: {FINAL_OUTPUT}")

if __name__ == "__main__":
    main()
