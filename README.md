import pandas as pd
import numpy as np
import os, time, math, io, socket, re, tldextract, ssl, threading
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from playwright.sync_api import sync_playwright
import imagehash
from PIL import Image
from bs4 import BeautifulSoup
from collections import Counter

# =================================================================
# I. CẤU HÌNH ĐUA TỐC ĐỘ (20 LUỒNG - GIỮ NGUYÊN FEATURES)
# =================================================================
RAW_CSV_FILE = 'PhiUSIIL_Phishing_URL_Dataset.csv'
TEMP_LOG_FILE = 'extraction_checkpoint.csv'
FINAL_OUTPUT = 'PhiUSIIL_Extracted_Full.csv'

# Tăng lên 20 luồng vì Load Average của bạn đang ổn định (~3.8)
MAX_WORKERS = 20  
CHUNK_SIZE = 15   
# Giảm Timeout xuống 10s để dứt điểm nhanh các URL "chết"
TIMEOUT_MS = 10000  
TARGET_PHASH = imagehash.hex_to_hash('9880e61f1c7e0c4f')

csv_lock = threading.Lock()

OLD_KEEP_COLS = [
    'URL', 'NoOfDegitsInURL', 'HasDescription', 'HasSocialNet', 'HasPasswordField', 
    'HasSubmitButton', 'HasExternalFormSubmit', 'DomainTitleMatchScore', 
    'IsHTTPS', 'HasCopyrightInfo', 'label'
]

# =================================================================
# II. CÔNG CỤ HỖ TRỢ (GIỮ NGUYÊN)
# =================================================================
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
# III. LOGIC TRÍCH XUẤT (GIỮ NGUYÊN 100% ĐẶC TRƯNG)
# =================================================================
def extract_full_features(page, url, retry=0):
    res = {k: 0.0 for k in [
        'V10_HTTP_Extraction_Success', 'V11_WHOIS_Extraction_Success', 'V1_PHash_Distance', 
        'V2_Layout_Similarity', 'V6_JS_Entropy', 'V7_Text_Readability_Score', 
        'V8_Total_IFrames', 'V9_Has_Hidden_IFrame', 'V5_TLS_Issuer_Reputation', 
        'V3_Domain_Age_Days', 'V4_DNS_Volatility_Count', 'Is_Top_1M_Domain', 
        'V22_IP_Subdomain_Pattern', 'V23_Entropy_Subdomain'
    ]}

    try:
        # Tăng tốc bằng cách chặn rác, nhưng giữ Script để tính V6_JS_Entropy
        page.route("**/*", lambda route: route.abort() if route.request.resource_type in ["image", "media", "font"] else route.continue_())

        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        res['V22_IP_Subdomain_Pattern'] = 1 if re.search(r'\d+\.\d+', ext.subdomain) else 0
        res['V23_Entropy_Subdomain'] = get_entropy(ext.subdomain)
        res['Is_Top_1M_Domain'] = 1 if ext.domain in ['google', 'facebook', 'microsoft', 'apple', 'amazon'] else 0
        
        try: res['V4_DNS_Volatility_Count'] = len(socket.gethostbyname_ex(domain)[2])
        except: pass
        res['V5_TLS_Issuer_Reputation'] = 1.0 if get_tls_issuer(domain) != 'None' else 0.0

        # Tải trang
        response = page.goto(url, timeout=TIMEOUT_MS, wait_until="domcontentloaded")
        if not response or response.status >= 400: raise Exception("Skip")

        res['V10_HTTP_Extraction_Success'] = 1
        
        # pHash (Chụp ảnh Viewport nhỏ để giảm tải CPU/RAM)
        try:
            img_bytes = page.screenshot(timeout=3000)
            img = Image.open(io.BytesIO(img_bytes)).convert('L')
            res['V1_PHash_Distance'] = (imagehash.phash(img) - TARGET_PHASH) / 64.0
        except: res['V1_PHash_Distance'] = 0.5

        content = page.content()
        soup = BeautifulSoup(content, 'lxml') 
        text_content = soup.get_text().strip()
        
        # Feature: DOM Depth
        depths = [len(list(t.parents)) for t in soup.find_all(True)]
        res['V2_Layout_Similarity'] = np.clip(1.0 - (max(depths or [0])/50.0), 0, 1)
        
        # Feature: JS Entropy
        res['V6_JS_Entropy'] = get_entropy("".join([s.text for s in soup.find_all('script')]))
        
        # Feature: Readability
        words, sents = text_content.split(), re.split(r'[.!?]+', text_content)
        res['V7_Text_Readability_Score'] = np.clip(len(words)/(len(sents) or 1) / 25.0, 0, 1)
        
        # Feature: IFrames
        iframes = soup.find_all('iframe')
        res['V8_Total_IFrames'] = len(iframes)
        res['V9_Has_Hidden_IFrame'] = 1 if any('none' in str(f.get('style','')).lower() for f in iframes) else 0
        res['V11_WHOIS_Extraction_Success'] = 1

    except Exception:
        res['V10_HTTP_Extraction_Success'] = 0
        res['V1_PHash_Distance'] = 0.5 
    return res

def thread_worker(chunk_df):
    results = []
    with sync_playwright() as p:
        # Thêm các cờ tối ưu RAM cực độ
        browser = p.chromium.launch(headless=True, args=[
            "--no-sandbox", 
            "--disable-gpu", 
            "--disable-dev-shm-usage", 
            "--single-process",
            "--js-flags='--max-old-space-size=256'"
        ])
        context = browser.new_context(
            user_agent="Mozilla/5.0 (X11; Linux x86_64)",
            viewport={'width': 800, 'height': 600} # Ảnh nhỏ hơn -> trích xuất nhanh hơn
        )
        
        for _, row in chunk_df.iterrows():
            page = context.new_page()
            data = extract_full_features(page, row['URL'])
            data['URL_KEY'] = str(row['URL'])
            results.append(data)
            page.close()
            
        browser.close()
    return results

# =================================================================
# IV. QUẢN LÝ TIẾN TRÌNH (BỎ PKILL - CHỈ DỌN CACHE)
# =================================================================
def main():
    start_time = time.time()
    df_raw = pd.read_csv(RAW_CSV_FILE, usecols=OLD_KEEP_COLS)
    
    processed_urls = set()
    if os.path.exists(TEMP_LOG_FILE):
        try:
            check_df = pd.read_csv(TEMP_LOG_FILE, usecols=['URL_KEY'])
            processed_urls = set(check_df['URL_KEY'].astype(str))
        except: pass

    df_todo = df_raw[~df_raw['URL'].astype(str).isin(processed_urls)]
    total_todo = len(df_todo)
    
    if total_todo == 0:
        print("✅ Đã hoàn thành!"); return

    print(f"🚀 ĐANG CHẠY {MAX_WORKERS} LUỒNG | Cần xử lý: {total_todo} URL")
    chunks = [df_todo[i:i + CHUNK_SIZE] for i in range(0, total_todo, CHUNK_SIZE)]
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(thread_worker, c): c for c in chunks}
        for i, future in enumerate(as_completed(futures), 1):
            try:
                batch = future.result()
                if batch:
                    with csv_lock:
                        pd.DataFrame(batch).to_csv(TEMP_LOG_FILE, mode='a', header=not os.path.exists(TEMP_LOG_FILE), index=False)
                
                # Dọn RAM hệ thống mỗi 30 batch (Không giết trình duyệt)
                if i % 30 == 0: 
                    os.system('sync; echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null')

                done = min(i * CHUNK_SIZE, total_todo)
                elapsed = time.time() - start_time
                speed = done / elapsed if elapsed > 0 else 0
                rem_sec = (total_todo - done) / speed if speed > 0 else 0
                
                print(f"➜ [{datetime.now().strftime('%H:%M:%S')}] {len(processed_urls)+done}/{len(df_raw)} "
                      f"| {speed:.2f} URL/s | Còn: {str(timedelta(seconds=int(rem_sec)))}")
            except Exception as e:
                print(f"❌ Lỗi: {e}")

    # Gộp file
    print("\n🔄 Đang tạo file kết quả...")
    df_new = pd.read_csv(TEMP_LOG_FILE).drop_duplicates('URL_KEY')
    df_final = pd.merge(df_raw, df_new, left_on='URL', right_on='URL_KEY', how='inner')
    df_final.drop(columns=['URL_KEY']).to_csv(FINAL_OUTPUT, index=False)
    print(f"✅ XONG! Lưu tại: {FINAL_OUTPUT}")

if __name__ == "__main__":
    main()
