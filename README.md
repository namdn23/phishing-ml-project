import pandas as pd
import concurrent.futures
import time
import os
import sys
import re
import math
import socket
import ssl
import requests
import warnings
from urllib.parse import urlparse
from datetime import datetime
from bs4 import BeautifulSoup

# --- CẤU HÌNH ---
INPUT_FILE = 'urldata_balanced.csv'       # File đầu vào (Đã cân bằng)
OUTPUT_FILE = 'dataset_final_train.csv'   # File kết quả (Dùng để Train)
MAX_WORKERS = 50                          # Số luồng chạy song song
TIMEOUT_REQUEST = 3                       # Thời gian chờ tải HTML (giây)
TIMEOUT_SOCKET = 2                        # Thời gian chờ check SSL (giây)

# Tắt cảnh báo SSL
warnings.filterwarnings('ignore')

# --- KHỐI DỮ LIỆU CỐ ĐỊNH (CONSTANTS) ---
RISKY_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.vip', '.online', '.club', '.cfd', '.loan', '.click', '.asia', '.ru', '.work', '.cn']

TRUSTED_ISSUERS = {
    'Google', 'Microsoft', 'DigiCert', 'Sectigo', 'GlobalSign', 'Amazon', 'Apple', 
    'Entrust', 'GeoTrust', 'Thawte', 'GoDaddy', 'VeriSign', 'GTS', "Let's Encrypt"
}

BRANDS = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'netflix', 'vietcombank', 'mbbank', 'tpbank', 'binance', 'shopee', 'lazada', 'tiki']

# ==============================================================================
# CLASS FEATURE EXTRACTOR (TRÍ TUỆ CỦA HỆ THỐNG)
# ==============================================================================
class FeatureExtractor:
    def __init__(self, url):
        self.url = str(url).strip()
        if not self.url.startswith(('http://', 'https://')):
            self.url = 'http://' + self.url
        
        try:
            self.parsed = urlparse(self.url)
            self.domain = self.parsed.netloc
            self.path = self.parsed.path
            self.query = self.parsed.query
        except:
            self.domain = ""
            self.path = ""
            self.query = ""
            
        self.html = None
        self.soup = None

    # --- 1. HÀM TẢI HTML ---
    def fetch_html(self):
        if self.html: return True
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'}
            resp = requests.get(self.url, headers=headers, timeout=TIMEOUT_REQUEST, verify=False)
            if resp.status_code == 200:
                self.html = resp.text
                self.soup = BeautifulSoup(self.html, 'html.parser')
                return True
        except: pass
        return False

    # --- 2. HÀM CHECK SSL ---
    def get_ssl_details(self):
        try:
            ctx = ssl.create_default_context()
            # Timeout cực ngắn để tránh treo luồng
            with socket.create_connection((self.domain, 443), timeout=TIMEOUT_SOCKET) as s:
                with ctx.wrap_socket(s, server_hostname=self.domain) as ss:
                    cert = ss.getpeercert()
                    nb = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    age = (datetime.now() - nb).days
                    issuer = "Unknown"
                    if 'issuer' in cert:
                        for item in cert['issuer']:
                             for kv in item:
                                if kv[0] in ['organizationName', 'commonName']:
                                    issuer = kv[1]; break
                    return age, issuer
        except: return -1, "Unknown"

    # --- 3. HÀM TÍNH ENTROPY ---
    def _entropy(self, s):
        if not s: return 0
        prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
        return -sum([p * math.log(p) / math.log(2.0) for p in prob])

    # --- 4. HÀM CHECK FORM & IFRAME ---
    def _check_external_form(self):
        try:
            for form in self.soup.find_all('form'):
                action = form.get('action', '')
                if action.startswith('http') and self.domain not in action: return 1
        except: pass
        return 0

    def _check_hidden_iframe(self):
        try:
            for i in self.soup.find_all('iframe'):
                style = str(i.get('style', '')).lower()
                if 'display:none' in style or 'visibility:hidden' in style or 'width:0' in style: return 1
        except: pass
        return 0

    # --- 5. LOGIC TRÍCH XUẤT CHÍNH ---
    def extract_all_features(self):
        # A. STATIC FEATURES (URL)
        domain_len = len(self.domain)
        path_len = len(self.path) + len(self.query)
        entropy = self._entropy(self.domain)
        
        is_punycode = 1 if 'xn--' in self.domain else 0
        is_risky_tld = 1 if any(self.domain.endswith(t) for t in RISKY_TLDS) else 0

        # B. INFRA FEATURES (SSL)
        ssl_age, ssl_issuer = self.get_ssl_details()
        is_trusted_ssl = 0
        if ssl_issuer != "Unknown":
            if any(t.lower() in str(ssl_issuer).lower() for t in TRUSTED_ISSUERS):
                is_trusted_ssl = 1
                
        # C. CONTENT FEATURES (HTML/DOM)
        dynamic_feats = {
            'Has_External_Form': -1, 'Has_Submit_Button': -1, 'Has_Password_Field': -1,
            'Total_IFrames': -1, 'Has_Hidden_IFrame': -1, 'Right_Click_Disabled': -1,
            'Has_Obfuscated_JS': -1, 'Google_DOM_Signature': -1, 
            'Certificate_Age': -1
        }

        success = self.fetch_html()
        
        if success and self.soup:
            html_content = str(self.soup).lower()
            
            # Check Obfuscated JS
            obfuscation_keywords = ['eval(', 'unescape(', 'atob(', 'document.write(', 'var _0x']
            has_obfuscated_js = 1 if any(k in html_content for k in obfuscation_keywords) else 0

            # Check Right Click
            right_click_disabled = 1 if 'event.button==2' in html_content or 'contextmenu' in html_content else 0

            # Check Google DOM Impersonation
            google_indicators = ['identifierid', 'f29vle', 'headingtext', 'signin/v2/identifier', 'data-initial-dir']
            google_sig_score = 1 if any(ind in html_content for ind in google_indicators) else 0
            
            is_google_impersonation = 0
            if google_sig_score == 1 and 'google.com' not in self.domain and 'youtube.com' not in self.domain:
                is_google_impersonation = 1

            dynamic_feats = {
                'Has_External_Form': self._check_external_form(),
                'Has_Submit_Button': 1 if self.soup.find(['input', 'button'], type=['submit', 'button']) else 0,
                'Has_Password_Field': 1 if self.soup.find('input', type='password') else 0,
                'Total_IFrames': len(self.soup.find_all('iframe')),
                'Has_Hidden_IFrame': self._check_hidden_iframe(),
                'Right_Click_Disabled': right_click_disabled,
                'Has_Obfuscated_JS': has_obfuscated_js,
                'Google_DOM_Signature': is_google_impersonation,
                'Certificate_Age': ssl_age
            }
        else:
            # Nếu không load được web, vẫn giữ giá trị SSL Age nếu lấy được
            dynamic_feats['Certificate_Age'] = ssl_age

        # TỔNG HỢP TOÀN BỘ FEATURE
        static_feats = {
            'Domain_Length': domain_len,
            'Path_Length': path_len,
            'Entropy_Subdomain': entropy,
            'Is_Punycode': is_punycode,
            'Digit_Ratio': sum(c.isdigit() for c in self.url) / len(self.url) if len(self.url) > 0 else 0,
            'Special_Char_Ratio': sum(not c.isalnum() for c in self.url) / len(self.url) if len(self.url) > 0 else 0,
            'Suspicious_TLD': is_risky_tld,
            'Has_IP_Address': 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', self.domain) else 0,
            'Has_Phishing_Keyword': 1 if any(k in self.url.lower() for k in ['login', 'secure', 'account', 'verify', 'update', 'bank', 'confirm']) else 0,
            'Brand_In_Subdomain': 1 if any(b in self.domain for b in BRANDS) else 0,
            'Is_Trusted_Issuer': is_trusted_ssl,
        }

        return {**static_feats, **dynamic_feats}

# ==============================================================================
# HÀM XỬ LÝ ĐA LUỒNG (SỨC MẠNH CỦA HỆ THỐNG)
# ==============================================================================

def process_row(row):
    """Xử lý từng dòng dữ liệu"""
    try:
        url = str(row.get('url', '')).strip()
        label = row.get('label', '')
        
        if not url: return None
        
        # 1. Trích xuất Feature
        extractor = FeatureExtractor(url)
        features = extractor.extract_all_features()
        
        # 2. Xử lý Label (Map text sang số)
        if str(label).lower() == 'bad':
            features['label'] = 1
        else:
            features['label'] = 0
            
        # Giữ URL để debug (Sau này train nhớ drop cột này)
        features['url'] = url
        
        return features
    except Exception:
        return None

def main():
    print(f"🚀 BẮT ĐẦU HỆ THỐNG TRÍCH XUẤT ALL-IN-ONE")
    print(f"   📂 Input:  {INPUT_FILE}")
    print(f"   📂 Output: {OUTPUT_FILE}")
    print(f"   🔥 Threads: {MAX_WORKERS}")
    print("-" * 60)
    
    if not os.path.exists(INPUT_FILE):
        print(f"❌ Lỗi: Không tìm thấy file '{INPUT_FILE}'. Hãy chắc chắn bạn đã chạy bước cân bằng dữ liệu.")
        return

    try:
        df = pd.read_csv(INPUT_FILE)
        print(f"📊 Tổng số URL cần xử lý: {len(df):,}")
    except Exception as e:
        print(f"❌ Lỗi đọc file CSV: {e}")
        return

    data = df.to_dict('records')
    results = []
    
    start_time = time.time()
    processed_count = 0
    total = len(data)

    print(f"⏳ Đang xử lý...")
    
    # Kích hoạt ThreadPool
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_row = {executor.submit(process_row, row): row for row in data}
        
        for future in concurrent.futures.as_completed(future_to_row):
            res = future.result()
            processed_count += 1
            
            if res:
                results.append(res)
            
            # Hiển thị tiến độ real-time
            if processed_count % 50 == 0 or processed_count == total:
                elapsed = time.time() - start_time
                percent = (processed_count / total) * 100
                speed = processed_count / elapsed if elapsed > 0 else 0
                remaining = total - processed_count
                eta = remaining / speed if speed > 0 else 0
                
                sys.stdout.write(f"\r   ▶ Tiến độ: {percent:5.1f}% | ✅ Xong: {processed_count} | ⚡ Tốc độ: {speed:5.1f} url/s | ⏱️ ETA: {eta/60:4.1f} phút")
                sys.stdout.flush()

    print("\n" + "="*60)
    print(f"✅ HOÀN TẤT SAU {time.time() - start_time:.2f} GIÂY")
    print(f"   📥 Thành công: {len(results)}/{total}")
    
    if results:
        final_df = pd.DataFrame(results)
        
        # Đưa cột url, label lên đầu
        cols = list(final_df.columns)
        if 'url' in cols: cols.insert(0, cols.pop(cols.index('url')))
        if 'label' in cols: cols.insert(1, cols.pop(cols.index('label')))
        final_df = final_df[cols]
        
        final_df.to_csv(OUTPUT_FILE, index=False)
        print(f"💾 Đã lưu dữ liệu Training vào: {OUTPUT_FILE}")
        print(f"👉 Sẵn sàng để Train Model!")
    else:
        print("❌ Không có dữ liệu nào được trích xuất.")

if __name__ == "__main__":
    main()
