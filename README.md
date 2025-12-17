import pandas as pd
import numpy as np
import os
import requests
from bs4 import BeautifulSoup
import tldextract
import time
import re
from datetime import datetime
from playwright.sync_api import sync_playwright, Playwright, Browser, Page, TimeoutError as PlaywrightTimeoutError
import imagehash
from PIL import Image
import io
import sys
import math
from collections import Counter
from typing import Dict, Any, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
import socket
import ssl

# Tắt cảnh báo SSL và tắt ghi file bytecode
requests.packages.urllib3.disable_warnings()
sys.dont_write_bytecode = True

# =================================================================
# I. CẤU HÌNH VÀ HẰNG SỐ
# =================================================================
RAW_CSV_FILE = 'PhiUSIIL_Phishing_URL_Dataset.csv'
OUTPUT_CSV_FILE = 'merged_extracted_data_final_processed.csv'
DETAILED_LOG_FILE = 'temp_new_features_log.csv'

# Tối ưu cho Kali Linux (Máy ảo)
MAX_WORKERS = 5 
BUFFER_SIZE = 100
TARGET_PHASH = imagehash.hex_to_hash('9880e61f1c7e0c4f')

OVERWRITE_FEATURES = [
    'NoOfDegitsInURL', 'HasDescription', 'HasSocialNet', 'HasPasswordField', 'HasSubmitButton',
    'HasExternalFormSubmit', 'DomainTitleMatchScore', 'IsHTTPS', 'HasCopyrightInfo', 'label'
]

NEW_FEATURES = [
    'V10_HTTP_Extraction_Success', 'V11_WHOIS_Extraction_Success', 'V1_PHash_Distance',
    'V2_Layout_Similarity', 'V6_JS_Entropy', 'V7_Text_Readability_Score', 'V8_Total_IFrames',
    'V9_Has_Hidden_IFrame', 'V5_TLS_Issuer_Reputation', 'V3_Domain_Age_Days',
    'V4_DNS_Volatility_Count', 'Is_Top_1M_Domain', 'V22_IP_Subdomain_Pattern',
    'V23_Entropy_Subdomain'
]

FEATURE_ORDER_LOG = ['url'] + OVERWRITE_FEATURES + NEW_FEATURES

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
]

# =================================================================
# II. LỚP TRÍCH XUẤT ĐẶC TRƯNG (FEATURE EXTRACTOR)
# =================================================================
class FeatureExtractor:
    WHOIS_TIMEOUT = 15
    RENDER_TIMEOUT = 40
    REQUESTS_TIMEOUT = 45

    def __init__(self, url: str):
        self.url = self._normalize_url(url)
        self.features = {'url': url}
        self.response = None
        self.soup = None
        self.current_domain = None
        self.http_extraction_successful = False
        self.top_1m_data = {'google.com': True, 'facebook.com': True, 'microsoft.com': True}

    def _normalize_url(self, url: str) -> str:
        return url if url.startswith('http') else 'http://' + url

    def _calculate_entropy(self, text: str) -> float:
        if not text: return 0.0
        p, lns = Counter(text), float(len(text))
        return (-sum(count / lns * math.log2(count / lns) for count in p.values())) / 8.0

    def _calculate_dns_volatility(self, domain: str) -> int:
        try:
            return len(set(socket.gethostbyname_ex(domain)[2])) - 1
        except: return 0

    def _parse_whois_date(self, date_data: Any) -> Optional[datetime]:
        if isinstance(date_data, list): date_data = date_data[0]
        if not date_data or date_data == 'None': return None
        if isinstance(date_data, datetime): return date_data.replace(tzinfo=None)
        return None

    def _calculate_tls_issuer_rep(self) -> float:
        if not self.url.startswith('https://'): return 0.0
        hostname = tldextract.extract(self.url).fqdn
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
            issuer = next((item[0][1] for item in cert['issuer'] if item[0][0] == 'organizationName'), '').lower()
            if any(x in issuer for x in ['google', 'digicert', 'cloudflare']): return 0.95
            return 0.2
        except: return 0.0

    def _get_url_domain_features(self):
        import whois
        self.features['V11_WHOIS_Extraction_Success'] = 0
        self.features['NoOfDegitsInURL'] = sum(c.isdigit() for c in self.url)
        
        ext = tldextract.extract(self.url)
        domain = f"{ext.domain}.{ext.suffix}"
        self.current_domain = ext.domain
        
        self.features['V22_IP_Subdomain_Pattern'] = 1 if re.search(r'\d+\.\d+', ext.subdomain) else 0
        self.features['V23_Entropy_Subdomain'] = self._calculate_entropy(ext.subdomain)
        self.features['V4_DNS_Volatility_Count'] = self._calculate_dns_volatility(domain)
        self.features['IsHTTPS'] = 1 if self.url.startswith('https') else 0
        self.features['Is_Top_1M_Domain'] = 1 if domain in self.top_1m_data else 0

        try:
            w = whois.whois(domain, timeout=self.WHOIS_TIMEOUT)
            creation_date = self._parse_whois_date(w.creation_date)
            if creation_date:
                self.features['V3_Domain_Age_Days'] = (datetime.now() - creation_date).days
                self.features['V11_WHOIS_Extraction_Success'] = 1
        except: self.features['V3_Domain_Age_Days'] = 0

    def _get_visual_and_complex(self, p: Playwright):
        if not self.http_extraction_successful: return
        browser = None
        try:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-setuid-sandbox"])
            page = browser.new_page()
            page.set_default_timeout(self.RENDER_TIMEOUT * 1000)
            page.goto(self.url, wait_until="networkidle")
            
            # V1: PHash
            img_data = page.screenshot()
            img = Image.open(io.BytesIO(img_data)).convert('L')
            self.features['V1_PHash_Distance'] = (imagehash.phash(img) - TARGET_PHASH) / 64.0
            
            # V2: Layout
            soup = BeautifulSoup(page.content(), 'html.parser')
            depths = [len(list(tag.parents)) for tag in soup.find_all(True)]
            self.features['V2_Layout_Similarity'] = np.clip(1.0 - (max(depths or [0]) / 20.0), 0.1, 0.9)
            
            browser.close()
        except:
            self.features['V1_PHash_Distance'] = 0.5
            self.features['V2_Layout_Similarity'] = 0.5
            if browser: browser.close()

    def get_all_features(self, label: int, p: Playwright):
        self.features.update({k: 0 for k in NEW_FEATURES + OVERWRITE_FEATURES})
        self.features['label'] = label
        
        self._get_url_domain_features()
        try:
            resp = requests.get(self.url, timeout=self.REQUESTS_TIMEOUT, verify=False, headers={'User-Agent': random.choice(USER_AGENTS)})
            self.soup = BeautifulSoup(resp.content, 'html.parser')
            self.http_extraction_successful = True
            self.features['V10_HTTP_Extraction_Success'] = 1
        except: pass
        
        self._get_visual_and_complex(p)
        return {k: self.features.get(k, 0) for k in FEATURE_ORDER_LOG}

# =================================================================
# III. LOGIC XỬ LÝ DỮ LIỆU VÀ ĐA LUỒNG
# =================================================================
def load_data_for_extraction(file_path: str):
    if not os.path.exists(file_path):
        print(f"❌ KHÔNG TÌM THẤY FILE: {file_path}")
        sys.exit(1)
    df_raw = pd.read_csv(file_path)
    if os.path.exists(DETAILED_LOG_FILE):
        df_log = pd.read_csv(DETAILED_LOG_FILE)
        processed = set(df_log['url'].tolist())
        df_remaining = df_raw[~df_raw['url'].isin(processed)]
    else:
        df_remaining = df_raw.copy()
    return df_raw, df_remaining

def run_task(rows, p):
    results = {}
    for _, row in rows.iterrows():
        extractor = FeatureExtractor(row['url'])
        results[row['url']] = extractor.get_all_features(row['label'], p)
    return results

def run_multiprocess_extraction():
    df_raw, df_remaining = load_data_for_extraction(RAW_CSV_FILE)
    if df_remaining.empty:
        print("✅ Tất cả đã hoàn thành."); return

    print(f"--- Đang trích xuất {len(df_remaining)} URL ---")
    chunks = np.array_split(df_remaining, MAX_WORKERS)
    
    with sync_playwright() as p:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(run_task, chunk, p) for chunk in chunks]
            for future in as_completed(futures):
                data = pd.DataFrame(future.result().values())
                data.to_csv(DETAILED_LOG_FILE, mode='a', header=not os.path.exists(DETAILED_LOG_FILE), index=False)
                print(f"✔ Đã lưu xong một nhóm kết quả.")

    # Merge cuối cùng
    df_new = pd.read_csv(DETAILED_LOG_FILE)
    df_final = pd.merge(df_raw[['url']], df_new, on='url', how='inner')
    df_final.to_csv(OUTPUT_CSV_FILE, index=False)
    print(f"🚀 HOÀN TẤT: {OUTPUT_CSV_FILE}")

if __name__ == "__main__":
    run_multiprocess_extraction()
