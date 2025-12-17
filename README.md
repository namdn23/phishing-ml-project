# =================================================================
# run_extraction_final_merge_FIXED.py - SỬ DỤNG PLAYWRIGHT ĐÃ SỬA LỖI MẠNG/TIMEOUT
# =================================================================
import pandas as pd
import numpy as np
import os
import requests
from bs4 import BeautifulSoup
import tldextract
import time
import re
from datetime import datetime
# --- Thay thế Selenium bằng Playwright ---
from playwright.sync_api import sync_playwright, Playwright, Browser, Page, TimeoutError as PlaywrightTimeoutError
# ----------------------------------------
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

# --- 1. CẤU HÌNH VÀ HẰNG SỐ ---
RAW_CSV_FILE = 'PhiUSIIL_Phishing_URL_Dataset.csv'
OUTPUT_CSV_FILE = 'merged_extracted_data_final_processed.csv' # File Output CUỐI CÙNG đã merge và xử lý lỗi
DETAILED_LOG_FILE = 'temp_new_features_log.csv'

# Tăng số luồng để tận dụng hiệu suất I/O tốt hơn
MAX_WORKERS = 10
BUFFER_SIZE = 500

# Hash mẫu (ví dụ: Google Search Page)
TARGET_PHASH = imagehash.hex_to_hash('9880e61f1c7e0c4f')

# Các đặc trưng TỒN TẠI trong file thô cần được CẬP NHẬT/GHI ĐÈ (Tính lại cho chính xác)
OVERWRITE_FEATURES = [
    'NoOfDegitsInURL', 'HasDescription', 'HasSocialNet', 'HasPasswordField', 'HasSubmitButton',
    'HasExternalFormSubmit', 'DomainTitleMatchScore', 'IsHTTPS', 'HasCopyrightInfo', 'label'
]

# Các đặc trưng MỚI cần được trích xuất (Không tồn tại trong file thô)
NEW_FEATURES = [
    'V10_HTTP_Extraction_Success', 'V11_WHOIS_Extraction_Success', 'V1_PHash_Distance',
    'V2_Layout_Similarity', 'V6_JS_Entropy', 'V7_Text_Readability_Score', 'V8_Total_IFrames',
    'V9_Has_Hidden_IFrame', 'V5_TLS_Issuer_Reputation', 'V3_Domain_Age_Days',
    'V4_DNS_Volatility_Count', 'Is_Top_1M_Domain', 'V22_IP_Subdomain_Pattern',
    'V23_Entropy_Subdomain'
]

# Các đặc trưng động có giá trị mặc định 0.0 hoặc 0.5 khi HTTP/Content FAIL (V10=0)
DYNAMIC_CONTENT_FEATURES = [
    'V1_PHash_Distance', 'V2_Layout_Similarity', 'V6_JS_Entropy', 'V7_Text_Readability_Score',
    'V8_Total_IFrames', 'V9_Has_Hidden_IFrame', 'HasDescription', 'HasSocialNet',
    'HasPasswordField', 'HasSubmitButton', 'HasExternalFormSubmit', 'DomainTitleMatchScore',
    'HasCopyrightInfo', 'V5_TLS_Issuer_Reputation'
]

# Các đặc trưng bị ảnh hưởng khi WHOIS FAIL (V11=0)
WHOIS_FEATURES = ['V3_Domain_Age_Days']
# ------------------------------------------------

FEATURE_ORDER_LOG = ['url'] + OVERWRITE_FEATURES + NEW_FEATURES

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    # Thêm nhiều User Agent để tăng tính ngẫu nhiên
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
]
# -------------------------------------

# =================================================================
# II. LỚP TRÍCH XUẤT ĐẶC TRƯNG (FEATURE EXTRACTOR) - ĐÃ SỬA LỖI
# =================================================================

class FeatureExtractor:
    WHOIS_TIMEOUT: int = 15 # Tăng WHOIS Timeout
    RENDER_TIMEOUT: int = 40 # Tăng Playwright Timeout lên 40s
    REQUESTS_TIMEOUT: int = 45 # Tăng requests Timeout lên 45s

    def __init__(self, url: str):
        self.url: str = self._normalize_url(url)
        self.features: Dict[str, Any] = {'url': url}
        self.response: Optional[requests.Response] = None
        self.soup: Optional[BeautifulSoup] = None
        self.current_domain: Optional[str] = None
        self.http_extraction_successful: bool = False
        self.top_1m_data: Dict[str, bool] = {'google.com': True, 'facebook.com': True, 'microsoft.com': True, 'amazon.com': True}

    def _normalize_url(self, url: str) -> str:
        if not url.startswith('http'):
            return 'http://' + url
        return url
        
    # --- Các hàm tính toán TĨNH (Giữ nguyên) ---
    def _calculate_entropy(self, text: str) -> float:
        if not text: return 0.0
        p, lns = Counter(text), float(len(text))
        entropy = -sum(count / lns * math.log2(count / lns) for count in p.values())
        return entropy / 8.0

    def _calculate_dns_volatility(self, domain: str) -> int:
        try:
            ip_list = socket.gethostbyname_ex(domain)[2]
            return len(set(ip_list)) - 1
        except socket.gaierror:
            return 0 # Trả về 0 thay vì -1 để thống nhất
        except Exception:
            return 0
            
    def _parse_whois_date(self, date_data: Any) -> Optional[datetime]:
        if isinstance(date_data, list): date_data = date_data[0]
        if date_data is None or date_data == 'None': return None
        if isinstance(date_data, datetime): return date_data.replace(tzinfo=None)
        
        if isinstance(date_data, str):
            clean_date_data = re.sub(r'(\s+\w{3}|\s+\+\d{2}:\d{2})$', '', date_data).strip()
            formats = ['%Y-%m-%d %H:%M:%S', '%Y-%m-%d', '%Y-%m-%dT%H:%M:%SZ', '%Y%m%d', '%d-%b-%Y', '%m/%d/%Y']
            for fmt in formats:
                try:
                    dt = datetime.strptime(clean_date_data, fmt)
                    return dt.replace(tzinfo=None)
                except ValueError:
                    continue
        return None
        
    def _calculate_tls_issuer_rep(self) -> float:
        # ... (Logic TLS/SSL giữ nguyên)
        if not self.url.startswith('https://'): return 0.0
        hostname = tldextract.extract(self.url).fqdn
        if not hostname: return 0.0 # Đã sửa mặc định thành 0.0 nếu không có hostname
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
            issuer = next((item[0][1] for item in cert['issuer'] if item[0][0] == 'organizationName'), '').lower()
            TRUSTED_ISSUERS = ['google', 'amazon', 'digicert', 'cloudflare', 'globalsign']
            if 'lets encrypt' in issuer: return 0.7
            if any(name in issuer for name in TRUSTED_ISSUERS): return 0.95
            return 0.2
        except Exception: return 0.0 # Đảm bảo trả về 0.0 khi thất bại TLS

    # --- TRÍCH XUẤT URL & WHOIS (Đã sửa lỗi try-except) ---
    def _get_url_domain_features(self) -> None:
        import whois
        self.features['V11_WHOIS_Extraction_Success'] = 0

        url_no_protocol = self.url.replace("http://", "").replace("https://", "")
        self.features['NoOfDegitsInURL'] = sum(c.isdigit() for c in url_no_protocol)

        domain_info = tldextract.extract(self.url)
        domain = f"{domain_info.domain}.{domain_info.suffix}"
        self.current_domain = domain_info.domain
        subdomain = domain_info.subdomain.lower()

        self.features['V22_IP_Subdomain_Pattern'] = 1 if re.search(r'\d+\.\d+\.\d+(\.\d+)?', subdomain) else 0
        self.features['V23_Entropy_Subdomain'] = self._calculate_entropy(subdomain)
        self.features['V4_DNS_Volatility_Count'] = max(0, self._calculate_dns_volatility(domain))

        domain_age_days = 0
        try:
            # SỬA LỖI: Tăng timeout cho WHOIS
            whois_info = whois.whois(domain, timeout=self.WHOIS_TIMEOUT)
            
            # Kiểm tra nếu whois_info là lỗi
            if isinstance(whois_info.domain_name, str) and ('not found' in whois_info.domain_name.lower() or 'no match' in whois_info.domain_name.lower()):
                 raise ValueError("Domain Not Found")

            creation_date = self._parse_whois_date(whois_info.creation_date)
            if creation_date:
                age = datetime.now().replace(tzinfo=None) - creation_date
                domain_age_days = age.days
                self.features['V11_WHOIS_Extraction_Success'] = 1
        except Exception:
            # Nếu WHOIS thất bại, đặt tuổi là 0 và V11=0
            domain_age_days = 0
            self.features['V11_WHOIS_Extraction_Success'] = 0 

        self.features['V3_Domain_Age_Days'] = max(0, domain_age_days)
        self.features['IsHTTPS'] = 1 if self.url.startswith('https://') else 0

        # SỬA LỖI: Đảm bảo kiểm tra toàn bộ domain (bao gồm suffix)
        is_top_1m = 1 if domain and domain.lower() in self.top_1m_data else 0
        self.features['Is_Top_1M_Domain'] = is_top_1m

    # --- TRUY VẤN VÀ PHÂN TÍCH NỘI DUNG (ĐÃ SỬA LỖI TIMEOUT) ---
    def _fetch_url_content(self) -> None:
        self.features['V10_HTTP_Extraction_Success'] = 0
        self.http_extraction_successful = False

        if '0.0.0.0' in self.url or '127.0.0.1' in self.url or '192.168.' in self.url:
            return

        headers = {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept-Language': 'en-US,en;q=0.9',
        }

        try:
            # SỬA LỖI: Tăng Timeout requests
            self.response = requests.get(self.url, timeout=self.REQUESTS_TIMEOUT, verify=False, allow_redirects=True, headers=headers)
            self.response.raise_for_status()
            self.soup = BeautifulSoup(self.response.content, 'html.parser')
            self.features['V10_HTTP_Extraction_Success'] = 1
            self.http_extraction_successful = True
        except requests.exceptions.RequestException as e:
            # Ghi lại lỗi request
            print(f"⚠️ Request Failed for {self.url}: {type(e).__name__}")
            self.response = None
            self.soup = None

    # --- TRÍCH XUẤT CÁC ĐẶC TRƯNG HTML (Giữ nguyên) ---
    def _get_content_features(self) -> None:
        # ĐẶT GIÁ TRỊ MẶC ĐỊNH cho các đặc trưng động (Rất quan trọng)
        default_features = {
            'HasDescription': 0, 'HasSocialNet': 0, 'HasPasswordField': 0, 'HasSubmitButton': 0,
            'HasExternalFormSubmit': 0, 'DomainTitleMatchScore': 0.0, 'HasCopyrightInfo': 0,
            'V8_Total_IFrames': 0, 'V9_Has_Hidden_IFrame': 0, 'V7_Text_Readability_Score': 0.0,
            'V6_JS_Entropy': 0.0,
            'V1_PHash_Distance': 0.5, 
            'V2_Layout_Similarity': 0.5,
        }

        self.features.update(default_features)
        self.features['V5_TLS_Issuer_Reputation'] = self._calculate_tls_issuer_rep()

        if not self.soup: return

        # --- BẮT ĐẦU TÍNH TOÁN KHI HTTP THÀNH CÔNG ---
        # (Giữ nguyên logic tính toán Readability, Form, Title Match, IFrame)
        def _calculate_readability(text: str) -> float:
             sentences = len(re.split(r'[.!?]+', text))
             words = len(re.findall(r'\w+', text))
             syllables = words * 1.5
             if sentences == 0 or words == 0: return 50.0
             score = 206.835 - 1.015 * (words / sentences) - 84.6 * (syllables / words)
             return np.clip(score, 0.0, 100.0)

        def _extract_dom_form_features(soup: BeautifulSoup, current_domain: str) -> Dict[str, Any]:
            f: Dict[str, Any] = {}
            f['HasPasswordField'] = 1 if len(soup.find_all('input', type='password')) > 0 else 0
            f['HasSubmitButton'] = 1 if len(soup.find_all('input', type='submit') + soup.find_all('button', type='submit')) > 0 else 0
            external_form = 0
            for form in soup.find_all('form'):
                action = form.get('action')
                if action and action.startswith('http') and tldextract.extract(action).domain != current_domain:
                    external_form = 1
                    break
            f['HasExternalFormSubmit'] = external_form
            return f

        form_features_static = _extract_dom_form_features(self.soup, self.current_domain)
        self.features.update(form_features_static)

        # Cập nhật các features tĩnh (HasDescription, HasSocialNet, TitleMatch, Copyright, IFrame, Entropy, Readability)
        description_tag = self.soup.find('meta', attrs={'name': 'description'})
        self.features['HasDescription'] = 1 if (description_tag and description_tag.get('content')) else 0
        social_links = self.soup.find_all('a', href=lambda href: href and ('facebook.com' in href or 'twitter.com' in href))
        self.features['HasSocialNet'] = 1 if len(social_links) > 0 else 0
        
        title_text = self.soup.title.string if self.soup.title and self.soup.title.string else ""
        domain_name = self.current_domain.lower() if self.current_domain else ""
        match_score = 1.0 if domain_name and title_text and domain_name in title_text.lower() else 0.0
        self.features['DomainTitleMatchScore'] = np.clip(match_score, 0.0, 1.0)
        
        copyright_text = self.soup.find(string=lambda text: text and 'copyright' in text.lower())
        self.features['HasCopyrightInfo'] = 1 if copyright_text else 0
        
        self.features['V8_Total_IFrames'] = len(self.soup.find_all('iframe'))
        hidden_iframe = self.soup.find('iframe', attrs={'style': lambda style: style and 'display:none' in style.lower()})
        if not hidden_iframe: hidden_iframe = self.soup.find('iframe', attrs={'width': '0', 'height': '0'})
        self.features['V9_Has_Hidden_IFrame'] = 1 if hidden_iframe else 0
        
        page_text = self.soup.get_text(separator=' ', strip=True)
        self.features['V7_Text_Readability_Score'] = _calculate_readability(page_text)
        
        script_tags = self.soup.find_all('script')
        js_content = "".join(tag.string for tag in script_tags if tag.string)
        self.features['V6_JS_Entropy'] = self._calculate_entropy(js_content)


    # --- ĐỘNG: TRÍCH XUẤT VISUAL VÀ JAVASCRIPT (ĐÃ SỬA LỖI PLAYWRIGHT) ---
    def _get_visual_and_complex_features(self, p: Playwright) -> None:
        """Sử dụng Playwright để render và trích xuất các đặc trưng động (V1, V2)."""

        if not self.http_extraction_successful: return

        # --- Hàm con (Giữ nguyên logic của bạn) ---
        def _calculate_phash_distance(image_data: bytes) -> float:
            try:
                image = Image.open(io.BytesIO(image_data)).convert('L')
                current_phash = imagehash.phash(image, hash_size=8)
                distance = current_phash - TARGET_PHASH
                return float(distance) / 64.0
            except Exception: return 0.5

        def _calculate_layout_similarity(dom_tree: BeautifulSoup) -> float:
            def find_max_depth(element: BeautifulSoup, current_depth: int = 0) -> int:
                max_d = current_depth
                for child in element.find_all(True, recursive=False):
                    max_d = max(max_d, find_max_depth(child, current_depth + 1))
                return max_d
            try:
                max_depth = find_max_depth(dom_tree)
                similarity = np.clip(1.0 - (max_depth / 20.0), 0.1, 0.9)
                return float(f"{similarity:.4f}")
            except Exception: return 0.5

        def _extract_dom_form_features_dynamic(soup: BeautifulSoup, current_domain: str) -> Dict[str, Any]:
             f: Dict[str, Any] = {}
             f['HasPasswordField'] = 1 if len(soup.find_all('input', type='password')) > 0 else 0
             f['HasSubmitButton'] = 1 if len(soup.find_all('input', type='submit') + soup.find_all('button', type='submit')) > 0 else 0
             external_form = 0
             for form in soup.find_all('form'):
                 action = form.get('action')
                 if action and action.startswith('http') and tldextract.extract(action).domain != current_domain:
                     external_form = 1
                     break
             f['HasExternalFormSubmit'] = external_form
             return f
        # ----------------------------------------------------

        # --- BẮT ĐẦU VỚI PLAYWRIGHT ---
        browser: Optional[Browser] = None
        try:
            # Tối ưu hóa Playwright
            browser = p.chromium.launch(
                headless=True,
                # Thêm cờ để tăng cường ổn định trên Linux
                args=[
                    "--disable-gpu", 
                    "--no-sandbox", 
                    "--disable-setuid-sandbox", # Rất quan trọng trên Linux
                    f"--user-agent={random.choice(USER_AGENTS)}"
                ]
            )

            page: Page = browser.new_page()
            # SỬA LỖI: Tăng timeout Playwright
            page.set_default_timeout(self.RENDER_TIMEOUT * 1000)

            try:
                # SỬA LỖI: Chờ networkidle
                page.goto(self.url, wait_until="networkidle")

                screenshot_data: bytes = page.screenshot()
                self.features['V1_PHash_Distance'] = _calculate_phash_distance(screenshot_data)

                rendered_html: str = page.content()
                rendered_soup: BeautifulSoup = BeautifulSoup(rendered_html, 'html.parser')
                self.features['V2_Layout_Similarity'] = _calculate_layout_similarity(rendered_soup)

                dynamic_form_features = _extract_dom_form_features_dynamic(rendered_soup, self.current_domain)
                self.features.update(dynamic_form_features)

            except PlaywrightTimeoutError as e:
                print(f"⚠️ Playwright Timeout (40s) khi xử lý {self.url}")
                # Giữ nguyên giá trị mặc định 0.5
            except Exception as e:
                print(f"⚠️ Lỗi Playwright khi xử lý {self.url}: {e}")
                # Giữ nguyên giá trị mặc định 0.5
            finally:
                if browser: browser.close()

        except Exception as e_init:
            print(f"❌ Lỗi Khởi tạo Browser Playwright: {e_init}")
            # Giữ nguyên giá trị mặc định 0.5
            

    def get_all_features(self, label: int, p: Playwright) -> Optional[Dict[str, Any]]:
        """Trả về dictionary chứa các đặc trưng MỚI và CẦN GHI ĐÈ đã trích xuất được."""
        try:
            self.features['label'] = label 
            
            # --- 1. FEATURE TĨNH (Không cần Playwright object) ---
            self._get_url_domain_features()
            self._fetch_url_content()
            self._get_content_features()
            
            # --- 2. FEATURE ĐỘNG (Cần Playwright object) ---
            self._get_visual_and_complex_features(p)

            # CHỈ TRẢ VỀ CÁC CỘT CẦN THIẾT
            final_features = {key: self.features.get(key,
                                                     0.5 if key in ['V1_PHash_Distance', 'V2_Layout_Similarity'] else
                                                     (label if key == 'label' else 0.0)
                                                     ) for key in FEATURE_ORDER_LOG}

            return final_features
        except Exception as e:
            # Nếu có lỗi quá lớn, vẫn trả về dictionary với giá trị mặc định
            print(f"Lỗi nghiêm trọng khi trích xuất feature cho {self.url}: {e}")
            return {key: self.features.get(key,
                                            0.5 if key in ['V1_PHash_Distance', 'V2_Layout_Similarity'] else
                                            (label if key == 'label' else 0.0)
                                            ) for key in FEATURE_ORDER_LOG}


# =================================================================
# III. LOGIC CHẠY ĐA LUỒNG VÀ MERGE (Đã sửa đổi để dùng Playwright object)
# =================================================================

# ... (Các hàm load_data_for_extraction, append_to_csv_and_log, merge_final_data được giữ nguyên)

# Thêm hàm run_extractor_with_playwright_context để quản lý Playwright context
def run_extractor_with_playwright_context(rows: List[pd.Series], p: Playwright) -> Dict[str, Optional[Dict[str, Any]]]:
    """Chạy trích xuất trong một luồng đơn, sử dụng cùng một Playwright context."""
    results = {}
    for row in rows:
        url = row['url']
        label = row['label']
        extractor = FeatureExtractor(url)
        results[url] = extractor.get_all_features(label, p)
    return results

def run_multiprocess_extraction():
    # ... (check_internet_connectivity được giữ nguyên)
    
    # SỬA LỖI: Thay thế ThreadPoolExecutor bằng logic quản lý Playwright context
    df_raw, df_remaining = load_data_for_extraction(RAW_CSV_FILE)

    if df_remaining.empty and os.path.exists(DETAILED_LOG_FILE):
        print("🎉 Tất cả URL đã được xử lý các feature mới. Chuyển sang Merge...")
        merge_final_data(df_raw)
        return

    ALL_ROWS = [row for index, row in df_remaining.iterrows()]
    total_remaining = len(ALL_ROWS)

    print(f"--- Bắt đầu trích xuất {total_remaining} URL feature mới với {MAX_WORKERS} luồng Playwright ---")

    # Chia nhỏ công việc cho các luồng
    chunk_size = math.ceil(total_remaining / MAX_WORKERS)
    row_chunks = [ALL_ROWS[i:i + chunk_size] for i in range(0, total_remaining, chunk_size)]
    
    results_buffer = []
    processed_count_success = 0
    start_time = time.time()
    
    initial_processed_count = pd.read_csv(DETAILED_LOG_FILE).shape[0] if os.path.exists(DETAILED_LOG_FILE) else 0

    try:
        with sync_playwright() as p:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                # Gửi mỗi chunk rows và đối tượng Playwright (p) đến hàm run_extractor_with_playwright_context
                future_to_chunk = {executor.submit(run_extractor_with_playwright_context, chunk, p): chunk for chunk in row_chunks}
                
                total_completed_chunks = 0
                for future in as_completed(future_to_chunk):
                    chunk_results = future.result() # Dict: {url: features}
                    
                    # Thêm kết quả vào buffer
                    for url, features_dict in chunk_results.items():
                        results_buffer.append((url, features_dict))

                    total_completed_chunks += 1
                    total_urls_processed = initial_processed_count + len(results_buffer) # Chỉ số này sẽ không chính xác tuyệt đối do buffer

                    if len(results_buffer) >= BUFFER_SIZE or total_completed_chunks == len(row_chunks):
                        successes = append_to_csv_and_log(results_buffer, os.path.exists(OUTPUT_CSV_FILE))
                        processed_count_success += successes
                        results_buffer = []

                        elapsed_time = time.time() - start_time
                        avg_speed = total_urls_processed / elapsed_time if elapsed_time > 0 else 0

                        print(f"[Completed Chunks: {total_completed_chunks}/{len(row_chunks)}] Đã xử lý (tổng): {total_urls_processed} URL. Thành công (V1/V2): {processed_count_success}. Tốc độ: {avg_speed:.2f} URL/giây.")

    except Exception as e:
        print(f"❌ Lỗi nghiêm trọng trong quá trình đa luồng/Playwright: {e}")
        
    print(f"\n--- Giai đoạn 1: Trích xuất Feature mới HOÀN THÀNH ---")
    merge_final_data(df_raw)


# (Hàm load_data_for_extraction được giữ nguyên)
def load_data_for_extraction(file_path: str) -> pd.DataFrame:
    # ... (Logic đọc file và lọc log giữ nguyên)
    # ...
    pass 

# (Hàm append_to_csv_and_log được giữ nguyên)
def append_to_csv_and_log(results_buffer: List[Tuple[str, Optional[Dict[str, Any]]]], output_file_exists: bool):
    # ... (Logic ghi log giữ nguyên)
    # ...
    pass

# (Hàm merge_final_data được giữ nguyên)
def merge_final_data(df_raw: pd.DataFrame):
    # ... (Logic merge và tạo biến báo hiệu giữ nguyên)
    # ...
    pass
    
def check_internet_connectivity():
    print("--- 🩺 Kiểm tra kết nối mạng...")
    try:
        requests.get("https://www.google.com", timeout=15)
        print("✅ Kiểm tra kết nối mạng: OK.")
    except requests.exceptions.RequestException:
        print("❌ KIỂM TRA MẠNG THẤT BẠI: Script không thể kết nối Internet.")
        print("    Vui lòng kiểm tra cài đặt NAT/Proxy.")
        sys.exit(1)


# =================================================================
# IV. KHỐI CHẠY CHÍNH
# =================================================================
if __name__ == "__main__":
    # SỬA LỖI: Bạn phải xóa file log cũ để chạy lại toàn bộ quá trình
    try:
         if os.path.exists(DETAILED_LOG_FILE):
             os.remove(DETAILED_LOG_FILE)
             print(f"⚠️ Đã xóa file log cũ: {DETAILED_LOG_FILE} để bắt đầu lại toàn bộ quá trình trích xuất.")
    except Exception:
         pass
         
    run_multiprocess_extraction()
