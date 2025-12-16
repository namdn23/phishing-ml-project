# =================================================================
# run_extraction_final_selenium.py - BẢN CODE ĐÃ SỬA LỖI SELENIUM & ENCODING
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
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service as ChromeService # Cần thiết
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

# Tắt cảnh báo SSL
requests.packages.urllib3.disable_warnings()
sys.dont_write_bytecode = True

# --- 1. CẤU HÌNH VÀ HẰNG SỐ ---
RAW_CSV_FILE = 'PhiUSIIL_Phishing_URL_Dataset.csv'
OUTPUT_CSV_FILE = 'cleaned_extracted_data.csv'
TEMP_LOG_FILE = 'processed_urls_log.txt'
MAX_WORKERS = 8
BUFFER_SIZE = 500

TARGET_PHASH = imagehash.hex_to_hash('9880e61f1c7e0c4f') 

# === ❗ KHAI BÁO ĐƯỜNG DẪN SELENIUM (QUAN TRỌNG) ❗ ===
# Dựa trên ảnh của bạn:
CHROME_DRIVER_PATH = "/usr/local/bin/chromedriver" 
# File Chrome thực thi nằm trong thư mục chrome-linux64/
CHROME_BINARY_PATH = "/usr/local/bin/chrome-linux64/chrome" 
# =====================================================

FEATURE_ORDER: List[str] = [
    'NoOfDegitsInURL', 'HasDescription', 'HasSocialNet', 'HasPasswordField', 'HasSubmitButton',
    'HasExternalFormSubmit', 'DomainTitleMatchScore', 'IsHTTPS', 'HasCopyrightInfo',
    'V10_HTTP_Extraction_Success', 'V11_WHOIS_Extraction_Success', 'V1_PHash_Distance',
    'V2_Layout_Similarity', 'V6_JS_Entropy', 'V7_Text_Readability_Score', 'V8_Total_IFrames',
    'V9_Has_Hidden_IFrame', 'V5_TLS_Issuer_Reputation', 'V3_Domain_Age_Days',
    'V4_DNS_Volatility_Count', 'Is_Top_1M_Domain',
    'V22_IP_Subdomain_Pattern',
    'V23_Entropy_Subdomain',
    'label'
]

# USER-AGENTS CHO NGỤY TRANG BOT
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1'
]
# -------------------------------------

# =================================================================
# II. LỚP TRÍCH XUẤT ĐẶC TRƯNG (FEATURE EXTRACTOR) - LOGIC ĐẦY ĐỦ
# =================================================================

class FeatureExtractor:
    WHOIS_TIMEOUT: int = 5
    RENDER_TIMEOUT: int = 20
    
    def __init__(self, url: str):
        self.url: str = self._normalize_url(url)
        self.features: Dict[str, Any] = {}
        self.response: Optional[requests.Response] = None
        self.soup: Optional[BeautifulSoup] = None
        self.current_domain: Optional[str] = None
        self.http_extraction_successful: bool = False
        self.visual_extraction_successful: bool = False
        self.top_1m_data: Dict[str, bool] = {'google': True, 'facebook': True, 'microsoft': True} 

    def _normalize_url(self, url: str) -> str:
        if not url.startswith('http'):
            return 'http://' + url
        return url

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
            return -1 
        except Exception:
            return 0
            
    def _calculate_tls_issuer_rep(self) -> float:
        if not self.url.startswith('https://'):
            return 0.0

        hostname = tldextract.extract(self.url).fqdn
        if not hostname: return 0.5
            
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

        except socket.gaierror: return 0.0
        except ssl.SSLError: return 0.1
        except TimeoutError: return 0.5
        except Exception: return 0.0

    # --- TĨNH: TRÍCH XUẤT DOMAIN & WHOIS (V3, V4, V11, V22, V23) ---
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
        
        volatility_count = self._calculate_dns_volatility(domain)
        self.features['V4_DNS_Volatility_Count'] = max(0, volatility_count)

        domain_age_days = 0
        try:
            whois_info = whois.whois(domain, timeout=self.WHOIS_TIMEOUT)
            if isinstance(whois_info.domain_name, str) and 'not found' in whois_info.domain_name.lower():
                raise ValueError("Domain not found")

            creation_date = self._parse_whois_date(whois_info.creation_date)
            if creation_date:
                age = datetime.now().replace(tzinfo=None) - creation_date
                domain_age_days = age.days
                self.features['V11_WHOIS_Extraction_Success'] = 1
        except Exception:
            domain_age_days = 3650
            
        self.features['V3_Domain_Age_Days'] = max(0, domain_age_days)
        self.features['IsHTTPS'] = 1 if self.url.startswith('https://') else 0

        is_top_1m = 1 if self.current_domain and self.current_domain.lower() in self.top_1m_data else 0
        self.features['Is_Top_1M_Domain'] = is_top_1m
    
    # --- TĨNH: TRUY VẤN VÀ PHÂN TÍCH NỘI DUNG (V10, V5) ---
    def _fetch_url_content(self) -> None:
        self.features['V10_HTTP_Extraction_Success'] = 0
        self.http_extraction_successful = False

        if '0.0.0.0' in self.url or '127.0.0.1' in self.url or '192.168.' in self.url:
            return
        
        headers = {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': 'https://www.google.com/'
        }
        
        try:
            self.response = requests.get(self.url, timeout=40, verify=False, allow_redirects=True, headers=headers) 
            self.response.raise_for_status()
            self.soup = BeautifulSoup(self.response.content, 'html.parser')
            self.features['V10_HTTP_Extraction_Success'] = 1
            self.http_extraction_successful = True
        except requests.exceptions.RequestException:
            self.response = None
            self.soup = None
    
    # --- TĨNH: TRÍCH XUẤT CÁC ĐẶC TRƯNG HTML ---
    def _get_content_features(self) -> None:
        
        default_features = {
            'HasDescription': 0, 'HasSocialNet': 0, 'HasPasswordField': 0, 'HasSubmitButton': 0,
            'HasExternalFormSubmit': 0, 'DomainTitleMatchScore': 0.0, 'HasCopyrightInfo': 0,
            'V8_Total_IFrames': 0, 'V9_Has_Hidden_IFrame': 0, 'V7_Text_Readability_Score': 0.0,
            'V6_JS_Entropy': 0.0,
        }
        self.features.update(default_features)
        
        self.features['V5_TLS_Issuer_Reputation'] = self._calculate_tls_issuer_rep()

        if not self.soup:
            return
            
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
        
        description_tag = self.soup.find('meta', attrs={'name': 'description'})
        self.features['HasDescription'] = 1 if (description_tag and description_tag.get('content')) else 0
        social_links = self.soup.find_all('a', href=lambda href: href and ('facebook.com' in href or 'twitter.com' in href))
        self.features['HasSocialNet'] = 1 if len(social_links) > 0 else 0
        
        title_text = self.soup.title.string if self.soup.title and self.soup.title.string else ""
        domain_name = self.current_domain.lower() if self.current_domain else ""
        match_score = 0.0
        if domain_name and title_text:
            if domain_name in title_text.lower():
                match_score = 1.0
        self.features['DomainTitleMatchScore'] = np.clip(match_score, 0.0, 1.0)

        copyright_text = self.soup.find(string=lambda text: text and 'copyright' in text.lower())
        self.features['HasCopyrightInfo'] = 1 if copyright_text else 0

        self.features['V8_Total_IFrames'] = len(self.soup.find_all('iframe'))
        hidden_iframe = self.soup.find('iframe', attrs={'style': lambda style: style and 'display:none' in style.lower()})
        if not hidden_iframe:
            hidden_iframe = self.soup.find('iframe', attrs={'width': '0', 'height': '0'})
        self.features['V9_Has_Hidden_IFrame'] = 1 if hidden_iframe else 0

        page_text = self.soup.get_text(separator=' ', strip=True)
        self.features['V7_Text_Readability_Score'] = _calculate_readability(page_text)
        
        script_tags = self.soup.find_all('script')
        js_content = "".join(tag.string for tag in script_tags if tag.string)
        self.features['V6_JS_Entropy'] = self._calculate_entropy(js_content)


    # --- ĐỘNG: TRÍCH XUẤT VISUAL VÀ JAVASCRIPT (V1, V2) BẰNG SELENIUM ---
    def _get_visual_and_complex_features(self) -> None:
        """Sử dụng Selenium để render và trích xuất các đặc trưng động (V1, V2)."""
        
        phash_distance = 0.5
        layout_similarity = 0.5
        self.visual_extraction_successful = False

        if not self.http_extraction_successful:
            self.features['V1_PHash_Distance'] = phash_distance
            self.features['V2_Layout_Similarity'] = layout_similarity
            return
            
        def _calculate_phash_distance(image_data: bytes) -> float:
            try:
                image = Image.open(io.BytesIO(image_data)).convert('L') 
                current_phash = imagehash.phash(image, hash_size=8)
                distance = current_phash - TARGET_PHASH
                return float(distance) / 64.0
            except Exception:
                return 0.5

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
            except Exception:
                return 0.5

        driver = None
        try:
            # 1. Cấu hình Chrome Options
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument(f"user-agent={random.choice(USER_AGENTS)}")
            
            # 2. Cấu hình Đường dẫn Chrome Binary Tường minh (Giải quyết Lỗi 58acdd.png)
            if os.path.exists(CHROME_BINARY_PATH):
                chrome_options.binary_location = CHROME_BINARY_PATH 
            else:
                print(f"Lỗi cấu hình: KHÔNG TÌM THẤY Chrome Binary tại {CHROME_BINARY_PATH}")
                return # Thoát nếu không tìm thấy Chrome

            # 3. Cấu hình ChromeDriver Service Tường minh (Giải quyết Lỗi 582254.png & 58b09d.png)
            if not os.path.exists(CHROME_DRIVER_PATH):
                print(f"Lỗi cấu hình: KHÔNG TÌM THẤY ChromeDriver tại {CHROME_DRIVER_PATH}")
                return # Thoát nếu không tìm thấy ChromeDriver
                
            service = ChromeService(executable_path=CHROME_DRIVER_PATH)
            
            # 4. Khởi tạo WebDriver 
            driver = webdriver.Chrome(service=service, options=chrome_options) 
            driver.set_page_load_timeout(self.RENDER_TIMEOUT)
            
            try:
                driver.get(self.url) 
                self.visual_extraction_successful = True

                # 1. TRÍCH XUẤT V1 (PHash Distance)
                screenshot_data = driver.get_screenshot_as_png()
                phash_distance = _calculate_phash_distance(screenshot_data)

                # 2. TRÍCH XUẤT V2 (Layout Similarity)
                rendered_html = driver.page_source
                rendered_soup = BeautifulSoup(rendered_html, 'html.parser')
                layout_similarity = _calculate_layout_similarity(rendered_soup)
                
                # Cập nhật DOM features dựa trên Selenium 
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
                
                dynamic_form_features = _extract_dom_form_features_dynamic(rendered_soup, self.current_domain)
                self.features.update(dynamic_form_features)


            except Exception as e:
                # In ra lỗi cụ thể nếu quá trình driver.get() thất bại
                print(f"⚠️ Lỗi Selenium khi xử lý {self.url}: {e}")
                pass 

            finally:
                if driver: driver.quit()
        
        except Exception as e_init:
            # In ra lỗi nếu không thể khởi tạo driver (lỗi phổ biến nhất)
            print(f"❌ Lỗi Khởi tạo WebDriver: {e_init}")
                
        self.features['V1_PHash_Distance'] = phash_distance
        self.features['V2_Layout_Similarity'] = layout_similarity

    def get_all_features(self, label: int) -> Optional[np.ndarray]:
        try:
            self._fetch_url_content()
            self._get_url_domain_features()
            self._get_content_features()
            self._get_visual_and_complex_features()
            
            self.features['label'] = label
            
            final_array = np.array([self.features.get(key, 0.0) for key in FEATURE_ORDER])
            
            return final_array
        except Exception:
            return None

# =================================================================
# III. LOGIC CHẠY ĐA LUỒNG VÀ RESUME (Giữ nguyên)
# =================================================================
# ... (Phần load_data_for_extraction, extract_features_worker, append_to_csv_and_log, check_internet_connectivity, run_multiprocess_extraction giữ nguyên)
# -----------------------------------------------------------------

def load_data_for_extraction(file_path: str) -> pd.DataFrame:
    """Đọc dữ liệu thô và lọc bỏ các URL đã được xử lý (dựa trên log)."""
    if not os.path.exists(file_path):
        print(f"❌ Lỗi: Không tìm thấy file CSV: {file_path}")
        return pd.DataFrame()

    ENCODINGS_TO_TRY = ['latin-1', 'utf-8', 'iso-8859-1', 'cp1252']
    df_raw = pd.DataFrame()
    success = False
    
    for enc in ENCODINGS_TO_TRY:
        try:
            df_raw = pd.read_csv(file_path, encoding=enc, encoding_errors='ignore')
            success = True
            print(f"✅ Đọc file CSV thành công với mã hóa: {enc} (Đã bỏ qua lỗi ký tự).")
            break
        except Exception:
            continue
    
    if not success:
        print(f"❌ Thất bại: Không thể đọc file CSV với bất kỳ mã hóa nào. Vui lòng kiểm tra mã hóa file nguồn.")
        return pd.DataFrame()

    COLUMNS_TO_KEEP = ['URL', 'label']
    
    if not all(col in df_raw.columns for col in COLUMNS_TO_KEEP):
        missing_cols = [col for col in COLUMNS_TO_KEEP if col not in df_raw.columns]
        print(f"❌ Lỗi: File CSV nguồn thiếu các cột cần thiết: {missing_cols}")
        return pd.DataFrame()

    df_base = df_raw[COLUMNS_TO_KEEP].copy()
    df_base.rename(columns={'URL': 'url'}, inplace=True)

    processed_urls = set()
    if os.path.exists(TEMP_LOG_FILE):
        try:
            with open(TEMP_LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f: 
                for line in f:
                    url_to_add = line.strip()
                    if url_to_add:
                        processed_urls.add(url_to_add)
            print(f"✅ Tải log thành công. Đã bỏ qua các ký tự hỏng nếu có.")
            
        except Exception as e:
            print(f"⚠️ Cảnh báo: Lỗi nghiêm trọng khi đọc file log {TEMP_LOG_FILE}. Đang xóa log để bắt đầu lại. Lỗi: {e}")
            os.remove(TEMP_LOG_FILE) 
            processed_urls = set()
    
    df_remaining = df_base[~df_base['url'].isin(processed_urls)]
    
    total_count = len(df_base)
    remaining_count = len(df_remaining)
    
    if remaining_count < total_count:
        print(f"✅ Đã tải: {total_count} URL. Đã xử lý: {total_count - remaining_count} URL. Tiếp tục xử lý {remaining_count} URL còn lại.")
    else:
        print(f"✅ Bắt đầu từ đầu: {total_count} URL cần xử lý.")

    return df_remaining

def extract_features_worker(row: pd.Series) -> Optional[Tuple[str, np.ndarray]]:
    url = row['url']
    label = row['label']
    
    extractor = FeatureExtractor(url)
    result_array = extractor.get_all_features(label)
    
    if result_array is not None:
        return (url, result_array)
    else:
        return (url, None)

def append_to_csv_and_log(results_buffer: List[Tuple[str, Optional[np.ndarray]]], file_exists: bool):
    
    successful_results = [res[1] for res in results_buffer if res[1] is not None]
    
    if successful_results:
        df_new = pd.DataFrame(np.vstack(successful_results), columns=FEATURE_ORDER)
        
        header = not file_exists
        df_new.to_csv(OUTPUT_CSV_FILE, mode='a', header=header, index=False)
        
    processed_urls = [res[0] for res in results_buffer]
    
    with open(TEMP_LOG_FILE, 'a', encoding='utf-8') as f: 
        f.write('\n'.join(processed_urls) + '\n')
            
    return len(successful_results)

def check_internet_connectivity():
    print("--- 🩺 Kiểm tra kết nối mạng...")
    try:
        requests.get("https://www.google.com", timeout=15) 
        print("✅ Kiểm tra kết nối mạng: OK.")
    except requests.exceptions.RequestException:
        print("❌ KIỂM TRA MẠNG THẤT BẠI: Script không thể kết nối Internet (HTTP/HTTPS).")
        print("   Vui lòng kiểm tra cài đặt NAT của VMWare.")
        print("   Không thể trích xuất nếu không có mạng.")
        sys.exit(1)


def run_multiprocess_extraction():
    
    check_internet_connectivity()
    
    start_global_time = time.time()
    
    df_remaining = load_data_for_extraction(RAW_CSV_FILE)
    if df_remaining.empty:
        print("🎉 Tất cả URL đã được xử lý xong hoặc không có dữ liệu để xử lý. Kiểm tra file output.")
        return

    ALL_ROWS = [row for index, row in df_remaining.iterrows()]
    total_remaining = len(ALL_ROWS)
    
    print(f"--- Bắt đầu trích xuất {total_remaining} URL còn lại với {MAX_WORKERS} luồng ---")
    
    results_buffer = []
    processed_count_success = 0
    start_time = time.time()
    
    initial_processed_count = pd.read_csv(OUTPUT_CSV_FILE).shape[0] if os.path.exists(OUTPUT_CSV_FILE) else 0

    output_file_exists = os.path.exists(OUTPUT_CSV_FILE)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_row = {executor.submit(extract_features_worker, row): row for row in ALL_ROWS}
        
        for i, future in enumerate(as_completed(future_to_row)):
            
            url, result = future.result()
            results_buffer.append((url, result))
            
            if len(results_buffer) >= BUFFER_SIZE or (i + 1) == total_remaining:
                
                successes = append_to_csv_and_log(results_buffer, output_file_exists)
                processed_count_success += successes
                results_buffer = []

                if not output_file_exists and successes > 0:
                    output_file_exists = True
                    
                elapsed_time = time.time() - start_time
                avg_speed = processed_count_success / elapsed_time if elapsed_time > 0 else 0
                
                total_complete = initial_processed_count + processed_count_success
                
                print(f"[{i + 1}/{total_remaining}] Đã xử lý (mới): {i + 1} URL. Thành công (mới): {processed_count_success}. Tổng cộng: {total_complete}. Tốc độ: {avg_speed:.2f} URL/giây.")
    
    final_elapsed_time = time.time() - start_global_time
    print(f"\n--- TRÍCH XUẤT HOÀN THÀNH ---")
    print(f"Thời gian chạy: {final_elapsed_time:.2f} giây.")
    print(f"Tổng số URL thành công: {total_complete} (Đã bao gồm các lần chạy trước).")
    print(f"File kết quả: {OUTPUT_CSV_FILE}")

# =================================================================
# IV. KHỐI CHẠY CHÍNH
# =================================================================
if __name__ == "__main__":
    run_multiprocess_extraction()
