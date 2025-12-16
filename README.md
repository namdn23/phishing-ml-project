# =================================================================
# run_extraction_final_merge.py - SỬ DỤNG PLAYWRIGHT
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

MAX_WORKERS = 8
BUFFER_SIZE = 500

# Hash mẫu (ví dụ: Google Search Page)
TARGET_PHASH = imagehash.hex_to_hash('9880e61f1c7e0c4f')

# === ❗ KHAI BÁO PLAYWRIGHT (Không cần đường dẫn Binary) ❗ ===
# ĐÃ LOẠI BỎ CHROME_DRIVER_PATH VÀ CHROME_BINARY_PATH
# =====================================================

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

# --- DANH SÁCH MỚI ĐỂ XỬ LÝ LỖI (QUAN TRỌNG) ---
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

# Thứ tự Output trong file log mới (DETAILED_LOG_FILE)
FEATURE_ORDER_LOG = ['url'] + OVERWRITE_FEATURES + NEW_FEATURES

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
# II. LỚP TRÍCH XUẤT ĐẶC TRƯNG (FEATURE EXTRACTOR) - DÙNG PLAYWRIGHT
# =================================================================

class FeatureExtractor:
    WHOIS_TIMEOUT: int = 5
    RENDER_TIMEOUT: int = 20 # 20 giây cho Playwright

    def __init__(self, url: str):
        self.url: str = self._normalize_url(url)
        self.features: Dict[str, Any] = {'url': url}
        self.response: Optional[requests.Response] = None
        self.soup: Optional[BeautifulSoup] = None
        self.current_domain: Optional[str] = None
        self.http_extraction_successful: bool = False
        self.visual_extraction_successful: bool = False
        # Dữ liệu Top 1M (ví dụ)
        self.top_1m_data: Dict[str, bool] = {'google': True, 'facebook': True, 'microsoft': True}

    def _normalize_url(self, url: str) -> str:
        if not url.startswith('http'):
            return 'http://' + url
        return url

    # --- TĨNH: WHOIS, DNS, TLS (Giữ nguyên) ---
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
        # Chuẩn hóa về [0, 1] (chia cho log2(alphabet_size), giả sử 256 ký tự)
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


    # --- TRÍCH XUẤT URL & WHOIS (Giữ nguyên) ---
    def _get_url_domain_features(self) -> None:
        import whois

        # MỚI: V11_WHOIS_Extraction_Success
        self.features['V11_WHOIS_Extraction_Success'] = 0

        url_no_protocol = self.url.replace("http://", "").replace("https://", "")
        # GHI ĐÈ: NoOfDegitsInURL
        self.features['NoOfDegitsInURL'] = sum(c.isdigit() for c in url_no_protocol)

        domain_info = tldextract.extract(self.url)
        domain = f"{domain_info.domain}.{domain_info.suffix}"
        self.current_domain = domain_info.domain
        subdomain = domain_info.subdomain.lower()

        # MỚI: V22_IP_Subdomain_Pattern, V23_Entropy_Subdomain
        self.features['V22_IP_Subdomain_Pattern'] = 1 if re.search(r'\d+\.\d+\.\d+(\.\d+)?', subdomain) else 0
        self.features['V23_Entropy_Subdomain'] = self._calculate_entropy(subdomain)

        # MỚI: V4_DNS_Volatility_Count
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
            # Nếu WHOIS thất bại, đặt tuổi là 0 (để tránh thiên vị Age, và V11=0 sẽ báo hiệu lỗi)
            domain_age_days = 0
            self.features['V11_WHOIS_Extraction_Success'] = 0 # Ghi rõ ràng V11=0 khi thất bại

        # MỚI: V3_Domain_Age_Days
        self.features['V3_Domain_Age_Days'] = max(0, domain_age_days)

        # GHI ĐÈ: IsHTTPS
        self.features['IsHTTPS'] = 1 if self.url.startswith('https://') else 0

        # MỚI: Is_Top_1M_Domain
        is_top_1m = 1 if self.current_domain and self.current_domain.lower() in self.top_1m_data else 0
        self.features['Is_Top_1M_Domain'] = is_top_1m

    # --- TRUY VẤN VÀ PHÂN TÍCH NỘI DUNG (Giữ nguyên) ---
    def _fetch_url_content(self) -> None:
        # MỚI: V10_HTTP_Extraction_Success
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
            # Tăng Timeout lên 40 giây để xử lý các trang chậm
            self.response = requests.get(self.url, timeout=40, verify=False, allow_redirects=True, headers=headers)
            self.response.raise_for_status()
            self.soup = BeautifulSoup(self.response.content, 'html.parser')
            self.features['V10_HTTP_Extraction_Success'] = 1
            self.http_extraction_successful = True
        except requests.exceptions.RequestException:
            self.response = None
            self.soup = None

    # --- TRÍCH XUẤT CÁC ĐẶC TRƯNG HTML (Giữ nguyên) ---
    def _get_content_features(self) -> None:

        # ĐẶT GIÁ TRỊ MẶC ĐỊNH cho các đặc trưng động có thể bị thiếu (0.0 hoặc 0.5)
        # Nếu V10 = 0, các giá trị này sẽ được giữ lại
        default_features = {
            # GHI ĐÈ
            'HasDescription': 0, 'HasSocialNet': 0, 'HasPasswordField': 0, 'HasSubmitButton': 0,
            'HasExternalFormSubmit': 0, 'DomainTitleMatchScore': 0.0, 'HasCopyrightInfo': 0,
            # MỚI
            'V8_Total_IFrames': 0, 'V9_Has_Hidden_IFrame': 0, 'V7_Text_Readability_Score': 0.0,
            'V6_JS_Entropy': 0.0,
            'V1_PHash_Distance': 0.5, # GIÁ TRỊ MẶC ĐỊNH THẤT BẠI RENDER
            'V2_Layout_Similarity': 0.5, # GIÁ TRỊ MẶC ĐỊNH THẤT BẠI RENDER
        }

        self.features.update(default_features)

        # MỚI: V5_TLS_Issuer_Reputation
        self.features['V5_TLS_Issuer_Reputation'] = self._calculate_tls_issuer_rep()

        if not self.soup:
            return # GIỮ NGUYÊN GIÁ TRỊ MẶC ĐỊNH

        # --- BẮT ĐẦU TÍNH TOÁN KHI HTTP THÀNH CÔNG ---

        def _calculate_readability(text: str) -> float:
            sentences = len(re.split(r'[.!?]+', text))
            words = len(re.findall(r'\w+', text))
            syllables = words * 1.5
            if sentences == 0 or words == 0: return 50.0
            # Flesch-Kincaid Readability Score (đơn giản hóa)
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

        # GHI ĐÈ: HasDescription, HasSocialNet
        description_tag = self.soup.find('meta', attrs={'name': 'description'})
        self.features['HasDescription'] = 1 if (description_tag and description_tag.get('content')) else 0
        social_links = self.soup.find_all('a', href=lambda href: href and ('facebook.com' in href or 'twitter.com' in href))
        self.features['HasSocialNet'] = 1 if len(social_links) > 0 else 0

        # GHI ĐÈ: DomainTitleMatchScore
        title_text = self.soup.title.string if self.soup.title and self.soup.title.string else ""
        domain_name = self.current_domain.lower() if self.current_domain else ""
        match_score = 0.0
        if domain_name and title_text:
            if domain_name in title_text.lower():
                match_score = 1.0
        self.features['DomainTitleMatchScore'] = np.clip(match_score, 0.0, 1.0)

        # GHI ĐÈ: HasCopyrightInfo
        copyright_text = self.soup.find(string=lambda text: text and 'copyright' in text.lower())
        self.features['HasCopyrightInfo'] = 1 if copyright_text else 0

        # MỚI: V8_Total_IFrames, V9_Has_Hidden_IFrame
        self.features['V8_Total_IFrames'] = len(self.soup.find_all('iframe'))
        hidden_iframe = self.soup.find('iframe', attrs={'style': lambda style: style and 'display:none' in style.lower()})
        if not hidden_iframe:
            hidden_iframe = self.soup.find('iframe', attrs={'width': '0', 'height': '0'})
        self.features['V9_Has_Hidden_IFrame'] = 1 if hidden_iframe else 0

        # MỚI: V7_Text_Readability_Score, V6_JS_Entropy
        page_text = self.soup.get_text(separator=' ', strip=True)
        self.features['V7_Text_Readability_Score'] = _calculate_readability(page_text)

        script_tags = self.soup.find_all('script')
        js_content = "".join(tag.string for tag in script_tags if tag.string)
        self.features['V6_JS_Entropy'] = self._calculate_entropy(js_content)


    # --- ĐỘNG: TRÍCH XUẤT VISUAL VÀ JAVASCRIPT (V1, V2) BẰNG PLAYWRIGHT ---
    def _get_visual_and_complex_features(self) -> None:
        """Sử dụng Playwright để render và trích xuất các đặc trưng động (V1, V2)."""

        # Bỏ qua nếu HTTP tĩnh đã thất bại
        if not self.http_extraction_successful:
            return

        # --- Hàm con (Giữ nguyên logic của bạn) ---
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
                # Tìm độ sâu DOM tối đa, chuẩn hóa và trả về (ví dụ: 0.1 đến 0.9)
                max_depth = find_max_depth(dom_tree)
                similarity = np.clip(1.0 - (max_depth / 20.0), 0.1, 0.9)
                return float(f"{similarity:.4f}")
            except Exception:
                return 0.5

        def _extract_dom_form_features_dynamic(soup: BeautifulSoup, current_domain: str) -> Dict[str, Any]:
            f: Dict[str, Any] = {}
            # GHI ĐÈ: HasPasswordField, HasSubmitButton
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
            with sync_playwright() as p:
                # 1. Khởi tạo Trình duyệt (Chromium)
                # Playwright tự động xử lý các cờ cần thiết cho headless mode
                browser = p.chromium.launch(
                    headless=True,
                    args=[
                        "--disable-gpu",
                        "--no-sandbox", # Quan trọng cho môi trường Kali/Linux
                        f"--user-agent={random.choice(USER_AGENTS)}"
                    ]
                )

                # 2. Mở Trang và Tải URL
                page: Page = browser.new_page()
                # Playwright dùng mili giây
                page.set_default_timeout(self.RENDER_TIMEOUT * 1000)

                try:
                    # Chờ cho đến khi mạng không hoạt động (hoặc timeout)
                    # "networkidle" đảm bảo trang web đã load xong nội dung động
                    page.goto(self.url, wait_until="networkidle")
                    self.visual_extraction_successful = True

                    # MỚI: V1_PHash_Distance
                    # Playwright get_screenshot_as_png() thay cho Selenium
                    screenshot_data: bytes = page.screenshot()
                    self.features['V1_PHash_Distance'] = _calculate_phash_distance(screenshot_data)

                    # MỚI: V2_Layout_Similarity
                    rendered_html: str = page.content()
                    rendered_soup: BeautifulSoup = BeautifulSoup(rendered_html, 'html.parser')
                    self.features['V2_Layout_Similarity'] = _calculate_layout_similarity(rendered_soup)

                    # Cập nhật DOM features dựa trên Playwright (Nội dung load sau JS)
                    dynamic_form_features = _extract_dom_form_features_dynamic(rendered_soup, self.current_domain)
                    self.features.update(dynamic_form_features)

                except PlaywrightTimeoutError as e:
                    # Lỗi Timeout
                    print(f"⚠️ Playwright Timeout khi xử lý {self.url} (quá {self.RENDER_TIMEOUT}s): {e}")
                    self.features['V1_PHash_Distance'] = 0.5
                    self.features['V2_Layout_Similarity'] = 0.5
                    pass

                except Exception as e:
                    # Lỗi chung trong quá trình render (ví dụ: Navigation Error, JS Error)
                    print(f"⚠️ Lỗi Playwright khi xử lý {self.url}: {e}")
                    self.features['V1_PHash_Distance'] = 0.5
                    self.features['V2_Layout_Similarity'] = 0.5
                    pass

                finally:
                    if browser: browser.close()

        except Exception as e_init:
            # Lỗi Khởi tạo Playwright (ví dụ: không tìm thấy browser binary)
            print(f"❌ Lỗi Khởi tạo Playwright/Browser: {e_init}")
            # Đảm bảo V1/V2 có giá trị mặc định khi lỗi nặng
            self.features['V1_PHash_Distance'] = 0.5
            self.features['V2_Layout_Similarity'] = 0.5

    def get_all_features(self, label: int) -> Optional[Dict[str, Any]]:
        """Trả về dictionary chứa các đặc trưng MỚI và CẦN GHI ĐÈ đã trích xuất được."""
        try:
            self.features['label'] = label # Đặt label ngay từ đầu

            self._get_url_domain_features()
            self._fetch_url_content()
            self._get_content_features()
            self._get_visual_and_complex_features()


            # CHỈ TRẢ VỀ CÁC CỘT CẦN THIẾT CHO LOG VÀ MERGE
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
# III. LOGIC CHẠY ĐA LUỒNG VÀ MERGE (Giữ nguyên)
# =================================================================

def load_data_for_extraction(file_path: str) -> pd.DataFrame:
    """Đọc dữ liệu thô và lọc bỏ các URL đã được xử lý (dựa trên DETAILED_LOG_FILE)."""
    if not os.path.exists(file_path):
        print(f"❌ Lỗi: Không tìm thấy file CSV: {file_path}")
        return pd.DataFrame()

    ENCODINGS_TO_TRY = ['latin-1', 'utf-8', 'iso-8859-1', 'cp1252']
    df_raw = pd.DataFrame()
    success = False

    for enc in ENCODINGS_TO_TRY:
        try:
            # TẢI TẤT CẢ CÁC CỘT CÓ SẴN
            df_raw = pd.read_csv(file_path, encoding=enc, encoding_errors='ignore')
            success = True
            print(f"✅ Đọc file CSV thô thành công với mã hóa: {enc} (Đã bỏ qua lỗi ký tự).")
            break
        except Exception:
            continue

    if not success:
        print(f"❌ Thất bại: Không thể đọc file CSV với bất kỳ mã hóa nào.")
        return pd.DataFrame()

    df_raw.rename(columns={'URL': 'url'}, inplace=True)
    df_base = df_raw.copy()

    processed_urls = set()
    if os.path.exists(DETAILED_LOG_FILE):
        try:
            # Đọc file log chi tiết (chỉ chứa các feature mới)
            df_log = pd.read_csv(DETAILED_LOG_FILE, usecols=['url'], encoding='utf-8', encoding_errors='ignore')
            processed_urls = set(df_log['url'].astype(str).tolist())
            print(f"✅ Tải log chi tiết thành công: {len(processed_urls)} URL đã được xử lý các feature mới.")

        except Exception as e:
            print(f"⚠️ Cảnh báo: Lỗi khi đọc file log chi tiết {DETAILED_LOG_FILE}. Đang xóa log để bắt đầu lại. Lỗi: {e}")
            try:
                os.remove(DETAILED_LOG_FILE)
            except Exception:
                pass
            processed_urls = set()

    # Lấy các hàng trong df_base mà URL chưa có trong processed_urls
    df_remaining = df_base[~df_base['url'].isin(processed_urls)]

    total_count = len(df_base)
    remaining_count = len(df_remaining)

    if remaining_count < total_count:
        print(f"✅ Đã tải: {total_count} URL. Đã xử lý feature mới: {total_count - remaining_count} URL. Tiếp tục xử lý {remaining_count} URL còn lại.")
    else:
        print(f"✅ Bắt đầu trích xuất feature mới: {total_count} URL cần xử lý.")

    # Trả về df_raw gốc (để merge sau) và df_remaining (để xử lý)
    return df_base, df_remaining


def extract_features_worker(row: pd.Series) -> Optional[Tuple[str, Optional[Dict[str, Any]]]]:
    url = row['url']
    label = row['label']

    extractor = FeatureExtractor(url)

    # Chỉ trích xuất các feature MỚI và CẦN GHI ĐÈ
    result_dict = extractor.get_all_features(label)

    return (url, result_dict)


def append_to_csv_and_log(results_buffer: List[Tuple[str, Optional[Dict[str, Any]]]], output_file_exists: bool):
    successful_log_dicts = []

    for url, features_dict in results_buffer:
        if features_dict:
            # Ghi tất cả các kết quả feature MỚI vào log
            successful_log_dicts.append(features_dict)

    # 1. Ghi chi tiết tất cả các đặc trưng MỚI đã trích xuất vào file LOG (temp_new_features_log.csv)
    if successful_log_dicts:

        df_log = pd.DataFrame(successful_log_dicts, columns=FEATURE_ORDER_LOG)

        log_file_exists = os.path.exists(DETAILED_LOG_FILE)
        log_header = not log_file_exists

        df_log.to_csv(DETAILED_LOG_FILE, mode='a', header=log_header, index=False)

    # Kiểm tra số lượng thành công (chỉ đếm V1, V2 khác 0.5)
    successes = sum(1 for d in successful_log_dicts if round(d.get('V1_PHash_Distance', 0.5), 2) != 0.5 or round(d.get('V2_Layout_Similarity', 0.5), 2) != 0.5)

    return successes


# --- HÀM MERGE ĐƯỢC CẬP NHẬT ĐỂ TẠO BIẾN BÁO HIỆU ---
def merge_final_data(df_raw: pd.DataFrame):
    """Thực hiện merge cuối cùng, xử lý lỗi bằng Biến Báo Hiệu, và lưu kết quả."""
    if not os.path.exists(DETAILED_LOG_FILE):
        print("❌ Lỗi: File log feature mới không tồn tại để merge. Chưa có dữ liệu nào được trích xuất.")
        return

    print("\n--- Bắt đầu giai đoạn 2: Hợp nhất dữ liệu và Xử lý Lỗi (Biến Báo Hiệu) ---")

    # 1. Đọc lại toàn bộ file log feature mới
    df_new_features = pd.read_csv(DETAILED_LOG_FILE, encoding='utf-8', encoding_errors='ignore')

    # 2. Loại bỏ các đặc trưng đã được cập nhật/ghi đè khỏi file thô
    cols_to_drop = [col for col in OVERWRITE_FEATURES if col != 'label']
    df_final = df_raw.drop(columns=cols_to_drop, errors='ignore')

    # 3. Thực hiện merge (Left Join: giữ lại tất cả các hàng từ file thô)
    df_final = pd.merge(df_final, df_new_features, on='url', how='left', suffixes=('_old', '_new'))

    # 4. TẠO BIẾN BÁO HIỆU (INDICATOR VARIABLES)
    print("    -> Áp dụng Biến Báo Hiệu cho các lỗi trích xuất...")

    # Tạo biến báo hiệu cho các lỗi HTTP/Content (V10=0)
    # df_final['V10_HTTP_Extraction_Success'] là cột mới đã được merge
    for col in DYNAMIC_CONTENT_FEATURES:
        indicator_col_name = f'Is_{col}_Missing_V10'
        # Nếu V10 = 0, tức là feature này bị thiếu và được gán giá trị mặc định (0.0 hoặc 0.5)
        df_final[indicator_col_name] = np.where(df_final['V10_HTTP_Extraction_Success'] == 0, 1, 0)

    # Tạo biến báo hiệu cho các lỗi WHOIS (V11=0)
    # df_final['V11_WHOIS_Extraction_Success'] là cột mới đã được merge
    for col in WHOIS_FEATURES:
        indicator_col_name = f'Is_{col}_Missing_V11'
        df_final[indicator_col_name] = np.where(df_final['V11_WHOIS_Extraction_Success'] == 0, 1, 0)

    # 5. Dọn dẹp cột và Lưu file

    # Đảm bảo cột label cuối cùng là cột mới
    df_final.rename(columns={'label_new': 'label'}, inplace=True)
    if 'label_old' in df_final.columns:
          df_final.drop(columns=['label_old'], inplace=True)

    # Loại bỏ các cột *old không cần thiết
    cols_to_keep = [col for col in df_final.columns if not col.endswith('_old')]
    df_final = df_final[cols_to_keep]

    # Ghi ra file cuối cùng
    df_final.to_csv(OUTPUT_CSV_FILE, index=False)
    print(f"✅ Hợp nhất thành công. Kết quả cuối cùng (đã xử lý lỗi) lưu tại: {OUTPUT_CSV_FILE}")


def check_internet_connectivity():
    print("--- 🩺 Kiểm tra kết nối mạng...")
    try:
        requests.get("https://www.google.com", timeout=15)
        print("✅ Kiểm tra kết nối mạng: OK.")
    except requests.exceptions.RequestException:
        print("❌ KIỂM TRA MẠNG THẤT BẠI: Script không thể kết nối Internet.")
        print("    Vui lòng kiểm tra cài đặt NAT/Proxy.")
        sys.exit(1)


def run_multiprocess_extraction():
    check_internet_connectivity()

    df_raw, df_remaining = load_data_for_extraction(RAW_CSV_FILE)

    if df_remaining.empty and os.path.exists(DETAILED_LOG_FILE):
        print("🎉 Tất cả URL đã được xử lý các feature mới. Chuyển sang Merge...")
        merge_final_data(df_raw)
        return

    ALL_ROWS = [row for index, row in df_remaining.iterrows()]
    total_remaining = len(ALL_ROWS)

    print(f"--- Bắt đầu trích xuất {total_remaining} URL feature mới với {MAX_WORKERS} luồng ---")

    results_buffer = []
    processed_count_success = 0
    start_time = time.time()

    # Số lượng URL đã hoàn thành trước đó (tính từ log)
    initial_processed_count = pd.read_csv(DETAILED_LOG_FILE).shape[0] if os.path.exists(DETAILED_LOG_FILE) else 0

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

                elapsed_time = time.time() - start_time
                avg_speed = (i + 1) / elapsed_time if elapsed_time > 0 else 0

                total_complete_log = initial_processed_count + (i + 1)

                print(f"[{i + 1}/{total_remaining}] Đã xử lý (mới): {i + 1} URL. Thành công (V1/V2): {processed_count_success}. Tổng log: {total_complete_log}. Tốc độ: {avg_speed:.2f} URL/giây.")

    print(f"\n--- Giai đoạn 1: Trích xuất Feature mới HOÀN THÀNH ---")
    # Thực hiện merge cuối cùng sau khi tất cả các luồng đã hoàn thành
    merge_final_data(df_raw)

# =================================================================
# IV. KHỐI CHẠY CHÍNH
# =================================================================
if __name__ == "__main__":
    run_multiprocess_extraction()
