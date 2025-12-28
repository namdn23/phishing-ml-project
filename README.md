"""
========================================
PHISHING URL DETECTION - FEATURE EXTRACTION SYSTEM
========================================
Version: 2.0 - Production Ready
Features: 27 features tối ưu
Author: Your Name
Date: 2024
========================================
"""

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
from collections import Counter

warnings.filterwarnings('ignore')

# ==================== CONFIGURATION ====================

INPUT_FILE = 'urldata_balanced.csv'      # File đầu vào
OUTPUT_FILE = 'dataset_final_train.csv'  # File output
MAX_WORKERS = 50                         # Số threads
TIMEOUT_REQUEST = 5                      # Timeout fetch HTML (giây)
TIMEOUT_SOCKET = 2                       # Timeout SSL check (giây)

# ==================== CONSTANTS ====================

RISKY_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.vip', 
    '.online', '.club', '.cfd', '.loan', '.click', '.asia', 
    '.ru', '.work', '.cn', '.info', '.biz'
]

TRUSTED_ISSUERS = {
    'Google', 'Microsoft', 'DigiCert', 'Sectigo', 'GlobalSign', 
    'Amazon', 'Apple', 'Entrust', 'GeoTrust', 'Thawte', 
    'GoDaddy', 'VeriSign', 'GTS', "Let's Encrypt", 'Cloudflare'
}

BRANDS = [
    'paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 
    'netflix', 'instagram', 'twitter', 'linkedin', 'dropbox',
    'vietcombank', 'mbbank', 'tpbank', 'techcombank', 'bidv',
    'binance', 'shopee', 'lazada', 'tiki', 'sendo'
]

PHISHING_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'secure', 'update', 
    'banking', 'confirm', 'password', 'suspend', 'locked', 
    'verify', 'validation', 'authenticate', 'credential'
]

# ==================== FEATURE EXTRACTOR CLASS ====================

class FeatureExtractor:
    """
    Feature Extractor với 27 features được tối ưu
    
    Features Groups:
    - URL Structure: 15 features
    - Infrastructure (SSL): 4 features  
    - Content (HTML/DOM): 8 features
    """
    
    def __init__(self, url):
        """Initialize với URL"""
        self.url = str(url).strip()
        
        # Thêm protocol nếu thiếu
        if not self.url.startswith(('http://', 'https://')):
            self.url = 'http://' + self.url
        
        # Parse URL
        try:
            self.parsed = urlparse(self.url)
            self.domain = self.parsed.netloc
            self.path = self.parsed.path
            self.query = self.parsed.query
            self.scheme = self.parsed.scheme
        except:
            self.domain = ""
            self.path = ""
            self.query = ""
            self.scheme = "http"
            
        self.html = None
        self.soup = None
    
    # ========== UTILITY METHODS ==========
    
    def _entropy(self, text):
        """
        Tính Shannon entropy của string
        Entropy cao = random/complex, thường thấy ở phishing
        """
        if not text or len(text) == 0:
            return 0.0
        
        freq = Counter(text)
        length = len(text)
        entropy = -sum((count/length) * math.log2(count/length) 
                      for count in freq.values())
        return round(entropy, 4)
    
    def _get_subdomain(self):
        """
        Trích xuất subdomain từ domain (improved logic)
        Example: 
        - login.paypal.com -> login
        - secure.login.paypal.com -> secure.login
        - shopee.com.vn -> "" (không có subdomain)
        - abc.shopee.com.vn -> abc
        """
        parts = self.domain.split('.')
        
        # Handle special TLDs: .com.vn, .co.uk, .com.au, etc.
        if len(parts) >= 3 and parts[-2] in ['com', 'co', 'net', 'org', 'edu', 'gov', 'ac']:
            # Domain có dạng: xxx.com.vn hoặc xxx.co.uk
            if len(parts) > 3:
                return '.'.join(parts[:-3])  # Bỏ 3 phần cuối
            return ""
        elif len(parts) > 2:
            # Domain thường: xxx.com, xxx.vn
            return '.'.join(parts[:-2])  # Bỏ 2 phần cuối
        
        return ""
    
    # ========== HTML FETCHING ==========
    
    def fetch_html(self):
        """Fetch HTML content từ URL"""
        if self.html:
            return True
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'close',
            }
            
            response = requests.get(
                self.url, 
                headers=headers, 
                timeout=TIMEOUT_REQUEST, 
                verify=False,
                allow_redirects=True
            )
            
            if response.status_code == 200:
                self.html = response.text
                self.soup = BeautifulSoup(self.html, 'html.parser')
                return True
                
        except Exception as e:
            pass
        
        return False
    
    # ========== SSL/CERTIFICATE ==========
    
    def get_ssl_info(self):
        """
        Lấy thông tin SSL certificate
        Returns: (cert_age, validity_period, issuer)
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.domain, 443), 
                                         timeout=TIMEOUT_SOCKET) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Parse dates
                    not_before = datetime.strptime(
                        cert['notBefore'], '%b %d %H:%M:%S %Y %Z'
                    )
                    not_after = datetime.strptime(
                        cert['notAfter'], '%b %d %H:%M:%S %Y %Z'
                    )
                    now = datetime.now()
                    
                    # Calculate metrics
                    cert_age = (now - not_before).days
                    validity_period = (not_after - not_before).days
                    
                    # Extract issuer (improved logic)
                    issuer = "Unknown"
                    if 'issuer' in cert:
                        # Thử các trường có thể chứa issuer name
                        issuer_fields = ['organizationName', 'O', 'commonName', 'CN']
                        
                        for item in cert['issuer']:
                            for key, value in item:
                                if key in issuer_fields and value:
                                    issuer = value
                                    break
                            if issuer != "Unknown":
                                break
                    
                    return cert_age, validity_period, issuer
                    
        except Exception as e:
            return -1, -1, "Unknown"
    
    # ========== CONTENT CHECKS ==========
    
    def _check_external_form(self):
        """Check nếu form submit đến external domain"""
        if not self.soup:
            return 0
        
        try:
            for form in self.soup.find_all('form'):
                action = form.get('action', '').lower()
                
                # Check if action points to external domain
                if action.startswith('http'):
                    if self.domain.lower() not in action:
                        return 1
                        
        except:
            pass
        
        return 0
    
    def _check_hidden_iframe(self):
        """Check iframe ẩn (dấu hiệu phishing)"""
        if not self.soup:
            return 0
        
        try:
            for iframe in self.soup.find_all('iframe'):
                style = str(iframe.get('style', '')).lower()
                width = str(iframe.get('width', ''))
                height = str(iframe.get('height', ''))
                
                # Check hidden patterns
                if any([
                    'display:none' in style,
                    'display: none' in style,
                    'visibility:hidden' in style,
                    'visibility: hidden' in style,
                    width == '0',
                    height == '0',
                    width == '0px',
                    height == '0px'
                ]):
                    return 1
                    
        except:
            pass
        
        return 0
    
    def _check_right_click_disabled(self):
        """Check nếu right-click bị disable"""
        if not self.soup:
            return 0
        
        html_lower = str(self.soup).lower()
        
        patterns = [
            'event.button==2',
            'event.button == 2',
            'contextmenu',
            'oncontextmenu="return false"',
            'oncontextmenu=\'return false\'',
            'document.oncontextmenu'
        ]
        
        return 1 if any(p in html_lower for p in patterns) else 0
    
    def _check_obfuscated_js(self):
        """Check JavaScript obfuscation"""
        if not self.soup:
            return 0
        
        html_lower = str(self.soup).lower()
        
        obf_patterns = [
            'eval(',
            'unescape(',
            'atob(',
            'document.write(',
            'fromcharcode',
            'var _0x',
            'function(_0x',
            'string.fromcharcode'
        ]
        
        return 1 if any(p in html_lower for p in obf_patterns) else 0
    
    def _check_brand_impersonation(self):
        """
        Check giả mạo brand
        Brand xuất hiện trong HTML nhưng không phải domain chính thức
        """
        if not self.soup:
            return 0
        
        html_lower = str(self.soup).lower()
        title = self.soup.find('title')
        title_text = title.get_text().lower() if title else ""
        domain_lower = self.domain.lower()
        
        # Check từng brand
        for brand in BRANDS:
            # Brand xuất hiện trong content hoặc title
            if brand in html_lower or brand in title_text:
                # Nhưng KHÔNG phải domain chính thức
                if not any([
                    domain_lower == f'{brand}.com',
                    domain_lower == f'www.{brand}.com',
                    domain_lower == f'{brand}.vn',
                    domain_lower == f'www.{brand}.vn',
                    domain_lower.endswith(f'.{brand}.com'),
                    domain_lower.endswith(f'.{brand}.vn')
                ]):
                    return 1
        
        return 0
    
    # ========== MAIN EXTRACTION METHOD ==========
    
    def extract_all_features(self):
        """
        Trích xuất TẤT CẢ 27 features
        Returns: dict với tất cả features
        """
        
        # ===== GROUP 1: URL STRUCTURE FEATURES (15) =====
        
        url_length = len(self.url)
        domain_length = len(self.domain)
        path_length = len(self.path) + len(self.query)
        
        # Character counts
        num_dots = self.domain.count('.')
        num_hyphens = self.domain.count('-')
        num_at = self.url.count('@')
        num_slashes = self.url.count('/')
        num_underscores = self.url.count('_')
        
        # Subdomain analysis
        subdomain = self._get_subdomain()
        
        # FIX: Tính subdomain level chính xác
        # Đếm số dots trong subdomain, không phải trong toàn bộ domain
        if subdomain:
            subdomain_level = subdomain.count('.') + 1  # +1 vì subdomain có ít nhất 1 level
        else:
            subdomain_level = 0
        
        # Entropy calculations
        entropy_domain = self._entropy(self.domain)
        entropy_subdomain = self._entropy(subdomain) if subdomain else 0.0
        
        # Character ratios
        num_digits = sum(c.isdigit() for c in self.url)
        digit_ratio = num_digits / url_length if url_length > 0 else 0
        
        special_chars = sum(not c.isalnum() for c in self.url)
        special_char_ratio = special_chars / url_length if url_length > 0 else 0
        
        # Suspicious patterns
        has_ip = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 
                               self.domain) else 0
        is_punycode = 1 if 'xn--' in self.domain else 0
        
        suspicious_tld = 1 if any(self.domain.lower().endswith(tld) 
                                 for tld in RISKY_TLDS) else 0
        
        has_phishing_keyword = 1 if any(kw in self.url.lower() 
                                       for kw in PHISHING_KEYWORDS) else 0
        
        brand_in_subdomain = 0
        subdomain_lower = subdomain.lower()
        for brand in BRANDS:
            if brand in subdomain_lower:
                # Check if NOT legitimate domain
                if not self.domain.lower().endswith(f'{brand}.com') and \
                   not self.domain.lower().endswith(f'{brand}.vn'):
                    brand_in_subdomain = 1
                    break
        
        # ===== GROUP 2: INFRASTRUCTURE FEATURES (4) =====
        
        cert_age, cert_validity, cert_issuer = self.get_ssl_info()
        
        is_trusted_issuer = 0
        if cert_issuer != "Unknown":
            is_trusted_issuer = 1 if any(t.lower() in cert_issuer.lower() 
                                        for t in TRUSTED_ISSUERS) else 0
        
        cert_too_new = 1 if 0 <= cert_age < 30 else 0
        
        # ===== GROUP 3: CONTENT FEATURES (8) =====
        
        # Default values (khi không fetch được HTML)
        content_features = {
            'Has_External_Form': 0,
            'Has_Submit_Button': 0,
            'Has_Password_Field': 0,
            'Total_IFrames': 0,
            'Has_Hidden_IFrame': 0,
            'Right_Click_Disabled': 0,
            'Has_Obfuscated_JS': 0,
            'Brand_Impersonation': 0
        }
        
        # Fetch HTML and extract content features
        if self.fetch_html() and self.soup:
            content_features = {
                'Has_External_Form': self._check_external_form(),
                'Has_Submit_Button': 1 if self.soup.find(
                    ['input', 'button'], 
                    type=['submit', 'button']
                ) else 0,
                'Has_Password_Field': 1 if self.soup.find(
                    'input', 
                    type='password'
                ) else 0,
                'Total_IFrames': len(self.soup.find_all('iframe')),
                'Has_Hidden_IFrame': self._check_hidden_iframe(),
                'Right_Click_Disabled': self._check_right_click_disabled(),
                'Has_Obfuscated_JS': self._check_obfuscated_js(),
                'Brand_Impersonation': self._check_brand_impersonation()
            }
        
        # ===== COMBINE ALL FEATURES =====
        
        all_features = {
            # URL Structure (15)
            'URL': self.url,  # Keep original URL
            'Domain_Length': domain_length,
            'Path_Length': path_length,
            'Num_Dots': num_dots,
            'Num_Hyphens': num_hyphens,
            'Num_At_Symbol': num_at,
            'Num_Slashes': num_slashes,
            'Subdomain_Level': subdomain_level,
            'Entropy_Subdomain': entropy_subdomain,
            'Is_Punycode': is_punycode,
            'Digit_Ratio': round(digit_ratio, 4),
            'Special_Char_Ratio': round(special_char_ratio, 4),
            'Suspicious_TLD': suspicious_tld,
            'Has_IP_Address': has_ip,
            'Has_Phishing_Keyword': has_phishing_keyword,
            'Brand_In_Subdomain': brand_in_subdomain,
            
            # Infrastructure (4)
            'Certificate_Age': cert_age,
            'Certificate_Validity_Days': cert_validity,
            'Cert_Too_New': cert_too_new,
            'Is_Trusted_Issuer': is_trusted_issuer,
            
            # Content (8)
            **content_features
        }
        
        return all_features


# ==================== MULTI-THREADING PROCESSOR ====================

def process_row(row):
    """
    Xử lý 1 dòng dữ liệu
    Returns: dict chứa features + label
    """
    try:
        url = str(row.get('url', '')).strip()
        label = row.get('label', '')
        
        if not url:
            return None
        
        # Extract features
        extractor = FeatureExtractor(url)
        features = extractor.extract_all_features()
        
        # Map label
        if str(label).lower() in ['bad', '1', 'phishing']:
            features['Label'] = 1
        else:
            features['Label'] = 0
        
        return features
        
    except Exception as e:
        return None


# ==================== MAIN EXECUTION ====================

def main():
    """Main execution function"""
    
    print("="*70)
    print(" PHISHING URL DETECTION - FEATURE EXTRACTION SYSTEM ".center(70, "="))
    print("="*70)
    print(f"\n📋 CONFIGURATION:")
    print(f"   📂 Input File:  {INPUT_FILE}")
    print(f"   📂 Output File: {OUTPUT_FILE}")
    print(f"   🔥 Threads:     {MAX_WORKERS}")
    print(f"   ⏱️  Timeout:     {TIMEOUT_REQUEST}s (HTML), {TIMEOUT_SOCKET}s (SSL)")
    print(f"\n📊 FEATURES:")
    print(f"   ├─ URL Structure:    15 features")
    print(f"   ├─ Infrastructure:    4 features")
    print(f"   └─ Content (HTML):    8 features")
    print(f"   TOTAL:               27 features")
    print("-"*70)
    
    # Check input file
    if not os.path.exists(INPUT_FILE):
        print(f"\n❌ ERROR: File '{INPUT_FILE}' not found!")
        print(f"   Please make sure the file exists in the current directory.")
        return
    
    # Load data
    try:
        df = pd.read_csv(INPUT_FILE)
        print(f"\n✅ Loaded dataset: {len(df):,} URLs")
        print(f"   Columns: {list(df.columns)}")
        
        # Check required columns
        if 'url' not in df.columns:
            print(f"\n❌ ERROR: 'url' column not found in dataset!")
            return
            
    except Exception as e:
        print(f"\n❌ ERROR reading CSV: {e}")
        return
    
    # Prepare data
    data = df.to_dict('records')
    results = []
    
    start_time = time.time()
    processed = 0
    total = len(data)
    
    print(f"\n⏳ Starting extraction with {MAX_WORKERS} threads...")
    print("-"*70)
    
    # Multi-threading execution
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_row = {executor.submit(process_row, row): row for row in data}
        
        for future in concurrent.futures.as_completed(future_to_row):
            result = future.result()
            processed += 1
            
            if result:
                results.append(result)
            
            # Progress update
            if processed % 50 == 0 or processed == total:
                elapsed = time.time() - start_time
                percent = (processed / total) * 100
                speed = processed / elapsed if elapsed > 0 else 0
                remaining = total - processed
                eta = remaining / speed if speed > 0 else 0
                
                sys.stdout.write(
                    f"\r   Progress: {percent:5.1f}% | "
                    f"Processed: {processed:,}/{total:,} | "
                    f"Speed: {speed:5.1f} url/s | "
                    f"ETA: {eta/60:4.1f}m | "
                    f"Success: {len(results):,}"
                )
                sys.stdout.flush()
    
    # Final summary
    elapsed_total = time.time() - start_time
    
    print("\n" + "="*70)
    print(" EXTRACTION COMPLETED ".center(70, "="))
    print("="*70)
    print(f"\n⏱️  Total Time:    {elapsed_total:.2f} seconds ({elapsed_total/60:.1f} minutes)")
    print(f"📥 Total Processed: {processed:,} URLs")
    print(f"✅ Successful:     {len(results):,} URLs ({len(results)/total*100:.1f}%)")
    print(f"❌ Failed:         {total - len(results):,} URLs")
    print(f"⚡ Average Speed:  {processed/elapsed_total:.1f} URLs/second")
    
    # Save results
    if results:
        final_df = pd.DataFrame(results)
        
        # Reorder columns (URL, Label first)
        cols = list(final_df.columns)
        if 'URL' in cols:
            cols.insert(0, cols.pop(cols.index('URL')))
        if 'Label' in cols:
            cols.insert(1, cols.pop(cols.index('Label')))
        final_df = final_df[cols]
        
        # Save to CSV
        final_df.to_csv(OUTPUT_FILE, index=False)
        
        print(f"\n💾 Dataset saved to: {OUTPUT_FILE}")
        print(f"📊 Shape: {final_df.shape}")
        print(f"📋 Features: {len(final_df.columns) - 2} (excluding URL, Label)")
        
        # Label distribution
        label_dist = final_df['Label'].value_counts()
        print(f"\n📈 Label Distribution:")
        print(f"   Legitimate (0): {label_dist.get(0, 0):,} URLs")
        print(f"   Phishing (1):   {label_dist.get(1, 0):,} URLs")
        
        # Feature summary
        print(f"\n✨ Feature Summary:")
        print(f"   Sample features extracted:")
        for col in final_df.columns[2:7]:  # Show first 5 features
            print(f"   ├─ {col}")
        print(f"   └─ ... and {len(final_df.columns) - 7} more features")
        
        print(f"\n🎯 Next Step:")
        print(f"   Run model training: python train_model.py")
        print(f"   Remember to drop 'URL' column before training!")
        print(f"   X = df.drop(['URL', 'Label'], axis=1)")
        print(f"   y = df['Label']")
        
    else:
        print(f"\n❌ No data extracted. Please check:")
        print(f"   - Internet connection")
        print(f"   - URL format in input file")
        print(f"   - Firewall/proxy settings")
    
    print("\n" + "="*70)


if __name__ == "__main__":
    main()
