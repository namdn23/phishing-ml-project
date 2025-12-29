"""
========================================
ANTI-BLOCK FEATURE EXTRACTION SYSTEM
========================================
Bypass mechanisms:
✅ Rotating User-Agents (1000+ agents)
✅ Random delays between requests
✅ Retry with exponential backoff
✅ Session management
✅ Header randomization
✅ Proxy support (optional)
✅ Rate limiting protection
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
import json
import logging
import random
from urllib.parse import urlparse
from datetime import datetime
from bs4 import BeautifulSoup
from collections import Counter
from tqdm import tqdm

warnings.filterwarnings('ignore')

# ==================== CONFIGURATION ====================

INPUT_FILE = 'urldata_balanced.csv'
OUTPUT_FILE = 'dataset_final_train.csv'

# CHECKPOINT & LOGGING
CHECKPOINT_FILE = 'checkpoint.json'
CHECKPOINT_DATA = 'checkpoint_data.csv'
LOG_FILE = 'extraction.log'
ERROR_LOG = 'errors.log'

# PERFORMANCE
MAX_WORKERS = 100
BATCH_SIZE = 500
TIMEOUT_REQUEST = 5  # Tăng lên để tránh timeout
TIMEOUT_SOCKET = 2
CHECKPOINT_INTERVAL = 500

# ANTI-BLOCK SETTINGS
ENABLE_RANDOM_DELAY = True      # Random delay giữa requests
MIN_DELAY = 0.1                 # Min delay (seconds)
MAX_DELAY = 0.5                 # Max delay (seconds)
ENABLE_RETRY = True
MAX_RETRIES = 3                 # Retry 3 lần
RETRY_BACKOFF = 2               # Exponential backoff multiplier

# PROXY SETTINGS (optional)
USE_PROXY = False               # Set True nếu có proxy
PROXY_LIST = [                  # List proxy của bạn
    # 'http://proxy1:port',
    # 'http://proxy2:port',
]

# ==================== USER AGENT POOL ====================

USER_AGENTS = [
    # Chrome on Windows
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
    
    # Firefox on Windows
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
    
    # Chrome on Mac
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    
    # Safari on Mac
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    
    # Edge on Windows
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
    
    # Chrome on Linux
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    
    # Mobile browsers
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
]

ACCEPT_LANGUAGES = [
    'en-US,en;q=0.9',
    'en-GB,en;q=0.9',
    'vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7',
    'zh-CN,zh;q=0.9,en;q=0.8',
    'ja-JP,ja;q=0.9,en;q=0.8',
]

# ==================== ANTI-BLOCK HELPERS ====================

def get_random_headers():
    """Generate random headers để bypass detection"""
    return {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': random.choice(ACCEPT_LANGUAGES),
        'Accept-Encoding': 'gzip, deflate, br',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Cache-Control': 'max-age=0',
    }

def random_delay():
    """Random delay để tránh rate limiting"""
    if ENABLE_RANDOM_DELAY:
        time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))

def get_proxy():
    """Get random proxy nếu có"""
    if USE_PROXY and PROXY_LIST:
        proxy = random.choice(PROXY_LIST)
        return {
            'http': proxy,
            'https': proxy
        }
    return None

# ==================== SESSION MANAGER ====================

class SessionManager:
    """Quản lý sessions với retry và backoff"""
    
    def __init__(self):
        self.session = requests.Session()
        # Disable SSL warnings
        requests.packages.urllib3.disable_warnings()
    
    def get_with_retry(self, url, max_retries=MAX_RETRIES):
        """GET request với retry và exponential backoff"""
        
        for attempt in range(max_retries):
            try:
                # Random delay trước mỗi request
                random_delay()
                
                # Random headers
                headers = get_random_headers()
                
                # Get proxy
                proxies = get_proxy()
                
                # Make request
                response = self.session.get(
                    url,
                    headers=headers,
                    timeout=TIMEOUT_REQUEST,
                    verify=False,
                    allow_redirects=True,
                    proxies=proxies
                )
                
                # Check for rate limiting
                if response.status_code == 429:
                    wait_time = RETRY_BACKOFF ** attempt
                    logging.warning(f"Rate limited. Waiting {wait_time}s...")
                    time.sleep(wait_time)
                    continue
                
                # Check for Cloudflare challenge
                if response.status_code == 403 and 'cloudflare' in response.text.lower():
                    logging.warning(f"Cloudflare detected on {url}")
                    # Có thể thêm cloudscraper ở đây
                    continue
                
                if response.status_code == 200:
                    return response
                
                # Other errors - retry with backoff
                if attempt < max_retries - 1:
                    wait_time = RETRY_BACKOFF ** attempt
                    time.sleep(wait_time)
                
            except requests.exceptions.Timeout:
                if attempt < max_retries - 1:
                    logging.warning(f"Timeout on {url}, retry {attempt+1}/{max_retries}")
                    time.sleep(RETRY_BACKOFF ** attempt)
                continue
                
            except requests.exceptions.ConnectionError:
                if attempt < max_retries - 1:
                    logging.warning(f"Connection error on {url}, retry {attempt+1}/{max_retries}")
                    time.sleep(RETRY_BACKOFF ** attempt)
                continue
                
            except Exception as e:
                logging.error(f"Error fetching {url}: {str(e)}")
                break
        
        return None

# Global session manager
session_manager = SessionManager()

# ==================== LOGGING SETUP ====================

def setup_logging():
    """Setup logging system"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE, encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    error_logger = logging.getLogger('error')
    error_handler = logging.FileHandler(ERROR_LOG, encoding='utf-8')
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(logging.Formatter('%(asctime)s [ERROR] %(message)s'))
    error_logger.addHandler(error_handler)
    
    return logging.getLogger(), error_logger

logger, error_logger = setup_logging()

# ==================== CHECKPOINT MANAGER ====================

class CheckpointManager:
    """Quản lý checkpoint và resume"""
    
    def __init__(self, checkpoint_file=CHECKPOINT_FILE, data_file=CHECKPOINT_DATA):
        self.checkpoint_file = checkpoint_file
        self.data_file = data_file
        self.checkpoint = self.load_checkpoint()
    
    def load_checkpoint(self):
        if os.path.exists(self.checkpoint_file):
            try:
                with open(self.checkpoint_file, 'r') as f:
                    checkpoint = json.load(f)
                logger.info(f"📂 Found checkpoint: {checkpoint['processed']} URLs processed")
                return checkpoint
            except Exception as e:
                logger.warning(f"⚠️  Failed to load checkpoint: {e}")
        
        return {
            'processed': 0,
            'total': 0,
            'last_index': 0,
            'start_time': time.time(),
            'processed_urls': []
        }
    
    def save_checkpoint(self, processed, total, last_index, processed_urls, results_df=None):
        checkpoint = {
            'processed': processed,
            'total': total,
            'last_index': last_index,
            'timestamp': datetime.now().isoformat(),
            'start_time': self.checkpoint.get('start_time', time.time()),
            'processed_urls': processed_urls[-1000:]
        }
        
        try:
            with open(self.checkpoint_file, 'w') as f:
                json.dump(checkpoint, f, indent=2)
            
            if results_df is not None and len(results_df) > 0:
                results_df.to_csv(self.data_file, index=False)
            
            logger.info(f"💾 Checkpoint saved: {processed}/{total} URLs")
        except Exception as e:
            logger.error(f"❌ Failed to save checkpoint: {e}")
    
    def get_processed_urls(self):
        processed = set(self.checkpoint.get('processed_urls', []))
        
        if os.path.exists(self.data_file):
            try:
                df = pd.read_csv(self.data_file)
                if 'url' in df.columns:
                    processed.update(df['url'].tolist())
            except Exception as e:
                logger.warning(f"⚠️  Failed to load checkpoint data: {e}")
        
        return processed
    
    def clear_checkpoint(self):
        try:
            if os.path.exists(self.checkpoint_file):
                os.remove(self.checkpoint_file)
            if os.path.exists(self.data_file):
                os.remove(self.data_file)
            logger.info("🗑️  Checkpoint cleared")
        except Exception as e:
            logger.warning(f"⚠️  Failed to clear checkpoint: {e}")

# ==================== CONSTANTS ====================

RISKY_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.vip', 
              '.online', '.club', '.cfd', '.loan', '.click', '.asia', '.ru', '.work', '.cn']

TRUSTED_ISSUERS = {'Google', 'Microsoft', 'DigiCert', 'Sectigo', 'GlobalSign', 
                   'Amazon', 'Apple', 'Entrust', 'GeoTrust', 'Thawte', 
                   'GoDaddy', 'VeriSign', 'GTS', "Let's Encrypt", 'Cloudflare'}

BRANDS = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 
          'netflix', 'vietcombank', 'mbbank', 'tpbank', 'binance', 'shopee', 'lazada', 'tiki']

PHISHING_KEYWORDS = ['login', 'signin', 'verify', 'account', 'secure', 'update', 
                     'banking', 'confirm', 'password', 'suspend', 'locked']

# ==================== FEATURE EXTRACTOR ====================

class AntiBlockFeatureExtractor:
    """Feature extractor với anti-block mechanisms"""
    
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
    
    def _entropy(self, text):
        if not text or len(text) == 0:
            return 0.0
        freq = Counter(text)
        length = len(text)
        return round(-sum((c/length) * math.log2(c/length) for c in freq.values()), 4)
    
    def _get_subdomain(self):
        parts = self.domain.split('.')
        if len(parts) >= 3 and parts[-2] in ['com', 'co', 'net', 'org', 'edu', 'gov', 'ac']:
            if len(parts) > 3:
                return '.'.join(parts[:-3])
            return ""
        elif len(parts) > 2:
            return '.'.join(parts[:-2])
        return ""
    
    def fetch_html(self):
        """Fetch HTML với anti-block"""
        if self.html:
            return True
        
        try:
            # Use session manager với retry
            response = session_manager.get_with_retry(self.url)
            
            if response and response.status_code == 200:
                self.html = response.text
                self.soup = BeautifulSoup(self.html, 'html.parser')
                return True
        except Exception as e:
            logger.debug(f"Failed to fetch {self.url}: {str(e)}")
        
        return False
    
    def get_ssl_info(self):
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.domain, 443), timeout=TIMEOUT_SOCKET) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    now = datetime.now()
                    
                    cert_age = (now - not_before).days
                    validity_period = (not_after - not_before).days
                    
                    issuer = "Unknown"
                    if 'issuer' in cert:
                        for item in cert['issuer']:
                            for key, value in item:
                                if key in ['organizationName', 'O', 'commonName', 'CN'] and value:
                                    issuer = value
                                    break
                            if issuer != "Unknown":
                                break
                    
                    return cert_age, validity_period, issuer
        except:
            return -1, -1, "Unknown"
    
    def extract_all_features(self):
        """Extract all 27 features"""
        url_length = len(self.url)
        domain_length = len(self.domain)
        path_length = len(self.path) + len(self.query)
        
        num_dots = self.domain.count('.')
        num_hyphens = self.domain.count('-')
        num_at = self.url.count('@')
        num_slashes = self.url.count('/')
        
        subdomain = self._get_subdomain()
        subdomain_level = subdomain.count('.') + 1 if subdomain else 0
        entropy_subdomain = self._entropy(subdomain) if subdomain else 0.0
        
        num_digits = sum(c.isdigit() for c in self.url)
        digit_ratio = num_digits / url_length if url_length > 0 else 0
        special_chars = sum(not c.isalnum() for c in self.url)
        special_char_ratio = special_chars / url_length if url_length > 0 else 0
        
        has_ip = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', self.domain) else 0
        is_punycode = 1 if 'xn--' in self.domain else 0
        suspicious_tld = 1 if any(self.domain.lower().endswith(t) for t in RISKY_TLDS) else 0
        has_phishing_keyword = 1 if any(k in self.url.lower() for k in PHISHING_KEYWORDS) else 0
        
        brand_in_subdomain = 0
        for brand in BRANDS:
            if brand in subdomain.lower() and not self.domain.lower().endswith(f'{brand}.com'):
                brand_in_subdomain = 1
                break
        
        cert_age, cert_validity, cert_issuer = self.get_ssl_info()
        is_trusted_issuer = 1 if cert_issuer != "Unknown" and any(t.lower() in cert_issuer.lower() for t in TRUSTED_ISSUERS) else 0
        cert_too_new = 1 if 0 <= cert_age < 30 else 0
        
        content_features = {'Has_External_Form': 0, 'Has_Submit_Button': 0, 'Has_Password_Field': 0,
                          'Total_IFrames': 0, 'Has_Hidden_IFrame': 0, 'Right_Click_Disabled': 0,
                          'Has_Obfuscated_JS': 0, 'Brand_Impersonation': 0}
        
        if self.fetch_html() and self.soup:
            html_lower = str(self.soup).lower()
            content_features = {
                'Has_External_Form': 1 if any(f.get('action', '').startswith('http') and 
                    self.domain.lower() not in f.get('action', '').lower() 
                    for f in self.soup.find_all('form')) else 0,
                'Has_Submit_Button': 1 if self.soup.find(['input', 'button'], type=['submit', 'button']) else 0,
                'Has_Password_Field': 1 if self.soup.find('input', type='password') else 0,
                'Total_IFrames': len(self.soup.find_all('iframe')),
                'Has_Hidden_IFrame': 1 if any('display:none' in str(i.get('style', '')).lower() or 
                    str(i.get('width', '')) == '0' for i in self.soup.find_all('iframe')) else 0,
                'Right_Click_Disabled': 1 if any(p in html_lower for p in ['event.button==2', 'contextmenu']) else 0,
                'Has_Obfuscated_JS': 1 if any(p in html_lower for p in ['eval(', 'atob(', 'unescape(']) else 0,
                'Brand_Impersonation': 1 if any(b in html_lower and not self.domain.lower().endswith(f'{b}.com') 
                    for b in BRANDS) else 0
            }
        
        return {
            'url': self.url,
            'Domain_Length': domain_length, 'Path_Length': path_length,
            'Num_Dots': num_dots, 'Num_Hyphens': num_hyphens, 'Num_At_Symbol': num_at,
            'Num_Slashes': num_slashes, 'Subdomain_Level': subdomain_level,
            'Entropy_Subdomain': entropy_subdomain, 'Is_Punycode': is_punycode,
            'Digit_Ratio': round(digit_ratio, 4), 'Special_Char_Ratio': round(special_char_ratio, 4),
            'Suspicious_TLD': suspicious_tld, 'Has_IP_Address': has_ip,
            'Has_Phishing_Keyword': has_phishing_keyword, 'Brand_In_Subdomain': brand_in_subdomain,
            'Certificate_Age': cert_age, 'Certificate_Validity_Days': cert_validity,
            'Cert_Too_New': cert_too_new, 'Is_Trusted_Issuer': is_trusted_issuer,
            **content_features
        }

# ==================== PROCESSOR ====================

def process_row_safe(row):
    """Process with anti-block"""
    try:
        url = str(row.get('url', '')).strip()
        label = row.get('label', '')
        
        if not url:
            return None
        
        extractor = AntiBlockFeatureExtractor(url)
        features = extractor.extract_all_features()
        
        if str(label).lower() in ['bad', '1', 'phishing']:
            features['label'] = 1
        else:
            features['label'] = 0
        
        return features
    except Exception as e:
        error_logger.error(f"Failed: {row.get('url', 'unknown')}: {str(e)}")
        return None

# ==================== MAIN ====================

def main():
    print("="*80)
    print(" ANTI-BLOCK FEATURE EXTRACTION SYSTEM ".center(80, "="))
    print("="*80)
    
    logger.info("🛡️  Anti-block mechanisms enabled:")
    logger.info(f"   • Random User-Agents: {len(USER_AGENTS)} agents")
    logger.info(f"   • Random delays: {MIN_DELAY}s - {MAX_DELAY}s")
    logger.info(f"   • Retry with backoff: {MAX_RETRIES} attempts")
    logger.info(f"   • Proxy support: {'Enabled' if USE_PROXY else 'Disabled'}")
    
    checkpoint_mgr = CheckpointManager()
    
    if not os.path.exists(INPUT_FILE):
        logger.error(f"❌ File not found: {INPUT_FILE}")
        return
    
    df = pd.read_csv(INPUT_FILE)
    logger.info(f"✅ Loaded: {len(df):,} URLs")
    
    processed_urls = checkpoint_mgr.get_processed_urls()
    if processed_urls:
        logger.info(f"📂 Found {len(processed_urls):,} processed URLs")
        df['url_lower'] = df['url'].str.lower().str.strip()
        processed_lower = {u.lower().strip() for u in processed_urls}
        df_todo = df[~df['url_lower'].isin(processed_lower)].drop('url_lower', axis=1)
        
        df_existing = pd.read_csv(checkpoint_mgr.data_file) if os.path.exists(checkpoint_mgr.data_file) else pd.DataFrame()
    else:
        df_todo = df
        df_existing = pd.DataFrame()
    
    if len(df_todo) == 0:
        logger.info("✅ All done!")
        return
    
    data = df_todo.to_dict('records')
    num_batches = (len(data) + BATCH_SIZE - 1) // BATCH_SIZE
    all_results = []
    start_time = time.time()
    
    try:
        for i in range(num_batches):
            batch_data = data[i*BATCH_SIZE:min((i+1)*BATCH_SIZE, len(data))]
            logger.info(f"\n📦 Batch {i+1}/{num_batches}")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {executor.submit(process_row_safe, row): row for row in batch_data}
                for future in tqdm(concurrent.futures.as_completed(futures), total=len(batch_data), 
                                 desc=f"Batch {i+1}", leave=False):
                    result = future.result()
                    if result:
                        all_results.append(result)
            
            logger.info(f"   ✅ Success: {len(all_results)}/{len(data)}")
            
            if len(all_results) % CHECKPOINT_INTERVAL < BATCH_SIZE:
                df_combined = pd.concat([df_existing, pd.DataFrame(all_results)], ignore_index=True) if len(df_existing) > 0 else pd.DataFrame(all_results)
                checkpoint_mgr.save_checkpoint(len(df_combined), len(df), i*BATCH_SIZE, 
                                             df_combined['url'].tolist(), df_combined)
    
    except KeyboardInterrupt:
        logger.warning("\n⚠️  Interrupted! Saving...")
        if all_results:
            df_combined = pd.concat([df_existing, pd.DataFrame(all_results)], ignore_index=True) if len(df_existing) > 0 else pd.DataFrame(all_results)
            checkpoint_mgr.save_checkpoint(len(df_combined), len(df), len(all_results),
                                         df_combined['url'].tolist(), df_combined)
        return
    
    logger.info("\n✅ COMPLETED!")
    
    final_df = pd.concat([df_existing, pd.DataFrame(all_results)], ignore_index=True) if len(df_existing) > 0 else pd.DataFrame(all_results)
    cols = list(final_df.columns)
    if 'url' in cols:
        cols.insert(0, cols.pop(cols.index('url')))
    if 'label' in cols:
        cols.insert(1, cols.pop(cols.index('label')))
    final_df = final_df[cols].drop_duplicates(subset=['url'], keep='first')
    
    final_df.to_csv(OUTPUT_FILE, index=False)
    logger.info(f"💾 Saved: {OUTPUT_FILE}")
    checkpoint_mgr.clear_checkpoint()

if __name__ == "__main__":
    main()
