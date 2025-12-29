"""
========================================
SELENIUM STEALTH FEATURE EXTRACTION
========================================
✅ Undetected Chrome - Bypass bot detection
✅ Cloudflare bypass
✅ JavaScript execution
✅ Human-like behavior
✅ Fallback to requests for speed
========================================

INSTALLATION:
pip install selenium undetected-chromedriver beautifulsoup4
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

# Selenium imports
try:
    import undetected_chromedriver as uc
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    print("⚠️  Selenium not installed. Run: pip install selenium undetected-chromedriver")

warnings.filterwarnings('ignore')

# ==================== CONFIGURATION ====================

INPUT_FILE = 'urldata_balanced.csv'
OUTPUT_FILE = 'dataset_final_train.csv'

CHECKPOINT_FILE = 'checkpoint.json'
CHECKPOINT_DATA = 'checkpoint_data.csv'
LOG_FILE = 'extraction.log'
ERROR_LOG = 'errors.log'

# PERFORMANCE
MAX_WORKERS = 20  # Giảm xuống vì Selenium nặng
BATCH_SIZE = 100  # Giảm batch size
CHECKPOINT_INTERVAL = 100

# STRATEGY SETTINGS
USE_SELENIUM_FOR_FAILED = True  # Dùng Selenium cho URLs fail
SELENIUM_TIMEOUT = 10           # Timeout cho Selenium
REQUESTS_TIMEOUT = 5            # Timeout cho requests
MAX_RETRIES = 2                 # Số lần retry

# SELENIUM POOL
SELENIUM_POOL_SIZE = 5  # Số browser instances

# ==================== LOGGING ====================

def setup_logging():
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

# ==================== SELENIUM DRIVER MANAGER ====================

class SeleniumDriverPool:
    """Pool of Selenium drivers for reuse"""
    
    def __init__(self, pool_size=SELENIUM_POOL_SIZE):
        self.pool_size = pool_size
        self.drivers = []
        self.available = []
        
        if not SELENIUM_AVAILABLE:
            logger.warning("⚠️  Selenium not available")
            return
        
        logger.info(f"🚀 Initializing {pool_size} Selenium drivers...")
        
        for i in range(pool_size):
            try:
                driver = self._create_driver()
                self.drivers.append(driver)
                self.available.append(driver)
                logger.info(f"   ✅ Driver {i+1}/{pool_size} ready")
            except Exception as e:
                logger.error(f"   ❌ Failed to create driver {i+1}: {e}")
        
        logger.info(f"✅ Selenium pool ready with {len(self.drivers)} drivers")
    
    def _create_driver(self):
        """Create undetected Chrome driver"""
        options = uc.ChromeOptions()
        
        # Stealth settings
        options.add_argument('--headless')  # Chạy ẩn
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-blink-features=AutomationControlled')
        options.add_argument('--disable-extensions')
        options.add_argument('--disable-gpu')
        options.add_argument('--disable-notifications')
        options.add_argument('--disable-popup-blocking')
        options.add_argument('--start-maximized')
        
        # User agent rotation
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        ]
        options.add_argument(f'--user-agent={random.choice(user_agents)}')
        
        # Create driver
        driver = uc.Chrome(options=options, version_main=None)
        driver.set_page_load_timeout(SELENIUM_TIMEOUT)
        
        # Execute CDP to hide automation
        driver.execute_cdp_cmd('Network.setUserAgentOverride', {
            "userAgent": driver.execute_script("return navigator.userAgent").replace('Headless', '')
        })
        
        return driver
    
    def get_driver(self):
        """Get available driver from pool"""
        if not self.available:
            # All busy, wait a bit
            time.sleep(0.5)
            if not self.available:
                # Still busy, create temp driver
                return self._create_driver()
        
        return self.available.pop(0)
    
    def return_driver(self, driver):
        """Return driver to pool"""
        if driver in self.drivers:
            self.available.append(driver)
        else:
            # Temp driver, close it
            try:
                driver.quit()
            except:
                pass
    
    def cleanup(self):
        """Close all drivers"""
        logger.info("🧹 Cleaning up Selenium drivers...")
        for driver in self.drivers:
            try:
                driver.quit()
            except:
                pass
        self.drivers.clear()
        self.available.clear()

# Global driver pool
driver_pool = None

# ==================== CHECKPOINT MANAGER ====================

class CheckpointManager:
    def __init__(self, checkpoint_file=CHECKPOINT_FILE, data_file=CHECKPOINT_DATA):
        self.checkpoint_file = checkpoint_file
        self.data_file = data_file
        self.checkpoint = self.load_checkpoint()
    
    def load_checkpoint(self):
        if os.path.exists(self.checkpoint_file):
            try:
                with open(self.checkpoint_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {'processed': 0, 'total': 0, 'processed_urls': []}
    
    def save_checkpoint(self, processed, total, processed_urls, results_df=None):
        checkpoint = {
            'processed': processed,
            'total': total,
            'timestamp': datetime.now().isoformat(),
            'processed_urls': processed_urls[-1000:]
        }
        
        try:
            with open(self.checkpoint_file, 'w') as f:
                json.dump(checkpoint, f, indent=2)
            
            if results_df is not None and len(results_df) > 0:
                results_df.to_csv(self.data_file, index=False)
            
            logger.info(f"💾 Checkpoint: {processed}/{total} URLs")
        except Exception as e:
            logger.error(f"❌ Checkpoint failed: {e}")
    
    def get_processed_urls(self):
        processed = set(self.checkpoint.get('processed_urls', []))
        if os.path.exists(self.data_file):
            try:
                df = pd.read_csv(self.data_file)
                if 'url' in df.columns:
                    processed.update(df['url'].tolist())
            except:
                pass
        return processed
    
    def clear_checkpoint(self):
        try:
            if os.path.exists(self.checkpoint_file):
                os.remove(self.checkpoint_file)
            if os.path.exists(self.data_file):
                os.remove(self.data_file)
        except:
            pass

# ==================== CONSTANTS ====================

RISKY_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.vip']
TRUSTED_ISSUERS = {'Google', 'Microsoft', 'DigiCert', 'Sectigo', 'GlobalSign', 
                   'Amazon', 'Apple', "Let's Encrypt"}
BRANDS = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 
          'vietcombank', 'mbbank', 'shopee', 'lazada']
PHISHING_KEYWORDS = ['login', 'signin', 'verify', 'account', 'secure', 'update']

# ==================== FEATURE EXTRACTOR ====================

class HybridFeatureExtractor:
    """Hybrid: Requests first, Selenium fallback"""
    
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
        self.method_used = "none"
    
    def _entropy(self, text):
        if not text:
            return 0.0
        freq = Counter(text)
        length = len(text)
        return round(-sum((c/length) * math.log2(c/length) for c in freq.values()), 4)
    
    def _get_subdomain(self):
        parts = self.domain.split('.')
        if len(parts) >= 3 and parts[-2] in ['com', 'co', 'net', 'org', 'edu']:
            return '.'.join(parts[:-3]) if len(parts) > 3 else ""
        return '.'.join(parts[:-2]) if len(parts) > 2 else ""
    
    def fetch_html_requests(self):
        """Try with requests first (fast)"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(
                self.url, 
                headers=headers, 
                timeout=REQUESTS_TIMEOUT,
                verify=False,
                allow_redirects=True
            )
            
            if response.status_code == 200:
                self.html = response.text
                self.soup = BeautifulSoup(self.html, 'html.parser')
                self.method_used = "requests"
                return True
        except:
            pass
        return False
    
    def fetch_html_selenium(self):
        """Fallback to Selenium (slower but works)"""
        if not SELENIUM_AVAILABLE or driver_pool is None:
            return False
        
        driver = None
        try:
            driver = driver_pool.get_driver()
            
            # Navigate
            driver.get(self.url)
            
            # Wait for page load
            time.sleep(2)  # Simple wait, hoặc dùng WebDriverWait
            
            # Get HTML
            self.html = driver.page_source
            self.soup = BeautifulSoup(self.html, 'html.parser')
            self.method_used = "selenium"
            
            driver_pool.return_driver(driver)
            return True
            
        except Exception as e:
            logger.debug(f"Selenium failed on {self.url}: {str(e)}")
            if driver:
                driver_pool.return_driver(driver)
            return False
    
    def fetch_html(self):
        """Hybrid: Try requests first, then Selenium"""
        # Try requests first
        if self.fetch_html_requests():
            return True
        
        # Fallback to Selenium if enabled
        if USE_SELENIUM_FOR_FAILED:
            logger.info(f"🔄 Trying Selenium for: {self.url[:50]}...")
            return self.fetch_html_selenium()
        
        return False
    
    def get_ssl_info(self):
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.domain, 443), timeout=2) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    
                    cert_age = (datetime.now() - not_before).days
                    validity = (not_after - not_before).days
                    
                    issuer = "Unknown"
                    if 'issuer' in cert:
                        for item in cert['issuer']:
                            for k, v in item:
                                if k in ['organizationName', 'O', 'commonName', 'CN']:
                                    issuer = v
                                    break
                    
                    return cert_age, validity, issuer
        except:
            return -1, -1, "Unknown"
    
    def extract_all_features(self):
        """Extract 27 features"""
        domain_length = len(self.domain)
        path_length = len(self.path) + len(self.query)
        
        num_dots = self.domain.count('.')
        num_hyphens = self.domain.count('-')
        num_at = self.url.count('@')
        num_slashes = self.url.count('/')
        
        subdomain = self._get_subdomain()
        subdomain_level = subdomain.count('.') + 1 if subdomain else 0
        entropy_subdomain = self._entropy(subdomain)
        
        url_length = len(self.url)
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
        is_trusted_issuer = 1 if cert_issuer != "Unknown" and any(t in cert_issuer for t in TRUSTED_ISSUERS) else 0
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
                'Has_Hidden_IFrame': 1 if any('display:none' in str(i.get('style', '')).lower() 
                    for i in self.soup.find_all('iframe')) else 0,
                'Right_Click_Disabled': 1 if 'contextmenu' in html_lower else 0,
                'Has_Obfuscated_JS': 1 if any(p in html_lower for p in ['eval(', 'atob(']) else 0,
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
            **content_features,
            'Fetch_Method': self.method_used  # Track method used
        }

# ==================== PROCESSOR ====================

def process_row_safe(row):
    try:
        url = str(row.get('url', '')).strip()
        label = row.get('label', '')
        
        if not url:
            return None
        
        extractor = HybridFeatureExtractor(url)
        features = extractor.extract_all_features()
        
        features['label'] = 1 if str(label).lower() in ['bad', '1', 'phishing'] else 0
        
        return features
    except Exception as e:
        error_logger.error(f"Failed: {row.get('url', 'unknown')}: {str(e)}")
        return None

# ==================== MAIN ====================

def main():
    global driver_pool
    
    print("="*80)
    print(" SELENIUM STEALTH FEATURE EXTRACTION ".center(80, "="))
    print("="*80)
    
    # Initialize Selenium pool
    if SELENIUM_AVAILABLE and USE_SELENIUM_FOR_FAILED:
        driver_pool = SeleniumDriverPool(SELENIUM_POOL_SIZE)
    
    checkpoint_mgr = CheckpointManager()
    
    if not os.path.exists(INPUT_FILE):
        logger.error(f"❌ File not found: {INPUT_FILE}")
        return
    
    df = pd.read_csv(INPUT_FILE)
    logger.info(f"✅ Loaded: {len(df):,} URLs")
    
    processed_urls = checkpoint_mgr.get_processed_urls()
    if processed_urls:
        logger.info(f"📂 Resume: {len(processed_urls):,} already done")
        df_todo = df[~df['url'].isin(processed_urls)]
        df_existing = pd.read_csv(checkpoint_mgr.data_file) if os.path.exists(checkpoint_mgr.data_file) else pd.DataFrame()
    else:
        df_todo = df
        df_existing = pd.DataFrame()
    
    if len(df_todo) == 0:
        logger.info("✅ All done!")
        if driver_pool:
            driver_pool.cleanup()
        return
    
    data = df_todo.to_dict('records')
    num_batches = (len(data) + BATCH_SIZE - 1) // BATCH_SIZE
    all_results = []
    
    try:
        for i in range(num_batches):
            batch_data = data[i*BATCH_SIZE:min((i+1)*BATCH_SIZE, len(data))]
            logger.info(f"\n📦 Batch {i+1}/{num_batches}")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {executor.submit(process_row_safe, row): row for row in batch_data}
                for future in tqdm(concurrent.futures.as_completed(futures), total=len(batch_data), leave=False):
                    result = future.result()
                    if result:
                        all_results.append(result)
            
            logger.info(f"   ✅ Success: {len(all_results)}")
            
            if len(all_results) % CHECKPOINT_INTERVAL < BATCH_SIZE:
                df_combined = pd.concat([df_existing, pd.DataFrame(all_results)], ignore_index=True) if len(df_existing) > 0 else pd.DataFrame(all_results)
                checkpoint_mgr.save_checkpoint(len(df_combined), len(df), df_combined['url'].tolist(), df_combined)
    
    except KeyboardInterrupt:
        logger.warning("\n⚠️  Interrupted!")
        if all_results:
            df_combined = pd.concat([df_existing, pd.DataFrame(all_results)], ignore_index=True) if len(df_existing) > 0 else pd.DataFrame(all_results)
            checkpoint_mgr.save_checkpoint(len(df_combined), len(df), df_combined['url'].tolist(), df_combined)
        if driver_pool:
            driver_pool.cleanup()
        return
    
    logger.info("\n✅ COMPLETED!")
    
    final_df = pd.concat([df_existing, pd.DataFrame(all_results)], ignore_index=True) if len(df_existing) > 0 else pd.DataFrame(all_results)
    
    # Reorder columns
    cols = list(final_df.columns)
    for col in ['url', 'label']:
        if col in cols:
            cols.insert(0, cols.pop(cols.index(col)))
    final_df = final_df[cols].drop_duplicates(subset=['url'], keep='first')
    
    # Show stats
    if 'Fetch_Method' in final_df.columns:
        method_stats = final_df['Fetch_Method'].value_counts()
        logger.info(f"\n📊 Fetch Methods:")
        for method, count in method_stats.items():
            logger.info(f"   {method}: {count} URLs")
        final_df = final_df.drop('Fetch_Method', axis=1)
    
    final_df.to_csv(OUTPUT_FILE, index=False)
    logger.info(f"💾 Saved: {OUTPUT_FILE}")
    checkpoint_mgr.clear_checkpoint()
    
    # Cleanup
    if driver_pool:
        driver_pool.cleanup()

if __name__ == "__main__":
    main()
