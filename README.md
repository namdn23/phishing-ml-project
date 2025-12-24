import pandas as pd
import numpy as np
import math
import re
import asyncio
import os
import time
import random
from urllib.parse import urlparse
from playwright.async_api import async_playwright
from playwright_stealth import stealth_async

# =========================================================
# CẤU HÌNH HỆ THỐNG
# =========================================================
INPUT_FILE = "Dataset_Ready_to_Train.csv"
OUTPUT_FILE = "Dataset_18_Features_Final.csv"
LOG_FILE = "processed_urls.log"
TOP_1M_FILE = "top-1m.csv"
CONCURRENT_PAGES = 35 
TIMEOUT = 20000

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
]

# =========================================================
# CÁC HÀM BỔ TRỢ
# =========================================================
def load_processed_urls():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            return set(line.strip() for line in f)
    return set()

try:
    top_1m_df = pd.read_csv(TOP_1M_FILE, header=None)
    top_1m_set = set(top_1m_df[1].astype(str).str.lower().values)
except:
    top_1m_set = set()
    print("⚠️ Cảnh báo: Không tìm thấy top-1m.csv")

def calculate_entropy(text):
    if not text: return 0
    p_x = [float(text.count(chr(x))) / len(text) for x in range(256) if text.count(chr(x)) > 0]
    return - sum(p * math.log(p, 2) for p in p_x)

def extract_static(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    return {
        'domainEntropy': calculate_entropy(domain),
        'V23_Entropy_Subdomain': calculate_entropy(domain.split('.')[0]),
        'hasIp': 1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0,
        'numHypRatio': domain.count('-') / len(domain) if len(domain) > 0 else 0,
        'domainLength': len(domain),
        'Subdomain_Level': domain.count('.'),
        'IsHTTPS': 1 if url.startswith('https') else 0,
        'Is_Top_1M_Domain': 1 if any(d in top_1m_set for d in [domain, '.'.join(domain.split('.')[-2:])]) else 0
    }

async def intercept_route(route):
    if route.request.resource_type in ["image", "media", "font"]:
        await route.abort()
    else:
        await route.continue()

# =========================================================
# LOGIC TRÍCH XUẤT CHÍNH (SỬA LỖI DÒNG 70)
# =========================================================
async def extract_dynamic(url, label, context, semaphore, log_handle):
    static_data = extract_static(url)
    
    if static_data['Is_Top_1M_Domain'] == 1:
        data = {**static_data, 'Outlink_Ratio': 0.0, 'HasExternalFormSubmit': 0, 'HasPasswordField': 0,
                'DomainTitleMatchScore': 1, 'HasSocialNet': 1, 'HasCopyrightInfo': 1, 'HasDescription': 1,
                'V9_Has_Hidden_IFrame': 0, 'V5_TLS_Issuer_Reputation': 1, 'V4_DNS_Volatility_Count': 0, 'label': label}
        log_handle.write(f"{url}\n")
        return data

    async with semaphore:
        page = await context.new_page()
        await stealth_async(page) 
        await page.route("**/*", intercept_route)
        
        try:
            await page.goto(url, timeout=TIMEOUT, wait_until="domcontentloaded")
            await asyncio.sleep(random.uniform(1, 2))
            
            domain = urlparse(url).netloc.lower()
            content = await page.content()
            title = (await page.title()).lower()

            all_links = await page.query_selector_all('a')
            ext_links = 0
            for l in all_links:
                h = await l.get_attribute('href')
                if h and 'http' in h and domain not in h:
                    ext_links += 1
            
            forms = await page.query_selector_all('form')
            ext_form = 0
            for f in forms:
                act = await f.get_attribute('action')
                if act and 'http' in act and domain not in act:
                    ext_form = 1
                    break

            # --- DÒNG 70 NẰM Ở ĐÂY ---
            # Tôi tách nhỏ logic check social để Python không bị nhầm dấu ngoặc
            social_check = any(s in content.lower() for s in ['facebook', 'twitter', 'linkedin'])
            
            dynamic_data = {
                'Outlink_Ratio': ext_links / len(all_links) if len(all_links) > 0 else 0,
                'HasExternalFormSubmit': ext_form,
                'HasPasswordField': 1 if await page.query_selector('input[type="password"]') else 0,
                'DomainTitleMatchScore': 1 if domain.split('.')[0] in title else 0,
                'HasSocialNet': 1 if social_check else 0,
                'HasCopyrightInfo': 1 if ("©" in content or "copyright" in content.lower()) else 0,
                'HasDescription': 1 if await page.query_selector('meta[name="description"]') else 0,
                'V9_Has_Hidden_IFrame': 1 if any(not await f.is_visible() for f in await page.query_selector_all('iframe')) else 0,
                'V5_TLS_Issuer_Reputation': 1, 
                'V4_DNS_Volatility_Count': 0
            }
        except:
            dynamic_data = {f: 0.5 for f in ['Outlink_Ratio', 'HasExternalFormSubmit', 'HasPasswordField', 'DomainTitleMatchScore', 'HasSocialNet', 'HasCopyrightInfo', 'HasDescription', 'V9_Has_Hidden_IFrame', 'V5_TLS_Issuer_Reputation', 'V4_DNS_Volatility_Count']}
        finally:
            await page.close()
            log_handle.write(f"{url}\n")
            log_handle.flush()
        
        return {**static_data, **dynamic_data, 'label': label}

# =========================================================
# HÀM CHÍNH
# =========================================================
async def main():
    start_time = time.time()
    processed_urls = load_processed_urls()
    
    if not os.path.exists(INPUT_FILE):
        print(f"❌ Không tìm thấy file {INPUT_FILE}")
        return

    df_all = pd.read_csv(INPUT_FILE)
    df_to_do = df_all[~df_all['url'].isin(processed_urls)]
    
    print(f"🚀 Còn lại: {len(df_to_do)} URL")

    semaphore = asyncio.Semaphore(CONCURRENT_PAGES)
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(user_agent=random.choice(USER_AGENTS))
        
        with open(LOG_FILE, 'a') as log_handle:
            tasks = []
            for i, (idx, row) in enumerate(df_to_do.iterrows()):
                tasks.append(extract_dynamic(row['url'], row['label'], context, semaphore, log_handle))
                
                if len(tasks) >= CONCURRENT_PAGES or i == len(df_to_do) - 1:
                    results = await asyncio.gather(*tasks)
                    pd.DataFrame(results).to_csv(OUTPUT_FILE, mode='a', index=False, header=not os.path.exists(OUTPUT_FILE))
                    tasks = []
                    
                    elapsed = time.time() - start_time
                    avg_speed = (i + 1) / elapsed
                    print(f"✅ Đã xong {i+1} URL | Tốc độ: {avg_speed:.2f} URL/s")

        await browser.close()

if __name__ == "__main__":
    asyncio.run(main())
