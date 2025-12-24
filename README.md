import pandas as pd
import numpy as np
import math
import re
import asyncio
import os
from urllib.parse import urlparse
from playwright.async_api import async_playwright

# --- CẤU HÌNH HỆ THỐNG ---
INPUT_FILE = "Dataset_Ready_to_Train.csv" 
OUTPUT_FILE = "Dataset_18_Features_Final.csv"
LOG_FILE = "processed_urls.log"  # Lưu vết các URL đã xong
TOP_1M_FILE = "top-1m.csv"
CONCURRENT_PAGES = 35  # Tối ưu cho RAM 32GB (có thể nâng lên 40 nếu mạng khỏe)

# --- NẠP WHITELIST & LOG ---
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

def calculate_entropy(text):
    if not text: return 0
    p_x = [float(text.count(chr(x))) / len(text) for x in range(256) if text.count(chr(x)) > 0]
    return - sum(p * math.log(p, 2) for p in p_x)

def extract_static(url):
    domain = urlparse(url).netloc.lower()
    return {
        'domainEntropy': calculate_entropy(domain),
        'V23_Entropy_Subdomain': calculate_entropy(domain.split('.')[0]),
        'hasIp': 1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0,
        'numHypRatio': domain.count('-') / len(domain) if len(domain) > 0 else 0,
        'domainLength': len(domain),
        'Subdomain_Level': domain.count('.'),
        'IsHTTPS': 1 if url.startswith('https') else 0,
        'Is_Top_1M_Domain': 1 if (domain in top_1m_set) else 0
    }

async def extract_dynamic(url, label, context, semaphore, log_file_handle):
    static_data = extract_static(url)
    
    # Bypass Playwright nếu là trang uy tín
    if static_data['Is_Top_1M_Domain'] == 1:
        data = {**static_data, 'Outlink_Ratio': 0.0, 'HasExternalFormSubmit': 0, 'HasPasswordField': 0,
                'DomainTitleMatchScore': 1, 'HasSocialNet': 1, 'HasCopyrightInfo': 1, 'HasDescription': 1,
                'V9_Has_Hidden_IFrame': 0, 'V5_TLS_Issuer_Reputation': 1, 'V4_DNS_Volatility_Count': 0, 'label': label}
        log_file_handle.write(f"{url}\n")
        log_file_handle.flush()
        return data

    async with semaphore:
        page = await context.new_page()
        try:
            await page.goto(url, timeout=15000, wait_until="domcontentloaded")
            domain = urlparse(url).netloc.lower()
            content = await page.content()
            
            # Logic nâng cấp
            all_links = await page.query_selector_all('a')
            external = 0
            for l in all_links:
                href = await l.get_attribute('href')
                if href and 'http' in href and domain not in href: external += 1
            
            forms = await page.query_selector_all('form')
            ext_form = 1 if any( (await f.get_attribute('action')) and 'http' in (await f.get_attribute('action')) and domain not in (await f.get_attribute('action')) for f in forms) else 0

            dynamic_data = {
                'Outlink_Ratio': external / len(all_links) if len(all_links) > 0 else 0,
                'HasExternalFormSubmit': ext_form,
                'HasPasswordField': 1 if await page.query_selector('input[type="password"]') else 0,
                'DomainTitleMatchScore': 1 if domain.split('.')[0] in (await page.title()).lower() else 0,
                'HasSocialNet': 1 if any(s in content.lower() for s in ['fb.com', 'facebook', 'twitter']),
                'HasCopyrightInfo': 1 if "©" in content or "copyright" in content.lower() else 0,
                'HasDescription': 1 if await page.query_selector('meta[name="description"]') else 0,
                'V9_Has_Hidden_IFrame': 1 if any(not await f.is_visible() for f in await page.query_selector_all('iframe')) else 0,
                'V5_TLS_Issuer_Reputation': 1, 'V4_DNS_Volatility_Count': 0
            }
        except:
            dynamic_data = {f: 0.5 for f in ['Outlink_Ratio', 'HasExternalFormSubmit', 'HasPasswordField', 'DomainTitleMatchScore', 'HasSocialNet', 'HasCopyrightInfo', 'HasDescription', 'V9_Has_Hidden_IFrame', 'V5_TLS_Issuer_Reputation', 'V4_DNS_Volatility_Count']}
        finally:
            await page.close()
            log_file_handle.write(f"{url}\n")
            log_file_handle.flush()
        
        return {**static_data, **dynamic_data, 'label': label}

async def main():
    processed_urls = load_processed_urls()
    df_all = pd.read_csv(INPUT_FILE)
    # Lọc bỏ những URL đã xử lý
    df = df_all[~df_all['url'].isin(processed_urls)]
    
    print(f"🚀 Tổng cộng: {len(df_all)} link. Đã làm: {len(processed_urls)}. Cần làm tiếp: {len(df)}")

    semaphore = asyncio.Semaphore(CONCURRENT_PAGES)
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        
        # Mở file log ở chế độ append
        with open(LOG_FILE, 'a') as log_handle:
            tasks = []
            for i, row in df.iterrows():
                tasks.append(extract_dynamic(row['url'], row['label'], context, semaphore, log_handle))
                
                if len(tasks) >= CONCURRENT_PAGES or i == df.index[-1]:
                    chunk_results = await asyncio.gather(*tasks)
                    # Ghi vào file CSV ngay lập tức (mode='a' append)
                    res_df = pd.DataFrame(chunk_results)
                    res_df.to_csv(OUTPUT_FILE, mode='a', index=False, header=not os.path.exists(OUTPUT_FILE))
                    tasks = []
                    print(f"✅ Đã lưu checkpoint tại dòng thứ {i+1}")

        await browser.close()

if __name__ == "__main__":
    asyncio.run(main())
