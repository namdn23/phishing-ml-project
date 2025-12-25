#!/usr/bin/env python3
"""
URL Feature Extractor v33
✔ 26 FEATURES + label
✔ URL-based logic (NO layout / JS heavy)
✔ Multithread
✔ Checkpoint + Resume
✔ ETA realtime
"""

import os
import re
import ssl
import time
import json
import math
import socket
import hashlib
import threading
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd
import requests
import whois
from bs4 import BeautifulSoup
from tqdm import tqdm

# ===================== CONFIG =====================

MAX_WORKERS = min(32, (os.cpu_count() or 8) * 4)
TIMEOUT = 6
CHECKPOINT_INTERVAL = 500
OUTPUT_DIR = "checkpoints"
os.makedirs(OUTPUT_DIR, exist_ok=True)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "link", "live", "rest",
    "country", "stream", "gq", "tk", "ml", "cf", "ga"
}

BRANDS = [
    "google", "facebook", "paypal", "amazon", "apple",
    "microsoft", "netflix", "instagram", "twitter",
    "linkedin", "github", "adobe", "ebay"
]

# ===================== RATE LIMITER =====================

class RateLimiter:
    def __init__(self, interval):
        self.interval = interval
        self.lock = threading.Lock()
        self.last = 0.0

    def wait(self):
        with self.lock:
            dt = time.time() - self.last
            if dt < self.interval:
                time.sleep(self.interval - dt)
            self.last = time.time()

http_rl = RateLimiter(1 / 20)
whois_rl = RateLimiter(1 / 5)
ssl_rl = RateLimiter(1 / 40)

# ===================== CHECKPOINT =====================

class CheckpointManager:
    def __init__(self, input_file):
        h = hashlib.md5(input_file.encode()).hexdigest()[:8]
        self.ckpt = f"{OUTPUT_DIR}/ckpt_{h}.json"
        self.resf = f"{OUTPUT_DIR}/res_{h}.csv"
        self.lock = threading.Lock()
        self.done = set()
        self.results = []

        if os.path.exists(self.ckpt):
            self._load()

    def _load(self):
        with open(self.ckpt) as f:
            self.done = set(json.load(f)["done"])
        if os.path.exists(self.resf):
            self.results = pd.read_csv(self.resf).to_dict("records")

    def add(self, idx, row):
        with self.lock:
            self.done.add(idx)
            self.results.append(row)

    def save(self):
        with self.lock:
            with open(self.ckpt, "w") as f:
                json.dump({"done": list(self.done)}, f)
            pd.DataFrame(self.results).to_csv(self.resf, index=False)

    def clear(self):
        if os.path.exists(self.ckpt):
            os.remove(self.ckpt)
        if os.path.exists(self.resf):
            os.remove(self.resf)

# ===================== URL HELPERS =====================

def parse_url(url):
    p = urlparse(url)
    domain = p.netloc.lower()
    parts = domain.split(".")
    return {
        "url": url,
        "domain": domain,
        "subdomain": ".".join(parts[:-2]) if len(parts) > 2 else "",
        "main": parts[-2] if len(parts) >= 2 else "",
        "tld": parts[-1] if parts else "",
        "path": p.path,
        "scheme": p.scheme
    }

# ===================== STATIC FEATURES (14) =====================

def static_features(url):
    p = parse_url(url)
    url_l = url.lower()

    digits = sum(c.isdigit() for c in url)
    specials = sum(not c.isalnum() for c in url)

    return {
        # From v32
        "Is_HTTPS": int(p["scheme"] == "https"),

        # New
        "Subdomain_Count": p["subdomain"].count(".") + 1 if p["subdomain"] else 0,
        "Has_Phishing_Keyword": int(any(k in url_l for k in [
            "login", "verify", "secure", "account", "update", "bank", "paypal"
        ])),
        "Path_Depth": p["path"].count("/"),
        "URL_Length": len(url),
        "Levenshtein_Brand": min(
            [abs(len(p["main"]) - len(b)) for b in BRANDS],
            default=10
        ),
        "Digit_Ratio": digits / len(url) if url else 0,
        "Has_IP_Address": int(bool(re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", p["domain"]))),
        "Suspicious_TLD": int(p["tld"] in SUSPICIOUS_TLDS),
        "Brand_In_Subdomain": int(any(b in p["subdomain"] for b in BRANDS)),
        "Has_At_Symbol": int("@" in url),
        "Special_Char_Ratio": specials / len(url) if url else 0,
        "Prefix_Suffix_Domain": int("-" in p["main"]),
    }

# ===================== DYNAMIC FEATURES (12) =====================

def domain_age(domain):
    try:
        whois_rl.wait()
        w = whois.whois(domain)
        d = w.creation_date
        if isinstance(d, list):
            d = d[0]
        return (datetime.now() - d).days if d else -1
    except:
        return -1

def cert_age(domain):
    try:
        ssl_rl.wait()
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as s:
            with ctx.wrap_socket(s, server_hostname=domain) as ss:
                cert = ss.getpeercert()
        start = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        return (datetime.now() - start).days
    except:
        return -1

def html_features(url, domain):
    try:
        http_rl.wait()
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")

        links = soup.find_all("a", href=True)
        ext = sum(1 for a in links if domain not in a["href"])
        ratio = ext / len(links) if links else 0

        popup = int(any(k in r.text.lower() for k in [
            "window.open", "alert(", "confirm(", "prompt("
        ]))

        favicon = soup.find("link", rel=lambda x: x and "icon" in x.lower())
        fav_match = int(favicon and domain in favicon.get("href", ""))

        return {
            "External_Links_Ratio": round(ratio, 3),
            "Has_Popup": popup,
            "Favicon_Match": fav_match
        }
    except:
        return {
            "External_Links_Ratio": -1,
            "Has_Popup": -1,
            "Favicon_Match": -1
        }

# ===================== WORKER =====================

def process_row(idx, row, cp):
    url = row["url"]
    p = parse_url(url)

    out = {
        "url": url,
        "status": "success"
    }

    try:
        out.update(static_features(url))
        out["Domain_Age"] = domain_age(p["domain"])
        out["Certificate_Age"] = cert_age(p["domain"]) if p["scheme"] == "https" else -1
        out["Redirect_Count"] = len(requests.get(url, timeout=TIMEOUT, allow_redirects=True).history)
        out.update(html_features(url, p["domain"]))
    except Exception as e:
        out["status"] = "error"
        out["error"] = str(e)

    cp.add(idx, out)
    return out

# ===================== MAIN =====================

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="Dataset_v32_Final.csv")
    ap.add_argument("--output", default="Dataset_v33_Final.csv")
    ap.add_argument("--clear-checkpoint", action="store_true")
    args = ap.parse_args()

    df = pd.read_csv(args.input)
    cp = CheckpointManager(args.input)

    if args.clear_checkpoint:
        cp.clear()
        print("Checkpoint cleared")
        return

    remain = [(i, r) for i, r in df.iterrows() if i not in cp.done]

    print(f"Workers: {MAX_WORKERS}")
    print(f"Remaining URLs: {len(remain)}")

    start = time.time()

    with ThreadPoolExecutor(MAX_WORKERS) as exe:
        futures = [exe.submit(process_row, i, r, cp) for i, r in remain]

        for i, _ in enumerate(tqdm(as_completed(futures), total=len(futures))):
            if (i + 1) % CHECKPOINT_INTERVAL == 0:
                cp.save()
                rate = (i + 1) / (time.time() - start)
                eta = (len(remain) - i - 1) / rate / 60
                print(f"\n💾 checkpoint | {rate:.2f} url/s | ETA {eta:.1f} min")

    cp.save()

    final = df.merge(pd.DataFrame(cp.results), on="url", how="left")
    final.to_csv(args.output, index=False)

    cp.clear()
    print("✅ DONE")

if __name__ == "__main__":
    main()
