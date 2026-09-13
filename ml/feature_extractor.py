import urllib.parse
import re
import math
import tldextract

# Threat lists matching threatData.js
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bl.ink", "short.io", "rebrand.ly", "cutt.ly"
]

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "banking", "confirm", "validation", "authenticate", "credential",
    "password", "reset", "support", "helpdesk", "alert", "urgent",
    "suspended", "limited", "unlock", "recover", "checkout", "wallet"
]

TARGETED_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "facebook",
    "instagram", "netflix", "ebay", "chase", "wellsfargo", "bankofamerica",
    "citibank", "dropbox", "linkedin", "twitter", "whatsapp", "coinbase"
]

HIGH_RISK_TLDS = ["xyz", "click", "loan", "work", "date", "review", "gq", "ml", "cf", "tk", "top", "info"]
KNOWN_LEGIT_DOMAINS = ["google.com", "github.com", "apple.com", "microsoft.com", "amazon.com", "wikipedia.org"]

def calculate_shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    entropy = 0
    for char in set(text):
        p_x = text.count(char) / len(text)
        entropy -= p_x * math.log2(p_x)
    return round(entropy, 3)

def extract_url_features(url: str) -> list:
    raw = (url or "").strip()
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    
    try:
        parsed = urllib.parse.urlparse(raw)
    except Exception:
        return [0] * 18

    ext = tldextract.extract(raw)
    hostname = parsed.hostname.lower() if parsed.hostname else ""
    full_url = raw.lower()
    pathname = parsed.path.lower() if parsed.path else ""

    clean_host = re.sub(r'^www\.', '', hostname)
    is_known_legit = any(clean_host == d or clean_host.endswith("." + d) for d in KNOWN_LEGIT_DOMAINS)

    # 1. IP Address as Host
    is_ip = 1 if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^0x[0-9a-fA-F]+\.', hostname) else 0

    # 2. URL Length
    url_length = len(full_url)

    # 3. @ Symbol
    has_at_symbol = 1 if '@' in full_url else 0

    # 4. Double Slash in Path
    double_slash_path = 1 if '//' in pathname else 0

    # 5. Hyphens in Domain
    hyphen_count = hostname.count('-')

    # 6. Subdomain Depth
    host_parts = clean_host.split('.')
    subdomain_count = max(0, len(host_parts) - 2)
    tld = ext.suffix.lower() if ext.suffix else ""
    root_domain = f"{ext.domain}.{ext.suffix}".lower() if ext.domain and ext.suffix else hostname

    # 7. HTTPS Protocol
    is_https = 1 if parsed.scheme == 'https' else 0

    # 8. Deceptive SSL Keyword in Domain
    has_ssl_kw = 1 if (not is_known_legit and any(kw in hostname for kw in ["https", "ssl", "secure"])) else 0

    # 9. URL Shortener
    is_shortener = 1 if any(s in hostname for s in URL_SHORTENERS) else 0

    # 10. Suspicious Keywords
    keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw not in root_domain and kw in full_url)

    # 11. Brand Spoofing
    detected_brands = [b for b in TARGETED_BRANDS if b in hostname]
    brand_spoofed = 1 if (detected_brands and not is_known_legit and not any(b in root_domain for b in detected_brands)) else 0

    # 12. TLD Risk
    tld_risk = 1 if (not is_known_legit and tld in HIGH_RISK_TLDS) else 0

    # 13. Shannon Entropy
    entropy = calculate_shannon_entropy(full_url)

    # 14. Special Character Density
    spec_chars = re.findall(r'[\-_\?=&%#@!\*\+\~]', full_url)
    spec_char_count = len(spec_chars)

    # 15. Non-Standard Port
    non_std_port = 1 if (parsed.port and parsed.port not in [80, 443]) else 0

    # 16. Punycode / IDN Homograph
    has_punycode = 1 if 'xn--' in hostname else 0

    # 17. Query Parameter Depth
    query_count = len(parsed.query.split('&')) if parsed.query else 0

    # 18. Suspicious File Extension in Path
    suspicious_ext = 1 if re.search(r'\.(exe|php|asp|bat|sh|cgi|pl)$', pathname) else 0

    return [
        is_ip, url_length, has_at_symbol, double_slash_path, hyphen_count,
        subdomain_count, is_https, has_ssl_kw, is_shortener, keyword_count,
        brand_spoofed, tld_risk, entropy, spec_char_count, non_std_port,
        has_punycode, query_count, suspicious_ext
    ]
