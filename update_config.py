import requests
import json

urls = [
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geoip/irgfw-other-injected-ips.srs",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geoip/iranserver.srs",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geoip/ir.srs",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geoip/ir.json",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geoip/arvancloud.srs",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geosite/category-travel-ir.srs",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geosite/category-travel-ir.json",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geosite/category-tech-ir.srs",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geosite/category-tech-ir.json",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geosite/category-social-media-ir.srs",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geosite/category-social-media-ir.json",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geosite/category-shopping-ir.srs",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geosite/category-shopping-ir.json",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geosite/category-scholar-ir.srs",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geosite/category-scholar-ir.json",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geosite/category-payment-ir.srs",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geosite/category-payment-ir.json",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geosite/category-news-ir.srs",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geosite/category-news-ir.json",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geosite/category-media-ir.srs",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geosite/category-media-ir.json",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geosite/category-ir.srs",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geosite/category-ir.json",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geosite/category-insurance-ir.srs",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geosite/category-insurance-ir.json",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geosite/category-gov-ir.srs",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geosite/category-gov-ir.json",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geosite/category-forums-ir.srs",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geosite/category-forums-ir.json",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geosite/category-education-ir.srs",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geosite/category-education-ir.json",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geosite/category-bourse-ir.srs",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geosite/category-bourse-ir.json",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geosite/category-bank-ir.srs",
    "https://github.com/KaringX/karing-ruleset/raw/refs/heads/sing/geo/geosite/category-bank-ir.json"
]

def to_raw_url(url):
    url = url.replace("github.com", "raw.githubusercontent.com")
    url = url.replace("/raw/", "/")
    return url

json_urls = set()
for u in urls:
    raw_u = to_raw_url(u)
    if raw_u.endswith(".json"):
        json_urls.add(raw_u)
    elif raw_u.endswith(".srs"):
        json_urls.add(raw_u[:-4] + ".json")

domains = set()
domain_suffixes = set()
domain_keywords = set()
ip_cidrs = set()

for url in sorted(list(json_urls)):
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            data = r.json()
            for rule in data.get("rules", []):
                if "domain" in rule:
                    for d in rule["domain"]: domains.add(d)
                if "domain_suffix" in rule:
                    for ds in rule["domain_suffix"]: domain_suffixes.add(ds)
                if "domain_keyword" in rule:
                    for dk in rule["domain_keyword"]: domain_keywords.add(dk)
                if "ip_cidr" in rule:
                    for ip in rule["ip_cidr"]: ip_cidrs.add(ip)
    except Exception as e:
        pass

shadowrocket_rules = []
for ds in sorted(list(domain_suffixes)): shadowrocket_rules.append(f"DOMAIN-SUFFIX,{ds},DIRECT")
for d in sorted(list(domains)): shadowrocket_rules.append(f"DOMAIN,{d},DIRECT")
for dk in sorted(list(domain_keywords)): shadowrocket_rules.append(f"DOMAIN-KEYWORD,{dk},DIRECT")
for ip in sorted(list(ip_cidrs)):
    if ":" in ip: shadowrocket_rules.append(f"IP-CIDR6,{ip},DIRECT")
    else: shadowrocket_rules.append(f"IP-CIDR,{ip},DIRECT")

# حذف حرف f برای جلوگیری از تداخل ساختاری براکت‌ها در متن کانفیگ
config_template = '''[General]
bypass-system = true
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, elcapitan.apple.com
tun-excluded-routes = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12
dns-server = 1.1.1.1, 8.8.8.8

[Rule]
# --- KaringX Ruleset Sync for Iran Bypass ---
''' + "\n".join(shadowrocket_rules) + "\n\nFINAL,PROXY\n"

with open("shadowrocket_iran.conf", "w", encoding="utf-8") as f:
    f.write(config_template)

print("shadowrocket_iran.conf updated successfully!")
