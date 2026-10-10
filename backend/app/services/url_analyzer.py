"""
URL Phishing Detection Module.
Performs static, safe, and explainable heuristic evaluation of submitted URLs
using urllib.parse and ipaddress without making outbound network requests.
"""

import re
import uuid
import datetime
import ipaddress
import unicodedata
from urllib.parse import urlparse, unquote
from typing import Dict, Any, List, Tuple, Optional

from app.services.risk_engine import calculate_url_risk, RiskLevel, PredictionCategory


# High-risk Top Level Domains heavily abused in phishing & spam
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click", "buzz",
    "country", "cam", "fit", "surf", "icu", "rest", "stream", "live", "link",
    "zip", "mov", "monster", "bar", "beauty", "hair", "skin", "quest", "racing",
    "date", "faith", "party", "gdn", "loan", "win", "bid"
}

# Major targeted brands frequently impersonated in phishing campaigns
TARGETED_BRANDS = [
    "microsoft", "office365", "outlook", "google", "gmail", "paypal",
    "apple", "icloud", "amazon", "netflix", "bankofamerica", "chase",
    "wellsfargo", "citibank", "dhl", "fedex", "quickbooks", "intuit",
    "adobe", "docusign", "dropbox", "sharepoint", "onedrive", "zoom",
    "facebook", "instagram", "whatsapp", "telegram", "binance", "coinbase"
]

# Established URL shortening services
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "rb.gy", "cutt.ly", "shorturl.at", "rebrand.ly", "bl.ink", "snip.ly",
    "goo.gl", "bit.do", "shorte.st", "tiny.cc", "bc.vc"
}

# Credential / Security lure keywords in path or query
CREDENTIAL_PATH_KEYWORDS = [
    "login", "signin", "verify", "verification", "update", "account",
    "banking", "secure", "security", "confirm", "wallet", "recover",
    "authenticate", "auth", "credential", "password", "session"
]
 
# Common Unicode confusable characters mimicking Latin script (Cyrillic, Greek, etc.)
CONFUSABLE_MAP: Dict[str, str] = {
    # Cyrillic lowercase confusables with Latin
    '\u0430': 'a', '\u0441': 'c', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
    '\u0455': 's', '\u0456': 'i', '\u0458': 'j', '\u0443': 'y', '\u0445': 'x',
    '\u045d': 'i',
    # Cyrillic uppercase confusables with Latin
    '\u0410': 'A', '\u0412': 'B', '\u0421': 'C', '\u0415': 'E', '\u041d': 'H',
    '\u0406': 'I', '\u0408': 'J', '\u041a': 'K', '\u041c': 'M', '\u041e': 'O',
    '\u0420': 'P', '\u0422': 'T', '\u0425': 'X', '\u0423': 'Y',
    # Greek lowercase confusables with Latin
    '\u03b1': 'a', '\u03bf': 'o', '\u03bd': 'v', '\u03c1': 'p', '\u03c4': 't',
    '\u03b9': 'i', '\u03ba': 'k', '\u03c5': 'u', '\u03c7': 'x',
    # Greek uppercase confusables with Latin
    '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0396': 'Z', '\u0397': 'H',
    '\u0399': 'I', '\u039a': 'K', '\u039c': 'M', '\u039d': 'N', '\u039f': 'O',
    '\u03a1': 'P', '\u03a4': 'T', '\u03a7': 'X', '\u03a5': 'Y'
}

def get_char_script(char: str) -> str:
    """Returns the primary script family of a character using unicodedata."""
    if not char or not char.isalpha():
        return "COMMON"
    name = unicodedata.name(char, "")
    if not name:
        return "COMMON"
    first = name.split()[0]
    known_scripts = (
        "LATIN", "CYRILLIC", "GREEK", "ARABIC", "HEBREW", "DEVANAGARI",
        "BENGALI", "THAI", "CJK", "HIRAGANA", "KATAKANA", "HANGUL",
        "ARMENIAN", "GEORGIAN"
    )
    if first in known_scripts:
        return first
    return "OTHER"


def analyze_idn_and_homoglyphs(hostname: str) -> Dict[str, Any]:
    """
    Safely inspects hostnames for Internationalized Domain Names (IDNs),
    Punycode representations (xn--), mixed-script homoglyphs, and visual confusables.
    
    Safe IDNA Decoding & Error Handling:
    - Decodes Punycode labels safely using Python's built-in idna codec.
    - Handles malformed Punycode labels gracefully without crashing.
    - Distinguishes legitimate single-script IDNs (e.g. German umlauts 'müller.de'
      or full Cyrillic ccTLDs) from malicious mixed-script lookalikes.
    - Does NOT claim to detect every conceivable homoglyph, but focuses on
      cross-script attacks (Latin mixed with Cyrillic or Greek) and brand impersonation.
    """
    if not hostname:
        return {
            "original_hostname": "",
            "normalized_hostname": "",
            "decoded_hostname": "",
            "is_punycode": False,
            "is_mixed_script": False,
            "scripts_detected": [],
            "confusables_detected": [],
            "confusable_skeleton": "",
            "homoglyph_brand_target": None,
            "is_homoglyph_attack": False,
            "explanation": "Empty hostname."
        }

    clean_host = hostname.lower().strip().split(":")[0]
    is_punycode = clean_host.startswith("xn--") or ".xn--" in clean_host

    # Safe label-by-label decoding
    decoded_labels = []
    labels = clean_host.split(".")
    for lbl in labels:
        if lbl.startswith("xn--"):
            try:
                decoded_lbl = lbl.encode("ascii").decode("idna")
                decoded_labels.append(decoded_lbl)
            except Exception:
                # Malformed punycode fallback
                decoded_labels.append(lbl)
        else:
            try:
                decoded_lbl = unicodedata.normalize("NFKC", lbl)
                decoded_labels.append(decoded_lbl)
            except Exception:
                decoded_labels.append(lbl)

    decoded_hostname = ".".join(decoded_labels)

    # Analyze scripts and confusables per label
    scripts_overall = set()
    confusables_found = []
    mixed_labels = []

    # Skeleton domain with confusable characters mapped to Latin
    skeleton_labels = []

    for label in decoded_labels:
        label_scripts = set()
        label_skeleton = []
        for ch in label:
            if ch.isalpha():
                script = get_char_script(ch)
                if script != "COMMON":
                    label_scripts.add(script)
                    scripts_overall.add(script)

            if ch in CONFUSABLE_MAP:
                confusable_replacement = CONFUSABLE_MAP[ch]
                label_skeleton.append(confusable_replacement)
                confusables_found.append({
                    "char": ch,
                    "codepoint": f"U+{ord(ch):04X}",
                    "script": get_char_script(ch),
                    "confusable_with": confusable_replacement
                })
            else:
                label_skeleton.append(ch)

        skeleton_labels.append("".join(label_skeleton))

        # Mixed script detection in a single label:
        # Suspicious if label mixes LATIN with CYRILLIC or GREEK, or contains confusables with Latin
        if "LATIN" in label_scripts and len(label_scripts) > 1:
            mixed_labels.append(label)
        elif "LATIN" in label_scripts and any(c in CONFUSABLE_MAP for c in label):
            mixed_labels.append(label)

    confusable_skeleton = ".".join(skeleton_labels)
    is_mixed_script = len(mixed_labels) > 0

    # Brand target detection via confusable skeleton
    homoglyph_brand_target = None
    if len(skeleton_labels) >= 2:
        sld = skeleton_labels[-2]
    else:
        sld = confusable_skeleton

    for brand in TARGETED_BRANDS:
        if sld == brand or (len(sld) >= 4 and levenshtein_distance(sld, brand) <= 1):
            if sld != (clean_host.split(".")[-2] if len(clean_host.split(".")) >= 2 else clean_host):
                homoglyph_brand_target = brand
                break
        elif brand in sld and sld != brand:
            if brand not in (clean_host.split(".")[-2] if len(clean_host.split(".")) >= 2 else clean_host):
                homoglyph_brand_target = brand
                break

    is_homoglyph_attack = is_mixed_script or (bool(homoglyph_brand_target) and len(confusables_found) > 0)

    # Human-readable explanation
    if is_homoglyph_attack:
        explanation = (
            f"Suspicious IDN homoglyph: Hostname mixes scripts ({', '.join(sorted(scripts_overall))}) "
            f"with {len(confusables_found)} confusable character(s)."
        )
        if homoglyph_brand_target:
            explanation += f" Confusable skeleton mimics trusted brand '{homoglyph_brand_target}'."
    elif is_punycode:
        explanation = (
            f"Internationalized domain name (Punycode): Decodes to '{decoded_hostname}' using single script "
            f"({', '.join(sorted(scripts_overall)) or 'Standard'}). No suspicious script mixing detected."
        )
    else:
        explanation = "Standard hostname without IDN punycode or mixed-script homoglyphs."

    return {
        "original_hostname": clean_host,
        "normalized_hostname": clean_host,
        "decoded_hostname": decoded_hostname,
        "is_punycode": is_punycode,
        "is_mixed_script": is_mixed_script,
        "scripts_detected": sorted(list(scripts_overall)),
        "confusables_detected": confusables_found,
        "confusable_skeleton": confusable_skeleton,
        "homoglyph_brand_target": homoglyph_brand_target,
        "is_homoglyph_attack": is_homoglyph_attack,
        "explanation": explanation
    }


def defang_url(url: str) -> str:
    """
    Safely defangs a URL to prevent accidental user clicks in triage reports and dashboards.
    Converts http -> hxxp, https -> hxxps, and periods into [.]
    """
    if not url:
        return ""
    defanged = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    defanged = defanged.replace(".", "[.]")
    return defanged


def is_ip_address(host: str) -> bool:
    """
    Safely checks if the provided hostname is an IPv4 or IPv6 address using ipaddress.
    Strips ports and enclosing brackets.
    """
    if not host:
        return False
    # Strip port if present
    clean_host = host.split(":")[0].strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False


def get_ip_info(host: str) -> Tuple[bool, bool, bool]:
    """
    Returns (is_ip, is_ipv4, is_ipv6).
    """
    if not host:
        return False, False, False
    clean_host = host.split(":")[0].strip("[]")
    try:
        addr = ipaddress.ip_address(clean_host)
        return True, addr.version == 4, addr.version == 6
    except ValueError:
        return False, False, False


def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def check_brand_lookalike(
    domain: str,
    registered_domain: Optional[str] = None,
    subdomains: Optional[List[str]] = None
) -> Tuple[bool, str, str]:
    """
    Inspects whether a domain label mimics a known brand via:
    1. Subdomain impersonation (brand embedded in subdomain under an unrelated domain).
    2. Embedded brand names inside the registered domain's SLD label.
    3. Leetspeak / character substitutions (e.g. micros0ft, paypa1).
    4. 1-character edit distance typosquatting (e.g. paypaal, goolge).

    Returns (is_lookalike, brand_name, reason).
    """
    if not domain:
        return False, "", ""
    domain_clean = domain.lower().strip().split(":")[0].strip("[]")
    if not domain_clean:
        return False, "", ""

    # Parse parts if registered_domain / subdomains not provided
    domain_parts = domain_clean.split(".")
    if registered_domain is None or subdomains is None:
        if len(domain_parts) > 2:
            # Common two-part ccTLDs (e.g. .co.uk, .gov.uk, .com.au)
            if len(domain_parts) >= 3 and domain_parts[-2] in ["co", "gov", "ac", "org", "net", "edu", "mil"] and len(domain_parts[-1]) == 2:
                computed_subdomains = domain_parts[:-3]
                computed_registered_domain = ".".join(domain_parts[-3:])
                main_label = domain_parts[-3]
            else:
                computed_subdomains = domain_parts[:-2]
                computed_registered_domain = ".".join(domain_parts[-2:])
                main_label = domain_parts[-2]
        elif len(domain_parts) == 2:
            computed_subdomains = []
            computed_registered_domain = domain_clean
            main_label = domain_parts[0]
        else:
            computed_subdomains = []
            computed_registered_domain = domain_clean
            main_label = domain_clean

        if registered_domain is None:
            registered_domain = computed_registered_domain
        if subdomains is None:
            subdomains = computed_subdomains
    else:
        reg_parts = registered_domain.split(".")
        if len(reg_parts) >= 3 and reg_parts[-2] in ["co", "gov", "ac", "org", "net", "edu", "mil"] and len(reg_parts[-1]) == 2:
            main_label = reg_parts[-3]
        elif len(reg_parts) >= 2:
            main_label = reg_parts[-2]
        else:
            main_label = registered_domain

    for brand in TARGETED_BRANDS:
        # Legitimate domain check:
        # If the registered domain's main label IS exactly this brand,
        # then official subdomains (e.g. www.paypal.com, login.microsoft.com) are authentic.
        if main_label == brand:
            continue
        if domain_clean in [f"{brand}.com", f"{brand}.net", f"{brand}.org", f"{brand}.io"]:
            continue
        if domain_clean.endswith(f".{brand}.com") or domain_clean.endswith(f".{brand}.net") or domain_clean.endswith(f".{brand}.org"):
            continue

        # 1. Deceptive Subdomain Impersonation:
        # If the registered domain is NOT owned by the brand (e.g. example.com),
        # but the brand name appears in a subdomain label (e.g. paypal-login-verify, paypal):
        for sub in subdomains:
            sub_tokens = re.split(r"[-_.]", sub)
            if brand == sub or brand in sub_tokens or (len(brand) >= 5 and brand in sub):
                return True, brand, f"Brand '{brand}' embedded in subdomain '{sub}' under unrelated domain '{registered_domain}'"

        # 2. Embedded brand name inside domain SLD (e.g., login-microsoft.com, paypal-update.xyz)
        if brand in main_label and main_label != brand:
            return True, brand, f"Brand '{brand}' embedded inside domain label '{main_label}'"

        # 3. Leetspeak / character substitutions (e.g. micros0ft, paypa1, go0gle)
        normalized_main = (main_label.replace("0", "o")
                                     .replace("1", "l")
                                     .replace("3", "e")
                                     .replace("5", "s")
                                     .replace("@", "a")
                                     .replace("v", "u"))
        if brand in normalized_main and brand not in main_label:
            return True, brand, f"Character substitution/leetspeak impersonating '{brand}' ('{main_label}')"

        for sub in subdomains:
            normalized_sub = (sub.replace("0", "o")
                                 .replace("1", "l")
                                 .replace("3", "e")
                                 .replace("5", "s")
                                 .replace("@", "a")
                                 .replace("v", "u"))
            if brand in normalized_sub and brand not in sub:
                return True, brand, f"Character substitution/leetspeak impersonating '{brand}' in subdomain '{sub}'"

        # 4. 1-character typosquatting in SLD
        if len(main_label) >= 4 and abs(len(main_label) - len(brand)) <= 2:
            dist = levenshtein_distance(main_label, brand)
            if dist == 1:
                return True, brand, f"Typosquatted domain '{main_label}' is 1 edit away from '{brand}'"

    return False, "", ""


def check_percent_encoding(raw_url: str) -> Tuple[bool, List[str]]:
    """
    Checks for percent-encoding anomalies and suspicious hex patterns.
    """
    matches = re.findall(r"%[0-9a-fA-F]{2}", raw_url)
    suspicious_chars = []
    # Encoded dots (%2e), slashes (%2f, %5c), at sign (%40), null bytes (%00)
    for m in matches:
        lm = m.lower()
        if lm in ["%2e", "%2f", "%5c", "%40", "%00", "%23", "%3f"]:
            suspicious_chars.append(m)

    if len(suspicious_chars) > 0 or len(matches) >= 3:
        return True, list(set(suspicious_chars or matches))
    return False, []


def extract_url_features(url: str) -> Dict[str, Any]:
    """
    Safely normalizes and extracts static structural features from a URL string
    using urllib.parse and ipaddress.
    """
    clean_url = url.strip()
    scheme_missing = False

    if not clean_url:
        raise ValueError("URL cannot be empty")

    # If scheme is absent, add default http:// for parsing while recording feature
    if "://" not in clean_url:
        scheme_missing = True
        parse_target = "http://" + clean_url
    else:
        parse_target = clean_url

    try:
        parsed = urlparse(parse_target)
    except Exception as exc:
        raise ValueError(f"Malformed URL syntax: {exc}")

    scheme = (parsed.scheme or "").lower()
    netloc = parsed.netloc or ""
    path = parsed.path or ""
    query = parsed.query or ""
    port = parsed.port

    # Hostname resolution
    hostname = (parsed.hostname or "").lower()
    if not hostname and netloc:
        # Fallback if netloc has port or unusual syntax
        hostname = netloc.split("@")[-1].split(":")[0].lower()

    is_ip, is_ipv4, is_ipv6 = get_ip_info(hostname)

    # Subdomain calculation
    subdomain_count = 0
    subdomains = []
    registered_domain = hostname

    if not is_ip and hostname:
        parts = hostname.split(".")
        if len(parts) > 2:
            # Common two-part ccTLDs
            if len(parts) >= 3 and parts[-2] in ["co", "gov", "ac", "org", "net", "edu", "mil"] and len(parts[-1]) == 2:
                subdomains = parts[:-3]
                registered_domain = ".".join(parts[-3:])
            else:
                subdomains = parts[:-2]
                registered_domain = ".".join(parts[-2:])
            subdomain_count = len(subdomains)
        elif len(parts) == 2:
            registered_domain = hostname
            subdomain_count = 0

    # Suspicious @ symbol in authority/userinfo
    has_at_symbol = "@" in parse_target.split("?")[0].split("#")[0] or bool(parsed.username)

    # URL length
    url_length = len(clean_url)

    # Percent encoding
    has_suspicious_encoding, encoded_tokens = check_percent_encoding(clean_url)

    # Shortener check
    is_shortener = hostname in URL_SHORTENERS or any(hostname.endswith("." + s) for s in URL_SHORTENERS)

    # Suspicious TLD check
    tld = hostname.split(".")[-1] if ("." in hostname and not is_ip) else ""
    is_suspicious_tld = tld in SUSPICIOUS_TLDS

    # IDN / Homoglyph / Punycode check
    idn_info = analyze_idn_and_homoglyphs(hostname)
    decoded_hostname = idn_info["decoded_hostname"]
    is_punycode = idn_info["is_punycode"]
    is_mixed_script = idn_info["is_mixed_script"]
    scripts_detected = idn_info["scripts_detected"]
    confusables_detected = idn_info["confusables_detected"]
    confusable_skeleton = idn_info["confusable_skeleton"]
    is_homoglyph_attack = idn_info["is_homoglyph_attack"]
    homoglyph_brand_target = idn_info["homoglyph_brand_target"]

    # Brand lookalike check (ASCII check first)
    is_lookalike, lookalike_brand, lookalike_reason = check_brand_lookalike(
        hostname, registered_domain=registered_domain, subdomains=subdomains
    )
    if not is_lookalike and homoglyph_brand_target:
        is_lookalike = True
        lookalike_brand = homoglyph_brand_target
        lookalike_reason = f"IDN homoglyph spoofing mimicking brand '{homoglyph_brand_target}'"
    elif not is_lookalike and confusable_skeleton and confusable_skeleton != hostname:
        skel_is_lookalike, skel_brand, skel_reason = check_brand_lookalike(
            confusable_skeleton, registered_domain=registered_domain, subdomains=subdomains
        )
        if skel_is_lookalike:
            is_lookalike = True
            lookalike_brand = skel_brand
            lookalike_reason = f"Confusable character skeleton mimics brand '{skel_brand}' ({skel_reason})"

    # Path keywords
    path_lower = path.lower()
    query_lower = query.lower()
    found_keywords = [
        kw for kw in CREDENTIAL_PATH_KEYWORDS
        if kw in path_lower or kw in query_lower
    ]

    # Hostname / Subdomain keywords
    found_host_keywords = []
    host_tokens = re.split(r"[-_.]", hostname)
    for kw in CREDENTIAL_PATH_KEYWORDS:
        if kw in host_tokens or any(kw in re.split(r"[-_.]", s) for s in subdomains):
            if kw not in found_host_keywords:
                found_host_keywords.append(kw)

    all_auth_keywords = list(dict.fromkeys(found_keywords + found_host_keywords))

    return {
        "original_url": clean_url,
        "defanged_url": defang_url(clean_url),
        "scheme": scheme,
        "scheme_missing": scheme_missing,
        "hostname": hostname,
        "normalized_hostname": hostname,
        "decoded_hostname": decoded_hostname,
        "registered_domain": registered_domain,
        "subdomains": subdomains,
        "subdomain_count": subdomain_count,
        "is_ip": is_ip,
        "is_ipv4": is_ipv4,
        "is_ipv6": is_ipv6,
        "port": port,
        "path": path,
        "query": query,
        "url_length": url_length,
        "has_at_symbol": has_at_symbol,
        "has_suspicious_encoding": has_suspicious_encoding,
        "encoded_tokens": encoded_tokens,
        "is_shortener": is_shortener,
        "is_suspicious_tld": is_suspicious_tld,
        "tld": tld,
        "is_lookalike": is_lookalike,
        "lookalike_brand": lookalike_brand,
        "lookalike_reason": lookalike_reason,
        "is_punycode": is_punycode,
        "is_mixed_script": is_mixed_script,
        "scripts_detected": scripts_detected,
        "confusables_detected": confusables_detected,
        "confusable_skeleton": confusable_skeleton,
        "is_homoglyph_attack": is_homoglyph_attack,
        "homoglyph_brand_target": homoglyph_brand_target,
        "idn_details": idn_info,
        "found_path_keywords": found_keywords,
        "found_host_keywords": found_host_keywords,
        "all_credential_keywords": all_auth_keywords
    }


def analyze_url_comprehensive(url: str) -> Dict[str, Any]:
    """
    Main URL analysis function for the URL Phishing Detection module.
    Evaluates extracted structural features and computes an explainable weighted risk score.
    
    Important Cybersecurity Principles:
    - HTTPS does NOT prove that a URL is safe (phishers use free valid SSL certificates).
    - HTTP alone does NOT prove phishing (indicates lack of encryption, but not malice).
    - Length or URL shortening alone does NOT prove maliciousness.
    - Heuristic scores are transparent risk assessments, not calibrated probabilities.
    """
    clean_url = url.strip()
    if not clean_url:
        raise ValueError("URL cannot be empty")

    features = extract_url_features(clean_url)
    indicators: List[Dict[str, Any]] = []

    # 1. Hostname is a raw IP address
    if features["is_ip"]:
        indicators.append({
            "category": "IP Address as Hostname",
            "severity": "Critical",
            "weight": 35,
            "description": f"Destination hostname is a numeric IP address ({features['hostname']}) rather than a registered domain name.",
            "evidence": f"Host: {features['hostname']}",
            "why_it_matters": "Legitimate enterprise services use registered domain names with reputation records. Bare IP addresses are frequently used in disposable phishing campaigns and attack toolkits."
        })

    # 2. Suspicious @ symbol in URL authority
    if features["has_at_symbol"]:
        indicators.append({
            "category": "Suspicious @ Credential Syntax",
            "severity": "Critical",
            "weight": 30,
            "description": "URL contains an '@' symbol in the authority component, which masks the true destination host.",
            "evidence": f"URL: {features['defanged_url']}",
            "why_it_matters": "Browsers ignore strings before '@' in the authority component. Attackers use this to prefix a legitimate-looking brand domain before the real malicious destination."
        })

    # 3. Brand Lookalike / Typosquatting (ASCII or non-homoglyph)
    # Only add standalone Brand Impersonation if not already handled by Homoglyph indicator to prevent double-counting
    if features["is_lookalike"] and not (features.get("is_homoglyph_attack") or features.get("is_mixed_script")):
        indicators.append({
            "category": "Brand Impersonation / Typosquatting",
            "severity": "High",
            "weight": 28,
            "description": f"Domain exhibits mimicry targeting brand '{features['lookalike_brand']}': {features['lookalike_reason']}.",
            "evidence": f"Domain: {features['hostname']}",
            "why_it_matters": "Attackers register typo variants or append deceptive prefixes/suffixes to well-known brand names to trick victims into trusting the page."
        })

    # 4. IDN / Punycode / Homoglyph Threat Analysis
    if features.get("is_homoglyph_attack") or features.get("is_mixed_script"):
        brand_target = features.get("homoglyph_brand_target") or features.get("lookalike_brand")
        target_clause = f" targeting brand '{brand_target}'" if brand_target else ""
        scripts_non_latin = [s for s in features.get("scripts_detected", []) if s != "LATIN"]
        script_clause = f" (mixing Latin with {', '.join(scripts_non_latin)})" if scripts_non_latin else ""
        indicators.append({
            "category": "Mixed-Script Homoglyph Impersonation",
            "severity": "Critical" if brand_target else "High",
            "weight": 35 if brand_target else 30,
            "description": (
                f"Suspicious mixed-script IDN homoglyph detected ({features['decoded_hostname']}){target_clause}{script_clause}. "
                f"Hostname contains {len(features.get('confusables_detected', []))} confusable character(s)."
            ),
            "evidence": f"Host: {features['hostname']} (Decoded: {features['decoded_hostname']})",
            "why_it_matters": "IDN homographs replace Latin characters with identical-looking Cyrillic or Greek symbols to visually spoof authentic websites in modern browsers."
        })
    elif features.get("is_punycode"):
        # Legitimate single-script IDN (e.g. German umlauts like müller.de or pure non-Latin ccTLD)
        indicators.append({
            "category": "Internationalized Domain Name (IDN)",
            "severity": "Informational",
            "weight": 0,
            "description": (
                f"Domain uses internationalized Punycode representation ({features['decoded_hostname']}) in "
                f"script(s): {', '.join(features.get('scripts_detected', [])) or 'Standard'} without suspicious script mixing."
            ),
            "evidence": f"Host: {features['hostname']} (Decoded: {features['decoded_hostname']})",
            "why_it_matters": "Internationalized Domain Names allow native characters across different languages. Single-script IDNs are common globally and are not inherently malicious."
        })

    # 5. Excessive Subdomains (only if not an IP address)
    if not features["is_ip"] and features["subdomain_count"] >= 3:
        indicators.append({
            "category": "Excessive Subdomain Depth",
            "severity": "Medium",
            "weight": 16,
            "description": f"Abnormally deep subdomain hierarchy ({features['subdomain_count']} levels: {'.'.join(features['subdomains'])}).",
            "evidence": f"Subdomains: {'.'.join(features['subdomains'])}",
            "why_it_matters": "Multi-tier subdomains on free DNS providers are commonly chained together to simulate trusted portal structures (e.g., login.microsoft.service.evil.com)."
        })

    # 6. URL Shortening Redirection Service
    if features["is_shortener"]:
        indicators.append({
            "category": "URL Shortener Redirection",
            "severity": "Medium",
            "weight": 25,
            "description": f"Uses known URL shortening service ({features['hostname']}) to disguise target destination.",
            "evidence": f"Host: {features['hostname']}",
            "why_it_matters": "Shortened links obscure the final destination domain and path from both users and automated security filters before click execution."
        })

    # 7. High-Risk / Suspicious TLD (only if not an IP address)
    if not features["is_ip"] and features["is_suspicious_tld"]:
        indicators.append({
            "category": "High-Risk Top-Level Domain",
            "severity": "Medium",
            "weight": 15,
            "description": f"Uses top-level domain (.{features['tld']}) heavily correlated with malicious and spam campaigns.",
            "evidence": f"TLD: .{features['tld']}",
            "why_it_matters": "Free or low-cost TLDs have minimal identity verification requirements, making them statistical favorites for disposable phishing deployments."
        })

    # 8. Suspicious Credential / Verification Keywords
    all_auth = features.get("all_credential_keywords", features["found_path_keywords"])
    if all_auth:
        keywords_str = ", ".join(all_auth)
        # Higher weight if host is already suspicious, IP, shortener, lookalike, or homoglyph
        is_suspicious_host = (
            features["is_ip"] or
            features["is_shortener"] or
            features["is_suspicious_tld"] or
            features["is_lookalike"] or
            features.get("is_homoglyph_attack") or
            features.get("is_mixed_script")
        )
        if is_suspicious_host:
            indicators.append({
                "category": "Credential Lure in Path on Suspicious Host",
                "severity": "High",
                "weight": 22,
                "description": f"Credential/security verification keywords ({keywords_str}) present on an unverified, lookalike, or high-risk host.",
                "evidence": f"Keywords: {keywords_str} | Host: {features['hostname']}",
                "why_it_matters": "Legitimate authentication endpoints reside on official corporate domains, not unverified, disposable, lookalike, or IP-based hosts."
            })
        elif len(all_auth) >= 2:
            indicators.append({
                "category": "Multiple Authentication Keywords in Path",
                "severity": "Medium",
                "weight": 12,
                "description": f"Multiple security/credential keywords detected in URL: {keywords_str}.",
                "evidence": f"Keywords: {keywords_str}",
                "why_it_matters": "Chained security keywords in path queries or domain labels are often crafted to entice victims into believing they are accessing a secure account recovery tool."
            })

    # 9. Suspicious Percent-Encoding / Obfuscation
    if features["has_suspicious_encoding"]:
        token_str = ", ".join(features["encoded_tokens"][:4])
        indicators.append({
            "category": "Suspicious Percent Encoding / Obfuscation",
            "severity": "Medium",
            "weight": 12,
            "description": f"URL contains suspicious percent-encoding sequences ({token_str}) commonly used to evade pattern filters.",
            "evidence": f"Tokens: {token_str}",
            "why_it_matters": "Hex percent-encoding is frequently leveraged to hide directory traversals, dots, and credentials from basic signature scanners."
        })

    # 10. Unusually Long URL Structure
    if features["url_length"] > 120:
        indicators.append({
            "category": "Abnormally Long URL Structure",
            "severity": "Low",
            "weight": 10,
            "description": f"URL is unusually long ({features['url_length']} characters), which may obscure true destination.",
            "evidence": f"Length: {features['url_length']} chars",
            "why_it_matters": "Extremely long URLs push the actual domain out of view in mobile or compact browser address bars."
        })
    elif features["url_length"] > 75 and len(indicators) >= 1:
        indicators.append({
            "category": "Extended URL Length",
            "severity": "Low",
            "weight": 5,
            "description": f"URL exhibits extended length ({features['url_length']} characters).",
            "evidence": f"Length: {features['url_length']} chars",
            "why_it_matters": "Long query parameters and tokens are often appended in tracking or credential-stealing exploits."
        })

    # 11. Non-Standard Port
    if features["port"] and features["port"] not in [80, 443, 8080]:
        indicators.append({
            "category": "Non-Standard Web Port",
            "severity": "Medium",
            "weight": 15,
            "description": f"Destination runs on non-standard port :{features['port']}.",
            "evidence": f"Port: {features['port']}",
            "why_it_matters": "Standard web portals use ports 80 (HTTP) or 443 (HTTPS). Non-standard ports suggest non-production or rogue servers."
        })

    # 12. Scheme Analysis (Explicitly Explainable: HTTPS != Safe, HTTP != Automatic Phishing)
    if features["scheme"] == "http":
        indicators.append({
            "category": "Unencrypted HTTP Scheme",
            "severity": "Informational",
            "weight": 5,
            "description": "URL uses unencrypted plain HTTP rather than HTTPS.",
            "evidence": "Scheme: http",
            "why_it_matters": "Plain HTTP traffic is vulnerable to interception and tampering. Note: HTTP alone does NOT prove phishing, but standard organizations mandate HTTPS for modern services."
        })
    elif features["scheme"] == "https":
        # Weight 0: HTTPS is recorded for transparent explainability without giving a false safe pass
        indicators.append({
            "category": "HTTPS Encryption",
            "severity": "Informational",
            "weight": 0,
            "description": "URL uses HTTPS transit encryption.",
            "evidence": "Scheme: https",
            "why_it_matters": "HTTPS confirms communication transit is encrypted. CRITICAL NOTE: HTTPS does NOT prove the website is trustworthy; over 80% of phishing pages now possess valid SSL certificates."
        })

    # Compute transparent risk score using risk engine
    risk_score, risk_level, prediction, recommendations = calculate_url_risk(features, indicators)

    # Format human-readable reasons
    reasons = [
        f"[{ind['category']}] {ind['description']}"
        for ind in indicators
        if ind.get("weight", 0) > 0
    ]
    if not reasons:
        reasons = ["No malicious structural anomalies identified in URL analysis."]

    analysis_id = f"URL-{uuid.uuid4().hex[:8].upper()}"
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Build AI-style explanations
    ai_explanations = [
        {
            "finding": ind["category"],
            "evidence": ind["evidence"],
            "why_it_matters": ind["why_it_matters"],
            "recommended_action": "Do not navigate to this destination or enter organizational credentials."
        }
        for ind in indicators
    ]

    highlighted_phrases = []
    if features["is_ip"]:
        highlighted_phrases.append({
            "phrase": features["hostname"],
            "category": "Raw IP Host",
            "explanation": "Direct numeric connection bypassing domain registration"
        })
    if features["is_lookalike"]:
        highlighted_phrases.append({
            "phrase": features["hostname"],
            "category": "Lookalike Domain",
            "explanation": features["lookalike_reason"]
        })
    if features["is_shortener"]:
        highlighted_phrases.append({
            "phrase": features["hostname"],
            "category": "URL Shortener",
            "explanation": "Obscures true destination"
        })
    if features.get("is_mixed_script") or features.get("is_homoglyph_attack"):
        highlighted_phrases.append({
            "phrase": features["hostname"],
            "category": "IDN Homoglyph",
            "explanation": f"Decodes to '{features['decoded_hostname']}' with confusable/mixed scripts ({', '.join(features['scripts_detected'])})"
        })

    return {
        "success": True,
        "analysis_id": analysis_id,
        "id": analysis_id,
        "url": clean_url,
        "defanged_url": features["defanged_url"],
        "prediction": prediction,
        "classification": prediction,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "features": features,
        "indicators": indicators,
        "indicator_details": indicators,
        "reasons": reasons,
        "recommendations": recommendations,
        "ai_explanation": ai_explanations,
        "missing_evidence": ["Live DNS server metadata (inspected purely offline and statically for safety)"],
        "extracted_urls": [{
            "original_url": clean_url,
            "defanged_url": features["defanged_url"],
            "domain": features["hostname"],
            "decoded_domain": features["decoded_hostname"],
            "is_ip": features["is_ip"],
            "is_suspicious_tld": features["is_suspicious_tld"],
            "is_shortener": features["is_shortener"],
            "is_lookalike": features["is_lookalike"],
            "is_punycode": features["is_punycode"],
            "is_mixed_script": features["is_mixed_script"],
            "reasons": reasons
        }],
        "attachment_names": [],
        "urls_count": 1,
        "attachments_count": 0,
        "highlighted_phrases": highlighted_phrases,
        "is_heuristic": True,
        "created_at": timestamp
    }


# Backwards compatibility alias for existing email parser and legacy routers
def analyze_url(url: str, anchor_text: str = "") -> Dict[str, Any]:
    """
    Legacy wrapper for analyze_url used by email_parser and phishing_analyzer.
    """
    try:
        res = analyze_url_comprehensive(url)
        features = res["features"]
        reasons = res["reasons"]
        if anchor_text:
            anchor_clean = anchor_text.strip().lower()
            if any(k in anchor_clean for k in ["http://", "https://", ".com", ".org"]):
                try:
                    anchor_parsed = urlparse(anchor_clean if "://" in anchor_clean else "http://" + anchor_clean)
                    anchor_host = (anchor_parsed.hostname or "").lower()
                    if anchor_host and features["hostname"] and anchor_host != features["hostname"] and not features["hostname"].endswith("." + anchor_host):
                        reasons.append(f"Misleading link text: Text displays '{anchor_clean}' but destination points to '{features['hostname']}'")
                except Exception:
                    pass

        return {
            "original_url": url,
            "defanged_url": features["defanged_url"],
            "domain": features["hostname"] or "unknown",
            "is_ip": features["is_ip"],
            "is_suspicious_tld": features["is_suspicious_tld"],
            "is_shortener": features["is_shortener"],
            "is_lookalike": features["is_lookalike"],
            "reasons": reasons
        }
    except Exception:
        return {
            "original_url": url,
            "defanged_url": defang_url(url),
            "domain": "Malformed",
            "is_ip": False,
            "is_suspicious_tld": False,
            "is_shortener": False,
            "is_lookalike": False,
            "reasons": ["Malformed URL syntax"]
        }


def analyze_single_url_comprehensive(url: str) -> Dict[str, Any]:
    """
    Alias maintaining exact backwards compatibility with existing backend routers.
    """
    return analyze_url_comprehensive(url)
