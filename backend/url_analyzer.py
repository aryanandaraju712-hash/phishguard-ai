"""
Proxy module exposing URL analyzer functionality from app.services.url_analyzer
"""
from app.services.url_analyzer import (
    defang_url,
    is_ip_address,
    get_ip_info,
    levenshtein_distance,
    check_brand_lookalike,
    check_percent_encoding,
    extract_url_features,
    analyze_url_comprehensive,
    analyze_single_url_comprehensive,
    analyze_url,
    analyze_idn_and_homoglyphs,
    get_char_script,
    CONFUSABLE_MAP,
    SUSPICIOUS_TLDS,
    TARGETED_BRANDS,
    URL_SHORTENERS
)

__all__ = [
    "defang_url",
    "is_ip_address",
    "get_ip_info",
    "levenshtein_distance",
    "check_brand_lookalike",
    "check_percent_encoding",
    "extract_url_features",
    "analyze_url_comprehensive",
    "analyze_single_url_comprehensive",
    "analyze_url",
    "analyze_idn_and_homoglyphs",
    "get_char_script",
    "CONFUSABLE_MAP",
    "SUSPICIOUS_TLDS",
    "TARGETED_BRANDS",
    "URL_SHORTENERS"
]
