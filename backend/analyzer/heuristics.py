"""
FORESIGHT - Rule-based Heuristic Security Analyzer
Purely deterministic rule-based indicators for QR code destinations.
NO AI or Machine Learning.
"""

import re
import math
import ipaddress
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Any, Tuple

# Suspicious / high-abuse Top-Level Domains commonly used in phishing & spam
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "cf", "gq", "buzz", "fit", "icu", "work",
    "click", "rest", "country", "surf", "gdn", "mom", "cam", "sbs", "cfd",
    "quest", "monster", "casa", "bar", "lat", "racing", "science", "zip", "mov"
}

# High-profile brand domains frequently targeted by QR phishing (Quishing)
HIGH_PROFILE_TARGETS = [
    "paypal.com", "google.com", "microsoft.com", "apple.com", "amazon.com",
    "facebook.com", "instagram.com", "whatsapp.com", "netflix.com", "github.com",
    "linkedin.com", "binance.com", "coinbase.com", "chase.com", "wellsfargo.com",
    "bankofamerica.com", "sbi.co.in", "hdfcbank.com", "icicibank.com", "paytm.com",
    "phonepe.com", "stripe.com", "dropbox.com", "adobe.com"
]

# Suspicious file extensions that should not be downloaded directly via QR
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".apk", ".bat", ".cmd", ".sh", ".vbs", ".scr", ".iso", ".dmg",
    ".msi", ".dll", ".ps1", ".jar", ".hta"
}

# Phishing and deceptive keywords
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "banking", "account-update",
    "confirm", "wallet", "recover", "authenticate", "passcode", "claim-reward",
    "giftcard", "airdrop", "free-crypto", "bonus-prize", "kyc-update", "otp"
]

# Known malicious threat indicators (sample known signatures / patterns)
KNOWN_MALICIOUS_DOMAINS = {
    "malicious-phish-portal.xyz",
    "secure-login-verify-account.top",
    "free-crypto-giveaway-claim.tk",
    "paypa1-security-center.com",
    "appleid-verify-alert.cfd",
    "hdfc-kyc-suspended-action.monster"
}


def calculate_levenshtein(s1: str, s2: str) -> int:
    """Computes exact Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return calculate_levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy to detect randomly generated domains (DGA)."""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(text)
        entropy -= p * math.log2(p)
    return entropy


def extract_domain_parts(parsed_url) -> Tuple[str, str, List[str]]:
    """Extracts hostname, registered domain, and subdomains."""
    netloc = (parsed_url.netloc or "").split(":")[0].lower()
    
    # Handle user:pass@host
    if "@" in netloc:
        netloc = netloc.split("@")[-1]

    parts = netloc.split(".")
    if len(parts) >= 2:
        # Handle country code double TLDs (e.g. .co.in, .com.au)
        if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "gov", "edu"}:
            reg_domain = ".".join(parts[-3:])
            subdomains = parts[:-3]
        else:
            reg_domain = ".".join(parts[-2:])
            subdomains = parts[:-2]
    else:
        reg_domain = netloc
        subdomains = []

    return netloc, reg_domain, subdomains


def check_ip_destination(hostname: str) -> Dict[str, Any]:
    """Checks if destination host is a raw IP address."""
    try:
        ip = ipaddress.ip_address(hostname)
        is_private = ip.is_private
        return {
            "is_ip": True,
            "ip_version": ip.version,
            "is_private": is_private,
            "warning": f"Destination uses raw IP address ({hostname})" + (" (Private/Internal Network)" if is_private else " (Direct IP bypass)")
        }
    except ValueError:
        return {"is_ip": False}


def check_domain_spoofing(reg_domain: str, subdomains: List[str], full_host: str) -> Dict[str, Any]:
    """
    Checks for domain spoofing / typosquatting:
    1. Levenshtein edit distance against high-profile targets.
    2. Subdomain deception (e.g. paypal.com.attacker.com).
    3. Common character substitution (1 -> l, 0 -> o, rn -> m).
    """
    if not reg_domain:
        return {"spoof_detected": False, "is_official_target": False}

    # 1. Exact match against known target
    if reg_domain in HIGH_PROFILE_TARGETS:
        return {
            "spoof_detected": False,
            "is_official_target": True,
            "matched_brand": reg_domain
        }

    # 2. Check if a high profile brand is embedded inside subdomains of a different domain
    joined_subdomains = ".".join(subdomains).lower()
    for target in HIGH_PROFILE_TARGETS:
        brand_name = target.split(".")[0]
        if brand_name in joined_subdomains and reg_domain != target:
            return {
                "spoof_detected": True,
                "target_brand": brand_name,
                "type": "subdomain_deception",
                "severity": "CRITICAL",
                "reason": f"Brand name '{brand_name}' found in subdomain, but actual registered domain is '{reg_domain}'"
            }

    # 3. Levenshtein distance check on the SLD (Second-Level Domain)
    reg_sld = reg_domain.split(".")[0] if "." in reg_domain else reg_domain
    
    for target in HIGH_PROFILE_TARGETS:
        target_sld = target.split(".")[0]
        dist = calculate_levenshtein(reg_sld, target_sld)
        
        # Edit distance of 1 or 2 on words of length >= 4 is a strong typosquatting indicator
        if 0 < dist <= 2 and abs(len(reg_sld) - len(target_sld)) <= 2:
            return {
                "spoof_detected": True,
                "target_brand": target,
                "type": "typosquatting",
                "edit_distance": dist,
                "severity": "CRITICAL",
                "reason": f"Domain '{reg_domain}' closely mimics legitimate brand '{target}' (typosquatting distance: {dist})"
            }

    # 4. Common lookalike character substitutions
    normalized_sld = reg_sld.replace("1", "l").replace("0", "o").replace("vv", "w").replace("rn", "m")
    if normalized_sld != reg_sld:
        for target in HIGH_PROFILE_TARGETS:
            target_sld = target.split(".")[0]
            if normalized_sld == target_sld:
                return {
                    "spoof_detected": True,
                    "target_brand": target,
                    "type": "visual_homoglyph",
                    "severity": "CRITICAL",
                    "reason": f"Domain '{reg_domain}' uses visual glyph substitutions to imitate '{target}'"
                }

    return {
        "spoof_detected": False,
        "is_official_target": False
    }


def analyze_heuristics(url_string: str) -> Dict[str, Any]:
    """
    Performs comprehensive rule-based static inspection of destination URL.
    Returns findings, risk penalties, and reason explanations.
    """
    findings = []
    reasons = []
    penalties = 0

    clean_url = (url_string or "").strip()
    if not clean_url:
        return {
            "is_valid": False,
            "error": "Empty destination payload",
            "penalties": 100,
            "reasons": ["Empty destination QR code"]
        }

    # Ensure URL has scheme for parsing
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", clean_url):
        url_to_parse = "http://" + clean_url
    else:
        url_to_parse = clean_url

    try:
        parsed = urlparse(url_to_parse)
    except Exception as e:
        return {
            "is_valid": False,
            "error": f"Malformed URL syntax: {str(e)}",
            "penalties": 80,
            "reasons": ["Malformed or unparseable destination URL"]
        }

    scheme = (parsed.scheme or "").lower()
    netloc, reg_domain, subdomains = extract_domain_parts(parsed)
    path = (parsed.path or "").lower()
    query = (parsed.query or "").lower()
    raw_port = parsed.port

    # 1. Scheme Check
    if scheme not in ["http", "https"]:
        penalties += 40
        msg = f"Non-standard web protocol detected ('{scheme}://')"
        reasons.append(msg)
        findings.append({"type": "scheme", "severity": "HIGH", "message": msg})
    elif scheme == "http":
        penalties += 10
        msg = "Unencrypted connection (HTTP instead of HTTPS)"
        reasons.append(msg)
        findings.append({"type": "scheme", "severity": "LOW", "message": msg})

    # 2. Raw IP Check
    ip_check = check_ip_destination(netloc)
    if ip_check["is_ip"]:
        penalties += 35
        msg = ip_check["warning"]
        reasons.append(msg)
        findings.append({"type": "raw_ip", "severity": "HIGH", "message": msg})

    # 3. Port Check
    if raw_port and raw_port not in [80, 443]:
        penalties += 25
        msg = f"Non-standard connection port detected: :{raw_port}"
        reasons.append(msg)
        findings.append({"type": "port", "severity": "MEDIUM", "message": msg})

    # 4. Embedded credentials / @ symbol trick
    if "@" in parsed.netloc:
        penalties += 45
        msg = "URL contains '@' credential notation - frequently used to disguise malicious destinations"
        reasons.append(msg)
        findings.append({"type": "credential_disguise", "severity": "CRITICAL", "message": msg})

    # 5. Punycode / IDN Homograph check
    if "xn--" in netloc:
        penalties += 40
        msg = f"Internationalized domain (Punycode 'xn--') detected ({netloc}) - potential homograph spoofing"
        reasons.append(msg)
        findings.append({"type": "punycode", "severity": "HIGH", "message": msg})

    # 6. TLD Risk Check
    tld = reg_domain.split(".")[-1] if "." in reg_domain else ""
    if tld in SUSPICIOUS_TLDS:
        penalties += 25
        msg = f"Domain uses high-risk Top-Level Domain (.{tld}) often associated with spam/phishing"
        reasons.append(msg)
        findings.append({"type": "suspicious_tld", "severity": "MEDIUM", "message": msg})

    # 7. Subdomain Depth Check
    if len(subdomains) >= 3:
        penalties += 20
        msg = f"Excessive subdomain nesting detected ({len(subdomains)} levels) - possible evasion technique"
        reasons.append(msg)
        findings.append({"type": "subdomain_depth", "severity": "MEDIUM", "message": msg})

    # 8. Domain Entropy (DGA detection)
    reg_sld = reg_domain.split(".")[0] if "." in reg_domain else reg_domain
    entropy = calculate_entropy(reg_sld)
    if entropy > 4.1 and len(reg_sld) > 10:
        penalties += 25
        msg = f"High domain randomness/entropy ({entropy:.2f}) indicates automatically generated domain (DGA)"
        reasons.append(msg)
        findings.append({"type": "domain_entropy", "severity": "MEDIUM", "message": msg})

    # 9. Domain Spoofing / Typosquatting Check
    spoof_info = check_domain_spoofing(reg_domain, subdomains, netloc)
    if spoof_info.get("spoof_detected"):
        penalties += 50
        msg = spoof_info["reason"]
        reasons.append(msg)
        findings.append({"type": "domain_spoofing", "severity": "CRITICAL", "message": msg})

    # 10. Suspicious File Extension in URL Path
    for ext in SUSPICIOUS_EXTENSIONS:
        if path.endswith(ext) or (ext + "?" in path):
            penalties += 55
            msg = f"URL points directly to executable/installer file download ({ext})"
            reasons.append(msg)
            findings.append({"type": "dangerous_extension", "severity": "CRITICAL", "message": msg})
            break

    # 11. Phishing Keywords in Path / Query
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in path or kw in query]
    if len(found_keywords) >= 2 and not spoof_info.get("is_official_target"):
        penalties += 20
        msg = f"Suspicious credential/action keywords in destination path: {', '.join(found_keywords[:3])}"
        reasons.append(msg)
        findings.append({"type": "phishing_keywords", "severity": "MEDIUM", "message": msg})

    # 12. Known Malicious Feed Match
    if reg_domain in KNOWN_MALICIOUS_DOMAINS or netloc in KNOWN_MALICIOUS_DOMAINS:
        penalties += 70
        msg = "Destination matches active threat intelligence feed (known malicious activity)"
        reasons.append(msg)
        findings.append({"type": "known_threat", "severity": "CRITICAL", "message": msg})

    # 13. URL Length anomaly
    if len(clean_url) > 180:
        penalties += 15
        msg = f"Abnormally long URL structure ({len(clean_url)} characters) often used to conceal payloads"
        reasons.append(msg)
        findings.append({"type": "url_length", "severity": "LOW", "message": msg})

    return {
        "is_valid": True,
        "scheme": scheme,
        "hostname": netloc,
        "registered_domain": reg_domain,
        "subdomains": subdomains,
        "tld": tld,
        "path": path,
        "penalties": penalties,
        "findings": findings,
        "reasons": reasons,
        "spoof_info": spoof_info,
        "entropy": round(entropy, 2)
    }
