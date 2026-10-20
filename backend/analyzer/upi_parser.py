"""
FORESIGHT - UPI Payment & Alternative QR Payload Parser
Safely inspects and parses UPI payment URIs, Contact cards, and Plain Text payloads.
Validates structure, extracts payee/amount metadata, and produces explainable risk indicators.
NO AI or Machine Learning.
"""

import re
from urllib.parse import urlparse, parse_qs, unquote
from typing import Dict, Any, Optional, Tuple

# Suspicious / coercive keywords often found in fraudulent payment requests
COERCIVE_PAYMENT_KEYWORDS = {
    "lottery", "prize", "refund", "kyc-fine", "penalty", "income-tax",
    "police", "cybercell", "free-money", "reward-claim", "bonus-credit",
    "overdue-charge", "urgent-release"
}

# Standard VPA (Virtual Payment Address) regex: user@psp / merchant@bank
# Matches: name@okhdfcbank, 9876543210@paytm, merchant.store@upi, etc.
VPA_PATTERN = re.compile(r"^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z0-9]{2,64}$")


def is_upi_payload(payload: str) -> bool:
    """Checks if the raw payload is a UPI payment URI."""
    clean = (payload or "").strip()
    return clean.lower().startswith(("upi://pay", "upi://", "upi:"))


def parse_upi_payload(payload: str) -> Dict[str, Any]:
    """
    Parses and evaluates a UPI payment URI.
    Extracts payee address (pa), payee name (pn), amount (am), currency (cu),
    merchant code (mc), and transaction reference (tr).
    
    Returns structured analysis with risk score and explainable reasons.
    """
    clean = (payload or "").strip()
    # Normalize scheme
    if clean.lower().startswith("upi:"):
        # e.g., upi:pay?pa=... -> upi://pay?...
        clean_url = "upi://" + clean[4:].lstrip("/")
    else:
        clean_url = clean

    parsed = urlparse(clean_url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    # Helper to get first parameter value
    def get_param(key: str) -> Optional[str]:
        vals = params.get(key, [])
        return unquote(vals[0]).strip() if vals else None

    pa = get_param("pa")   # Payee VPA
    pn = get_param("pn")   # Payee Name
    am = get_param("am")   # Amount
    cu = get_param("cu") or "INR"  # Currency (default INR)
    mc = get_param("mc")   # Merchant Code
    tr = get_param("tr")   # Transaction Ref
    tid = get_param("tid") # Transaction ID
    url_param = get_param("url")  # Embedded URL parameter

    penalties = 0
    reasons = []
    findings = []

    # 1. Validate Payee Address (pa) - Mandatory for valid UPI
    if not pa:
        penalties += 35
        msg = "Malformed UPI payment QR: Missing mandatory payee address (pa parameter)"
        reasons.append(msg)
        findings.append({"type": "upi_missing_pa", "severity": "HIGH", "penalty": 35, "message": msg})
    elif not VPA_PATTERN.match(pa):
        penalties += 35
        msg = f"Invalid UPI Payee Address format ('{pa}'): Expected format like payee@bank"
        reasons.append(msg)
        findings.append({"type": "upi_invalid_vpa", "severity": "HIGH", "penalty": 35, "message": msg})
    else:
        # Valid Payee Address
        findings.append({
            "type": "upi_valid_vpa",
            "severity": "INFO",
            "penalty": 0,
            "message": f"Valid UPI payee VPA structure detected: {pa}"
        })

    # 2. Check Payee Name (pn)
    display_name = pn if pn else (pa or "Unknown Recipient")
    if pn:
        lower_pn = pn.lower()
        for kw in COERCIVE_PAYMENT_KEYWORDS:
            if kw in lower_pn:
                penalties += 40
                msg = f"Coercive or deceptive payee name keyword detected: '{kw}' in '{pn}'"
                reasons.append(msg)
                findings.append({"type": "upi_coercive_name", "severity": "CRITICAL", "penalty": 40, "message": msg})
                break

    # 3. Check Amount (am)
    is_fixed_amount = False
    amount_display = "Open (Payer enters amount in UPI app)"
    if am:
        try:
            am_float = float(am)
            if am_float <= 0:
                penalties += 20
                msg = f"Anomalous UPI payment amount: ₹{am} (non-positive value)"
                reasons.append(msg)
                findings.append({"type": "upi_invalid_amount", "severity": "MEDIUM", "penalty": 20, "message": msg})
            else:
                is_fixed_amount = True
                amount_display = f"₹{am_float:,.2f} {cu}"
        except ValueError:
            penalties += 20
            msg = f"Malformed UPI payment amount parameter: '{am}'"
            reasons.append(msg)
            findings.append({"type": "upi_malformed_amount", "severity": "MEDIUM", "penalty": 20, "message": msg})

    # 4. Embedded URL in UPI parameter
    if url_param:
        msg = f"UPI payment QR contains external reference URL: '{url_param}'"
        findings.append({"type": "upi_embedded_url", "severity": "LOW", "penalty": 5, "message": msg})
        # If external URL is suspicious
        if any(bad in url_param.lower() for bad in ["apk", "exe", "bit.ly", "tinyurl"]):
            penalties += 25
            reasons.append(f"UPI payment QR embeds suspicious link: {url_param}")

    # Determine final score and status
    # Base score for valid UPI payment is 10 (SAFE: 0-29 range) to account for payment advisory
    # If no penalties were added, set score to 10
    if penalties == 0:
        risk_score = 10
        status = "SAFE"
        reasons.append(f"Valid UPI payment request for {display_name} ({pa}). Always verify payee details in your UPI app before entering your UPI PIN.")
        recommendation = f"Verify recipient: '{display_name}' ({pa}). Confirm the amount ({amount_display}) in your payment app before entering your UPI PIN."
    elif penalties < 30:
        risk_score = min(29, 10 + penalties)
        status = "SAFE"
        recommendation = f"Verify payee '{display_name}' ({pa}) carefully in your payment app before proceeding."
    elif penalties < 70:
        risk_score = min(69, max(30, 10 + penalties))
        status = "SUSPICIOUS"
        recommendation = "EXERCISE CAUTION. Irregularities detected in payment parameters. Do not pay without confirming payee identity through an independent channel."
    else:
        risk_score = min(100, max(70, 10 + penalties))
        status = "DANGEROUS"
        recommendation = "AVOID PAYMENT. High probability of deceptive or fraudulent payment parameters."

    payment_details = {
        "is_payment": True,
        "protocol": "UPI",
        "payee_address": pa or "",
        "payee_name": pn or "",
        "display_name": display_name,
        "amount": am or "",
        "amount_display": amount_display,
        "is_fixed_amount": is_fixed_amount,
        "currency": cu,
        "merchant_code": mc or "",
        "transaction_ref": tr or tid or "",
        "embedded_url": url_param or "",
        "advisory": "FORESIGHT Advisory: A QR code can only request payments, never receive funds. You only enter your UPI PIN to SEND money, never to receive money."
    }

    return {
        "payload_type": "UPI",
        "score": risk_score,
        "status": status,
        "recommendation": recommendation,
        "reasons": reasons,
        "original_url": clean,
        "final_url": clean,
        "domain": "UPI Payment Network",
        "hostname": pa or "upi-payment",
        "scheme": "upi",
        "is_payment": True,
        "payment_details": payment_details,
        "redirects": {"hops": [], "hop_count": 0, "destination_drift": False},
        "heuristics": {
            "findings": findings,
            "typosquatting_detected": False,
            "punycode_detected": False,
            "high_risk_tld": False,
            "suspicious_file_extension": False,
            "resolved_ip": "N/A (UPI Protocol)"
        }
    }


def parse_non_url_payload(payload: str) -> Optional[Dict[str, Any]]:
    """
    Inspects non-web payloads: Contact vCard/MeCard, Wi-Fi config, and Plain Text.
    Returns analysis dict if matched, or None if payload should be treated as a web URL.
    """
    clean = (payload or "").strip()
    upper = clean.upper()

    # 1. Contact cards: vCard or MeCard
    if upper.startswith("BEGIN:VCARD") or upper.startswith("MECARD:"):
        return {
            "payload_type": "CONTACT",
            "score": 5,
            "status": "SAFE",
            "recommendation": "Contact card data detected. Verify the contact identity before saving to your device.",
            "reasons": ["Standard contact card format (vCard/MeCard). No active web links or payment commands found."],
            "original_url": clean,
            "final_url": clean,
            "domain": "Contact Card (vCard)",
            "hostname": "contact-card",
            "scheme": "contact",
            "is_payment": False,
            "payment_details": None,
            "redirects": {"hops": [], "hop_count": 0, "destination_drift": False},
            "heuristics": {
                "findings": [{"type": "contact_card", "severity": "INFO", "penalty": 0, "message": "Standard contact card payload"}],
                "typosquatting_detected": False,
                "punycode_detected": False,
                "high_risk_tld": False,
                "suspicious_file_extension": False,
                "resolved_ip": "N/A (Local Contact Card)"
            }
        }

    # 2. Wi-Fi Configuration
    if upper.startswith("WIFI:"):
        return {
            "payload_type": "WIFI",
            "score": 5,
            "status": "SAFE",
            "recommendation": "Wi-Fi network configuration profile. Confirm the network SSID matches your intended venue before connecting.",
            "reasons": ["Wi-Fi network connection profile. Contains network credentials rather than an external web link."],
            "original_url": clean,
            "final_url": clean,
            "domain": "Wi-Fi Configuration",
            "hostname": "wifi-config",
            "scheme": "wifi",
            "is_payment": False,
            "payment_details": None,
            "redirects": {"hops": [], "hop_count": 0, "destination_drift": False},
            "heuristics": {
                "findings": [{"type": "wifi_profile", "severity": "INFO", "penalty": 0, "message": "Wi-Fi network setup payload"}],
                "typosquatting_detected": False,
                "punycode_detected": False,
                "high_risk_tld": False,
                "suspicious_file_extension": False,
                "resolved_ip": "N/A (Wi-Fi Profile)"
            }
        }

    # 3. Check if payload has URL characteristics (scheme, dots in domain, path)
    # If not a URL, treat as Plain Text
    has_web_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", clean))
    has_domain_pattern = bool(re.search(r"^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(/.*)?$", clean))
    
    if not has_web_scheme and not has_domain_pattern and not ("." in clean and "/" in clean):
        # Plain text payload (e.g. "Order #12345", "Welcome to conference", "SKU-99214")
        return {
            "payload_type": "TEXT",
            "score": 0,
            "status": "SAFE",
            "recommendation": "Informational plain text payload. Contains non-web alphanumeric content; no active redirection or executable instructions found.",
            "reasons": ["Plain text content: No executable links or payment commands detected."],
            "original_url": clean,
            "final_url": clean,
            "domain": "Plain Text Payload",
            "hostname": "text-content",
            "scheme": "text",
            "is_payment": False,
            "payment_details": None,
            "redirects": {"hops": [], "hop_count": 0, "destination_drift": False},
            "heuristics": {
                "findings": [{"type": "plain_text", "severity": "INFO", "penalty": 0, "message": "Plain text payload"}],
                "typosquatting_detected": False,
                "punycode_detected": False,
                "high_risk_tld": False,
                "suspicious_file_extension": False,
                "resolved_ip": "N/A (Plain Text)"
            }
        }

    return None
