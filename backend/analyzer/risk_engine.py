"""
FORESIGHT - Risk Scoring & Classification Engine
Deterministic rule-based risk evaluation.
Combines static URL heuristics, safe redirect tracking, and destination drift analysis.
Distinguishes HTTP/HTTPS URLs, UPI payments, plain text, and contact information.
NO AI or Machine Learning.
"""

from typing import Dict, List, Any
from .heuristics import analyze_heuristics
from .redirect_tracer import trace_redirects
from .upi_parser import is_upi_payload, parse_upi_payload, parse_non_url_payload


def evaluate_destination(raw_payload: str, follow_redirects: bool = True) -> Dict[str, Any]:
    """
    Core evaluation pipeline:
    1. Distinguish payload type: UPI payment, Plain text, Contact, or Web URL.
    2. For UPI: safely parse payee VPA, name, amount, currency; evaluate integrity.
    3. For Plain text/Contact/WiFi: evaluate non-web parameters with safe defaults.
    4. For Web URLs:
       a. Static heuristic analysis of initial payload.
       b. Dynamic redirect trace with SSRF protection & destination drift detection.
       c. Static heuristic analysis of final resolved URL (if different).
    5. Clamped deterministic score aggregation (0 - 100).
    6. Categorical classification:
       - SAFE: 0–29
       - SUSPICIOUS: 30–69
       - DANGEROUS: 70–100
    7. Explainability breakdown: explicit list of reasons.
    """
    clean_input = (raw_payload or "").strip()
    if not clean_input:
        return {
            "score": 100,
            "status": "DANGEROUS",
            "summary": "No readable destination payload provided.",
            "reasons": ["Empty QR code or unreadable data"],
            "original_url": "",
            "final_url": "",
            "domain": "Empty Payload",
            "hostname": "",
            "scheme": "",
            "is_payment": False,
            "payment_details": None,
            "redirects": {"hops": [], "hop_urls": [], "hop_count": 0, "destination_drift": False},
            "heuristics": {
                "findings": [{"type": "empty_payload", "severity": "CRITICAL", "penalty": 100, "message": "Empty payload"}],
                "typosquatting_detected": False,
                "punycode_detected": False,
                "high_risk_tld": False,
                "suspicious_file_extension": False,
                "resolved_ip": "None"
            }
        }

    # --- Step 1: Detect and Handle UPI Payment Payloads ---
    if is_upi_payload(clean_input):
        return parse_upi_payload(clean_input)

    # --- Step 2: Detect and Handle Non-Web Payloads (Contact, WiFi, Plain Text) ---
    non_url_result = parse_non_url_payload(clean_input)
    if non_url_result is not None:
        return non_url_result

    # --- Step 3: Web URL Analysis Pipeline ---
    initial_heuristics = analyze_heuristics(clean_input)
    
    total_penalties = initial_heuristics.get("penalties", 0)
    all_reasons: List[str] = list(initial_heuristics.get("reasons", []))
    all_findings: List[Dict[str, Any]] = list(initial_heuristics.get("findings", []))

    redirect_info = {
        "hops": [],
        "hop_urls": [],
        "hop_count": 0,
        "is_shortener": False,
        "destination_drift": False,
        "initial_domain": initial_heuristics.get("registered_domain", ""),
        "final_domain": initial_heuristics.get("registered_domain", ""),
        "trace_error": None
    }
    final_url = clean_input
    resolved_ip = "Standard DNS"

    if follow_redirects and initial_heuristics.get("is_valid", False):
        trace_result = trace_redirects(clean_input)
        redirect_info = {
            "hops": trace_result.get("hops", []),
            "hop_urls": trace_result.get("hop_urls", []),
            "hop_count": trace_result.get("hop_count", 0),
            "is_shortener": trace_result.get("is_shortener", False),
            "destination_drift": trace_result.get("destination_drift", False),
            "initial_domain": trace_result.get("initial_domain", ""),
            "final_domain": trace_result.get("final_domain", ""),
            "trace_error": trace_result.get("trace_error")
        }
        final_url = trace_result.get("final_url", clean_input)
        resolved_ip = trace_result.get("resolved_ip", "Standard DNS")
        total_penalties += trace_result.get("penalties", 0)
        all_reasons.extend(trace_result.get("reasons", []))

        # Check for HTTPS upgrade: if initial was plain HTTP but redirected to HTTPS,
        # discount the HTTP transport penalty since final connection is encrypted
        if clean_input.lower().startswith("http://") and final_url.lower().startswith("https://"):
            # Reduce 8 points for successful HTTPS upgrade
            total_penalties = max(0, total_penalties - 8)
            all_reasons = [r for r in all_reasons if "Unencrypted transport" not in r]
            all_reasons.append("Secure upgrade: HTTP connection safely redirected to encrypted HTTPS")

        # Step 4: Analyze Final URL if it differed from initial
        if final_url != clean_input:
            final_heuristics = analyze_heuristics(final_url)
            final_penalties = final_heuristics.get("penalties", 0)
            if final_penalties > 0:
                total_penalties += int(final_penalties * 0.8)
                for r in final_heuristics.get("reasons", []):
                    final_reason = f"Final destination: {r}"
                    if final_reason not in all_reasons:
                        all_reasons.append(final_reason)
                all_findings.extend(final_heuristics.get("findings", []))

    # Calculate final score (Clamped between 0 and 100)
    risk_score = min(100, max(0, total_penalties))

    # Categorize Status based on defined scale:
    # SAFE: 0–29 | SUSPICIOUS: 30–69 | DANGEROUS: 70–100
    if risk_score >= 70:
        status = "DANGEROUS"
        recommendation = "AVOID. High probability of malicious intent, credential theft, or fraud."
    elif risk_score >= 30:
        status = "SUSPICIOUS"
        recommendation = "EXERCISE CAUTION. Suspicious destination indicators or unexpected redirect behavior detected."
    else:
        status = "SAFE"
        recommendation = "Destination shows standard security indicators. Safe to proceed with normal caution."
        if not all_reasons:
            all_reasons.append("Standard domain structure and valid protocols detected")
            all_reasons.append("No spoofing, anomalous redirects, or known threat indicators found")

    # Deduplicate reasons while preserving order
    seen = set()
    deduped_reasons = []
    for reason in all_reasons:
        lower_r = reason.lower()
        if lower_r not in seen:
            seen.add(lower_r)
            deduped_reasons.append(reason)

    return {
        "score": risk_score,
        "status": status,
        "recommendation": recommendation,
        "reasons": deduped_reasons,
        "original_url": clean_input,
        "final_url": final_url,
        "domain": redirect_info.get("final_domain") or initial_heuristics.get("registered_domain"),
        "hostname": initial_heuristics.get("hostname"),
        "scheme": initial_heuristics.get("scheme", "http"),
        "is_payment": False,
        "payment_details": None,
        "redirects": redirect_info,
        "heuristics": {
            "findings": all_findings,
            "spoof_info": initial_heuristics.get("spoof_info", {}),
            "entropy": initial_heuristics.get("entropy", 0),
            "typosquatting_detected": initial_heuristics.get("typosquatting_detected", False),
            "similar_to_brand": initial_heuristics.get("similar_to_brand"),
            "punycode_detected": initial_heuristics.get("punycode_detected", False),
            "high_risk_tld": initial_heuristics.get("high_risk_tld", False),
            "suspicious_file_extension": initial_heuristics.get("suspicious_file_extension", False),
            "resolved_ip": resolved_ip
        }
    }
