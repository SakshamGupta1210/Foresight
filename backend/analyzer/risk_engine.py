"""
FORESIGHT - Risk Scoring & Classification Engine
Deterministic rule-based risk evaluation.
Combines static URL heuristics, redirect tracking, and destination drift analysis.
"""

from typing import Dict, List, Any
from .heuristics import analyze_heuristics
from .redirect_tracer import trace_redirects

def evaluate_destination(raw_payload: str, follow_redirects: bool = True) -> Dict[str, Any]:
    """
    Core evaluation pipeline:
    1. Static heuristic analysis of original payload.
    2. Dynamic redirect trace & destination drift detection.
    3. Static heuristic analysis of final resolved URL (if different).
    4. Deterministic score aggregation (0 - 100).
    5. Categorical classification (SAFE / SUSPICIOUS / DANGEROUS).
    6. Explainability breakdown: explicit list of reasons.
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
            "redirects": {"hops": [], "hop_count": 0, "destination_drift": False},
            "heuristics": {"findings": []}
        }

    # Step 1: Initial Heuristic Scan
    initial_heuristics = analyze_heuristics(clean_input)
    
    total_penalties = initial_heuristics.get("penalties", 0)
    all_reasons: List[str] = list(initial_heuristics.get("reasons", []))
    all_findings: List[Dict[str, Any]] = list(initial_heuristics.get("findings", []))

    # Step 2: Redirect & Destination Drift Tracing
    redirect_info = {
        "hops": [],
        "hop_count": 0,
        "is_shortener": False,
        "destination_drift": False,
        "initial_domain": initial_heuristics.get("registered_domain", ""),
        "final_domain": initial_heuristics.get("registered_domain", ""),
        "trace_error": None
    }
    final_url = clean_input

    if follow_redirects and initial_heuristics.get("is_valid", False):
        trace_result = trace_redirects(clean_input)
        redirect_info = {
            "hops": trace_result.get("hops", []),
            "hop_count": trace_result.get("hop_count", 0),
            "is_shortener": trace_result.get("is_shortener", False),
            "destination_drift": trace_result.get("destination_drift", False),
            "initial_domain": trace_result.get("initial_domain", ""),
            "final_domain": trace_result.get("final_domain", ""),
            "trace_error": trace_result.get("trace_error")
        }
        final_url = trace_result.get("final_url", clean_input)
        total_penalties += trace_result.get("penalties", 0)
        all_reasons.extend(trace_result.get("reasons", []))

        # Step 3: Analyze Final URL if it differed from initial
        if final_url != clean_input:
            final_heuristics = analyze_heuristics(final_url)
            # Add final destination specific penalties
            final_penalties = final_heuristics.get("penalties", 0)
            if final_penalties > 0:
                total_penalties += int(final_penalties * 0.8) # Weight final landing indicators
                for r in final_heuristics.get("reasons", []):
                    final_reason = f"Final destination: {r}"
                    if final_reason not in all_reasons:
                        all_reasons.append(final_reason)
                all_findings.extend(final_heuristics.get("findings", []))

    # Calculate final score (Clamped between 0 and 100)
    risk_score = min(100, max(0, total_penalties))

    # Categorize Status
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
        if reason.lower() not in seen:
            seen.add(reason.lower())
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
        "redirects": redirect_info,
        "heuristics": {
            "findings": all_findings,
            "spoof_info": initial_heuristics.get("spoof_info", {}),
            "entropy": initial_heuristics.get("entropy", 0)
        }
    }
