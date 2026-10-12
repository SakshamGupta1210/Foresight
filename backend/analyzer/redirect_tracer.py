"""
FORESIGHT - Safe Redirect Chain Tracer & Destination Drift Detector
Unravels shortened links and inspects multi-hop HTTP redirect chains safely.
"""

from urllib.parse import urlparse
import requests
from typing import Dict, List, Any

KNOWN_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "qr.ae", "rebrand.ly",
    "tiny.cc", "t.ly", "shorturl.at", "bl.ink"
}

def extract_base_domain(url: str) -> str:
    """Extracts base domain from a URL for drift comparison."""
    try:
        parsed = urlparse(url)
        host = (parsed.netloc or "").split(":")[0].lower()
        parts = host.split(".")
        if len(parts) >= 2:
            if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "gov", "edu"}:
                return ".".join(parts[-3:])
            return ".".join(parts[-2:])
        return host
    except Exception:
        return ""


def trace_redirects(target_url: str, max_hops: int = 6, timeout: float = 4.0) -> Dict[str, Any]:
    """
    Safely traces redirect chains without downloading file bodies.
    Detects destination drift, loop traps, and excessive redirection.
    """
    clean_url = target_url.strip()
    if not clean_url.startswith(("http://", "https://")):
        clean_url = "https://" + clean_url

    hops: List[Dict[str, Any]] = []
    reasons: List[str] = []
    penalties = 0
    current_url = clean_url
    initial_domain = extract_base_domain(clean_url)
    visited_urls = set()

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 ForesightSecurityScanner/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5"
    })

    # Check if initial URL is a known shortener
    initial_host = urlparse(clean_url).netloc.split(":")[0].lower()
    is_shortener = initial_host in KNOWN_URL_SHORTENERS
    if is_shortener:
        penalties += 15
        reasons.append(f"URL uses a link shortener ({initial_host}) to conceal true destination")

    trace_error = None

    for hop_idx in range(max_hops):
        if current_url in visited_urls:
            penalties += 35
            reasons.append("Redirect loop detected (URL redirects back to a previously visited page)")
            break
        visited_urls.add(current_url)

        try:
            # Try HEAD first for safety and low bandwidth
            try:
                resp = session.head(current_url, allow_redirects=False, timeout=timeout)
                if resp.status_code in [405, 501]: # Method Not Allowed
                    resp = session.get(current_url, allow_redirects=False, stream=True, timeout=timeout)
            except requests.RequestException:
                # Fallback to streaming GET with immediate close
                resp = session.get(current_url, allow_redirects=False, stream=True, timeout=timeout)

            status = resp.status_code
            hop_domain = extract_base_domain(current_url)
            hops.append({
                "hop": hop_idx + 1,
                "url": current_url,
                "status_code": status,
                "domain": hop_domain
            })

            # Check if this response redirects
            if status in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location")
                if not location:
                    break

                # Resolve relative redirect URLs
                next_url = requests.compat.urljoin(current_url, location)
                current_url = next_url
            else:
                # Reached final non-redirect response
                break

        except requests.exceptions.Timeout:
            trace_error = "Connection timed out during destination verification"
            hops.append({
                "hop": hop_idx + 1,
                "url": current_url,
                "status_code": 408,
                "domain": extract_base_domain(current_url)
            })
            break
        except requests.exceptions.SSLError:
            trace_error = "SSL/TLS Certificate verification failed at destination"
            penalties += 30
            reasons.append("SSL/TLS Certificate invalid or untrusted on destination")
            hops.append({
                "hop": hop_idx + 1,
                "url": current_url,
                "status_code": 495,
                "domain": extract_base_domain(current_url)
            })
            break
        except requests.exceptions.ConnectionError:
            trace_error = "Host could not be reached (DNS failure or connection refused)"
            hops.append({
                "hop": hop_idx + 1,
                "url": current_url,
                "status_code": 503,
                "domain": extract_base_domain(current_url)
            })
            break
        except Exception as e:
            trace_error = f"Redirect trace aborted: {str(e)}"
            break

    final_url = hops[-1]["url"] if hops else clean_url
    final_domain = extract_base_domain(final_url)
    hop_count = max(0, len(hops) - 1)

    # Destination Drift Check
    destination_drift = (initial_domain != final_domain) and (bool(initial_domain) and bool(final_domain))
    if destination_drift:
        # If it was a shortener, drift is expected, but still noteworthy
        if not is_shortener:
            penalties += 30
            reasons.append(f"Destination drift detected: Initial domain '{initial_domain}' redirected to different domain '{final_domain}'")
        else:
            penalties += 10
            reasons.append(f"Shortened link resolves to external landing domain: '{final_domain}'")

    # Multi-hop penalty
    if hop_count >= 3:
        penalties += 25
        reasons.append(f"Suspiciously long redirect chain detected ({hop_count} hops)")
    elif hop_count >= 1:
        reasons.append(f"Redirect found: Followed {hop_count} intermediate hop(s) to reach destination")

    return {
        "initial_url": clean_url,
        "final_url": final_url,
        "initial_domain": initial_domain,
        "final_domain": final_domain,
        "hops": hops,
        "hop_count": hop_count,
        "is_shortener": is_shortener,
        "destination_drift": destination_drift,
        "trace_error": trace_error,
        "penalties": penalties,
        "reasons": reasons
    }
