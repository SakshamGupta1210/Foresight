"""
FORESIGHT - Safe Redirect Chain Tracer & Destination Drift Detector
Unravels shortened links and inspects multi-hop HTTP redirect chains safely.
Includes strict Server-Side Request Forgery (SSRF) defenses against private/internal networks.
"""

from urllib.parse import urlparse
import ipaddress
import socket
import requests
from typing import Dict, List, Any, Tuple, Optional

KNOWN_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "qr.ae", "rebrand.ly",
    "tiny.cc", "t.ly", "shorturl.at", "bl.ink"
}

MULTI_PART_TLDS = {
    "co.in", "net.in", "org.in", "gen.in", "ind.in", "ac.in", "edu.in", "res.in",
    "gov.in", "mil.in", "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk",
    "sch.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.za", "org.za", "com.br", "net.br", "org.br", "com.sg", "edu.sg", "gov.sg"
}


def extract_base_domain(url: str) -> str:
    """Extracts base registered domain from a URL for drift comparison."""
    try:
        parsed = urlparse(url)
        host = (parsed.netloc or "").split(":")[0].lower()
        parts = host.split(".")
        if len(parts) >= 2:
            if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in MULTI_PART_TLDS:
                return ".".join(parts[-3:])
            if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "gov", "edu"}:
                return ".".join(parts[-3:])
            return ".".join(parts[-2:])
        return host
    except Exception:
        return ""


def is_safe_host_for_network(host: str) -> Tuple[bool, str, Optional[str]]:
    """
    Validates that a hostname/IP is safe to connect to from the server.
    Blocks loopback, private RFC1918, link-local, carrier-grade NAT, and reserved IP ranges
    to prevent Server-Side Request Forgery (SSRF).
    Returns (is_safe, error_reason, resolved_ip).
    """
    clean_host = host.split(":")[0].strip().lower()
    if not clean_host:
        return False, "Empty destination host", None

    # Disallow explicit localhost or cloud metadata hostnames
    if clean_host in {"localhost", "127.0.0.1", "::1", "metadata.google.internal", "instance-data"}:
        return False, f"Access to internal/loopback host '{clean_host}' is blocked (SSRF defense)", "127.0.0.1"

    # Check if host is a raw IP literal
    try:
        ip_obj = ipaddress.ip_address(clean_host)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast:
            return False, f"Direct access to internal/private IP ({clean_host}) is blocked (SSRF defense)", clean_host
        return True, "", clean_host
    except ValueError:
        pass

    # Resolve hostname via DNS
    try:
        resolved = socket.getaddrinfo(clean_host, None)
        if not resolved:
            return False, f"Could not resolve host '{clean_host}' via DNS", None

        first_ip = None
        for entry in resolved:
            ip_str = entry[4][0]
            if not first_ip:
                first_ip = ip_str
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast:
                return False, f"Destination '{clean_host}' resolves to internal IP ({ip_str}) - blocked for security", ip_str

        return True, "", first_ip
    except socket.gaierror:
        return False, f"DNS resolution failed for '{clean_host}'", None
    except Exception as e:
        return False, f"Host verification error: {str(e)}", None


def trace_redirects(target_url: str, max_hops: int = 6, timeout: float = 3.5) -> Dict[str, Any]:
    """
    Safely traces redirect chains without downloading file bodies.
    Detects destination drift, loop traps, and excessive redirection.
    Enforces SSRF prevention before any outbound connection.
    """
    clean_url = target_url.strip()
    if not clean_url.startswith(("http://", "https://")):
        clean_url = "https://" + clean_url

    hops: List[Dict[str, Any]] = []
    hop_urls: List[str] = []
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
        penalties += 10
        reasons.append(f"URL uses a link shortener ({initial_host}) to conceal the final destination")

    trace_error = None
    last_resolved_ip = None

    for hop_idx in range(max_hops):
        if current_url in visited_urls:
            penalties += 35
            reasons.append("Redirect loop detected (URL redirects back to a previously visited page)")
            break
        visited_urls.add(current_url)

        # SSRF Check before sending request
        current_host = urlparse(current_url).netloc.split(":")[0].lower()
        is_safe, block_reason, resolved_ip = is_safe_host_for_network(current_host)
        if resolved_ip:
            last_resolved_ip = resolved_ip

        if not is_safe:
            penalties += 40
            trace_error = block_reason
            reasons.append(f"SSRF Protection: {block_reason}")
            hops.append({
                "hop": hop_idx + 1,
                "url": current_url,
                "status_code": 403,
                "domain": extract_base_domain(current_url)
            })
            hop_urls.append(current_url)
            break

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
            hop_urls.append(current_url)

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
            hop_urls.append(current_url)
            break
        except requests.exceptions.SSLError:
            trace_error = "SSL/TLS Certificate verification failed at destination"
            penalties += 25
            reasons.append("SSL/TLS Certificate invalid or untrusted on destination")
            hops.append({
                "hop": hop_idx + 1,
                "url": current_url,
                "status_code": 495,
                "domain": extract_base_domain(current_url)
            })
            hop_urls.append(current_url)
            break
        except requests.exceptions.ConnectionError:
            trace_error = "Host could not be reached (offline or connection refused)"
            hops.append({
                "hop": hop_idx + 1,
                "url": current_url,
                "status_code": 503,
                "domain": extract_base_domain(current_url)
            })
            hop_urls.append(current_url)
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
        if not is_shortener:
            penalties += 25
            reasons.append(f"Destination drift detected: Initial domain '{initial_domain}' redirected to different domain '{final_domain}'")
        else:
            reasons.append(f"Shortened link resolves to external landing domain: '{final_domain}'")

    # Multi-hop penalty
    if hop_count >= 3:
        penalties += 20
        reasons.append(f"Long redirect chain detected ({hop_count} hops)")
    elif hop_count >= 1:
        reasons.append(f"Redirect followed {hop_count} intermediate hop(s) to reach destination")

    return {
        "initial_url": clean_url,
        "final_url": final_url,
        "initial_domain": initial_domain,
        "final_domain": final_domain,
        "hops": hops,
        "hop_urls": hop_urls,
        "hop_count": hop_count,
        "is_shortener": is_shortener,
        "destination_drift": destination_drift,
        "trace_error": trace_error,
        "resolved_ip": last_resolved_ip or "Resolved via DNS",
        "penalties": penalties,
        "reasons": reasons
    }
