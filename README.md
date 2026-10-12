# FORESIGHT
## QR Code Destination Analysis & Risk Assessment

> *“Know the risk before you take the step.”*

A preventive cybersecurity platform designed to protect users from deceptive, fraudulent, or malicious QR codes by forensically inspecting and assessing the destination **before** any connection is established.

---

## 1. Project Overview

**FORESIGHT** is a deterministic, rule-based QR security verification utility. When a user scans a QR code in the physical or digital world, they are typically unable to preview the final destination URL or inspect intermediate redirection hops. Attackers exploit this blind spot (commonly termed "Quishing") to direct unsuspecting victims to credential harvesters, fraudulent payment gateways, and malicious executables.

FORESIGHT acts as a preventive security barrier: it dynamically decodes the QR code, traces HTTP redirection chains, evaluates structural risk indicators, displays transparent risk explanations, and allows the user to make an informed decision (*Avoid* or *Proceed*).

---

## 2. Problem Statement

QR codes are ubiquitous across point-of-sale systems, transit, dining, marketing, and multi-factor authentication. However, conventional QR reader applications blindly open embedded URLs directly in the default browser.

This lack of pre-execution destination transparency enables malicious actors to:
- Conceal deceptive domains and lookalike brand spoofs (typosquatting).
- Cloak final destinations behind URL shorteners and multi-hop HTTP redirects.
- Leverage high-risk top-level domains (TLDs) and unusual ports.
- Embed credential harvesting forms or initiate unauthorized file downloads.

---

## 3. Solution

FORESIGHT eliminates the blind leap of trust:
- **Pre-Execution Destination Inspection**: Intercepts the destination URL and resolves intermediate redirect hops without executing client-side scripts.
- **Explainable Threat Indicators**: Highlights the specific forensic reasons behind each risk assessment.
- **User Agency**: Places the final choice firmly in the user's hands with clear Avoid and Proceed actions.
- **Incident Escalation**: Automatically generates structured incident reports when high-volume distribution surges are detected.

---

## 4. Key Features

- **Multi-Modal Universal QR Ingestion**:
  - Live in-browser optical camera viewfinder using `jsQR`.
  - Server-side image decoding (PNG, JPG, WEBP) via `zxing-cpp` and OpenCV with grayscale and contrast preprocessing.
  - Direct URL testing and manual destination verification.
- **Deterministic Heuristic Risk Engine**:
  - Levenshtein distance calculations against high-profile institutions (e.g., PayPal, Apple, Google, Microsoft, Amazon, SBI, HDFC, PayTM).
  - Detection of homograph attacks and Punycode domains.
  - Flagging of high-risk TLDs (`.xyz`, `.top`, `.tk`, etc.) and raw IP destinations.
  - Identification of suspicious file extensions (`.apk`, `.exe`, `.bat`, `.sh`).
- **Hop-by-Hop Redirect Tracing**:
  - Captures full HTTP status codes (`301`, `302`, `307`, `308`, `200`).
  - Detects destination domain drift between the initial QR payload and the final landed URL.
- **User Authentication & Private History**:
  - PBKDF2-HMAC-SHA256 password derivation (200,000 salt iterations).
  - Strict data isolation ensuring each user only accesses their own scan records.
- **High-Surge Incident Reports**:
  - Integrated 24-hour unique access tracking per destination hash.
  - Automatic generation of structured reports for cybercell review upon reaching 100+ unique accesses in a rolling 24-hour window.

---

## 5. How FORESIGHT Works

FORESIGHT employs a deterministic, zero-AI approach. Every verdict is computed using transparent, explainable heuristics:

1. **Ingest & Decode**: Extracts raw payload string from the camera feed, uploaded image, or manual input.
2. **Normalize & Parse**: Resolves the protocol, hostname, port, and path components.
3. **Trace Redirects**: Sends controlled HTTP HEAD/GET requests with custom user-agents to uncover the full redirect trail without executing client JavaScript or downloading executable payloads.
4. **Evaluate Indicators**: Computes penalty weights for typosquatting distance, IP-based destinations, TLD reputation, and path anomalies.
5. **Score & Classify**: Generates a composite risk score (0 to 100) and displays clear recommendations.

---

## 6. Complete Workflow

```
[ QR Code ]
     │
     ▼
[ Ingestion (Camera / Upload / URL) ]
     │
     ▼
[ QR Decoding (zxing-cpp / jsQR) ]
     │
     ▼
[ Extract Raw Destination URL ]
     │
     ▼
[ Safe Redirect Tracing (Hop-by-Hop) ]
     │
     ▼
[ Heuristic & Structural Analysis ]
     │
     ▼
[ Composite Risk Score (0 - 100) ]
     │
     ├── SAFE (0 - 29)
     ├── SUSPICIOUS (30 - 69)
     └── DANGEROUS (70 - 100)
     │
     ▼
[ User Decision: Avoid & Discard  OR  Proceed to Destination ]
     │
     ▼
[ Log Access to User History (Isolated) ]
     │
     ▼
[ 24-Hour Rolling Access Tracker ]
     │
     └─ If >= 100 Unique Accesses in 24h ──> [ Structured Incident Report Generated ]
```

---

## 7. Risk Assessment

Risk scores range from **0 to 100**, categorized into three transparent status tiers:

| Tier | Score Range | Description | Typical Indicators |
| :--- | :---: | :--- | :--- |
| **SAFE** | 0 – 29 | Standard legitimate destination | Reputable domain, standard HTTPS port, zero spoofing indicators. |
| **SUSPICIOUS** | 30 – 69 | Caution strongly advised | Multiple redirect hops, domain drift, unverified TLD, or high subdomain depth. |
| **DANGEROUS** | 70 – 100 | High risk of fraud or malware | Brand typosquatting / spoofing, raw IP address, executable file extension, Punycode tricks. |

Every evaluation provides human-readable bullet points explaining the exact factors contributing to the score.

---

## 8. Integrated Reporting Mechanism

To address large-scale physical QR tampering campaigns (such as sticker overlays on transit payment points), FORESIGHT includes an integrated early-warning reporting mechanism:

- Every destination access is recorded with a SHA-256 hash and timestamp in the local SQLite database.
- A rolling **24-hour observation window** evaluates unique client accesses.
- When **100 or more unique accesses** occur for the same destination within 24 hours, the system generates a **Structured Incident Report**.
- *Important*: Reaching the 100+ threshold is an indicator of distribution volume, not an automatic proof of malice. The report combines access metrics with the heuristic security assessment to provide structured context for cybercell review.

---

## 9. Technology Stack

- **Backend**: Python 3.10+, FastAPI, Uvicorn, Requests
- **Computer Vision & Decoding**: `zxing-cpp`, OpenCV (`opencv-python`), `Pillow`
- **Frontend**: Clean Semantic HTML5, CSS3 (Light Editorial & Dark Graphite palettes), Vanilla JavaScript (ES6+)
- **Client Scanner**: `jsQR` (offline, in-browser optical decoding)
- **Database**: SQLite3 (`foresight.db`) with parameterized queries and WAL mode
- **Security & Cryptography**: Python standard `hashlib` (PBKDF2-HMAC-SHA256, SHA-256 tokens)
- **Version Control & CI/CD**: Git, GitHub

---

## 10. Application Pages

- **`/login`**: Sign-in page with password visibility toggle. Default entry point for unauthenticated visitors.
- **`/signup`**: User registration with salted PBKDF2 password derivation.
- **`/scan`**: Central workspace for camera scanning, image upload, and direct URL inspection.
- **`/result/<scan_id>`**: Detailed forensic destination breakdown with risk dial, redirect hops, threat factors, and Avoid/Proceed actions.
- **`/history`**: Personal scan audit ledger with domain search, status filter pills, and report modals.
- **`/reports`**: QR Security Incident Reports tracking destinations that reach 100+ unique accesses in 24 hours.
- **`/profile`**: Analyst profile, session management, and metrics breakdown.

---

## 11. Screenshots

### Login
![FORESIGHT Login](docs/screenshots/login.png)

### QR Scan
![FORESIGHT Scan](docs/screenshots/scan.png)

### Analysis Result
![FORESIGHT Result](docs/screenshots/result.png)

### Scan History
![FORESIGHT History](docs/screenshots/history.png)

### Reports
![FORESIGHT Reports](docs/screenshots/reports.png)

### Profile
![FORESIGHT Profile](docs/screenshots/profile.png)

---

## 12. Installation

### Prerequisites
- Python 3.10 or higher
- Git

### Step-by-Step Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/SakshamGupta1210/Foresight.git
   cd Foresight
   ```

2. **Create and activate a virtual environment:**
   - **Windows:**
     ```bash
     python -m venv venv
     venv\Scripts\activate
     ```
   - **Linux / macOS:**
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize environment configuration:**
   ```bash
   cp .env.example .env
   ```

5. **Start the application:**
   ```bash
   python run.py
   ```
   *The server will start at `http://localhost:8000`.*

---

## 13. Configuration / Environment Variables

Configuration is loaded from environment variables or `.env`:

| Variable | Default | Purpose |
| :--- | :---: | :--- |
| `HOST` | `0.0.0.0` | Server bind host address |
| `PORT` | `8000` | Application server listening port |
| `SECRET_KEY` | *(Generated)* | Secret key for session management |
| `VIRUSTOTAL_API_KEY` | *(Optional)* | Optional integration for third-party intelligence feeds |
| `URLHAUS_API_KEY` | *(Optional)* | Optional integration for URLhaus abuse intelligence |

---

## 14. Project Structure

```
Foresight/
├── backend/
│   ├── analyzer/
│   │   ├── heuristics.py        # Deterministic threat indicators & typosquatting logic
│   │   ├── redirect_tracer.py   # Hop-by-hop HTTP redirect tracer
│   │   └── risk_engine.py       # Composite risk calculation & verdict engine
│   ├── storage/
│   │   └── access_tracker.py    # SQLite database access, PBKDF2 auth, 24h reporting
│   ├── main.py                  # FastAPI server routes, middleware & static mounting
│   └── qr_decoder.py            # Computer vision decoding (OpenCV + zxing-cpp)
├── frontend/
│   ├── css/
│   │   └── styles.css           # Clean design system & responsive styling
│   ├── js/
│   │   ├── app.js               # Legacy utilities
│   │   ├── auth-guard.js        # Authentication session & header manager
│   │   └── jsQR.js              # Client-side camera QR scanner library
│   ├── pages/
│   │   ├── history.html         # Scan audit history page
│   │   ├── login.html           # Sign in interface
│   │   ├── profile.html         # Analyst profile & statistics
│   │   ├── reports.html         # Incident reporting ledger (100+ accesses / 24h)
│   │   ├── result.html          # Destination forensics & risk evaluation
│   │   ├── scan.html            # Primary QR scanning workspace
│   │   └── signup.html          # Account registration
│   └── index.html               # Root redirect helper
├── sample_qrs/                  # Test QR image assets for verification
├── tests/
│   └── test_foresight.py        # Automated test suite (16 unit tests)
├── docs/
│   └── screenshots/             # Interface screenshots
├── .env.example                 # Template environment variables
├── .gitignore                   # Exclusions for virtual environments, secrets, databases
├── requirements.txt             # Python package dependencies
├── run.py                       # Server entry point
├── start_foresight.bat          # Windows launcher script
└── README.md                    # Project documentation
```

---

## 15. Security Considerations

- **No Plaintext Passwords**: Passwords are salted and hashed using PBKDF2-HMAC-SHA256 with 200,000 iterations.
- **Isolated User Scans**: Multi-tenant database records enforce strict ownership checks; users cannot view other users' scan histories.
- **Safe Tracing**: Redirection tracing limits request headers and disallows client-side script execution during probe requests.
- **Database Exclusions**: Local databases containing personal scans (`foresight.db`) are excluded from version control via `.gitignore`.

---

## 16. Reporting Logic

The reporting mechanism monitors physical distribution abuse:
$$\text{Unique Accesses}(D) = \left| \{ \text{Client ID} \mid (D, t) \in \text{Accesses}, t \ge T_{\text{current}} - 24\text{h} \} \right|$$
If $\text{Unique Accesses}(D) \ge 100$:
- Generates an incident record containing target domain, final destination, access count, and forensic risk indicators.
- Classifies incident status according to computed threat level (`CRITICAL / FLAGGED / NOTICE`).
- Provides structured context for administrative or cybercell review.

---

## 17. Limitations

- **Heuristic Assessment**: Risk scores are evaluations based on observable indicators; they do not guarantee that a clean destination cannot be updated maliciously later.
- **Dynamic Content**: Pages requiring JavaScript execution or CAPTCHA cannot have their post-login contents fully rendered during a headless redirect trace.
- **Network Dependency**: Live redirect tracing requires an active network connection to query destination hostnames.

---

## 18. Future Scope

- Integration with official threat feeds (VirusTotal, URLhaus) via optional environment keys.
- Browser extension to inspect desktop web-based QR codes.
- Exportable PDF incident dossiers for reporting documentation.
- Automated webhook notifications for high-volume incident triggers.

---

## 19. Disclaimer

FORESIGHT is a security verification and educational utility. Risk scores and verdicts represent automated evaluations based on observable heuristic indicators and do not constitute an absolute guarantee of safety or maliciousness. Users should always exercise personal caution when interacting with untrusted destinations.

---

## 20. Team / Author

**FORESIGHT Project Team**  
GitHub: [@SakshamGupta1210](https://github.com/SakshamGupta1210)  
Repository: [https://github.com/SakshamGupta1210/Foresight](https://github.com/SakshamGupta1210/Foresight)
