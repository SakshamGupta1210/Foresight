/**
 * FORESIGHT: QR Code Destination Analysis & Risk Assessment
 * Streamlined User Flow Controller:
 * LOGIN PAGE -> USER LOGS IN -> MAIN FORESIGHT PAGE (SCAN QR) ->
 * ANALYZE QR -> SHOW RESULT -> SAVE TO USER HISTORY -> VIEW HISTORY ANYTIME
 */

let videoStream = null;
let scanInterval = null;
let currentAnalysisData = null;
let currentIncidentDossier = null;
let currentUser = null;
let currentView = 'login';
let historyFilter = 'ALL';
let historySearchQuery = '';
let searchDebounceTimer = null;

const EXAMPLE_TARGETS = {
  safe: "https://en.wikipedia.org/wiki/Computer_security",
  suspicious: "http://tinyurl.com/sample-drift-test",
  dangerous: "http://paypa1-security-center.xyz/signin/verify-account.exe"
};

// =====================================================================
// INITIALIZATION & DIRECT LOGIN-FIRST ROUTING
// =====================================================================

document.addEventListener("DOMContentLoaded", () => {
  initAuthFlow();
});

function getAuthToken() {
  return localStorage.getItem("foresight_token") || "";
}

function setAuthToken(token) {
  if (token) {
    localStorage.setItem("foresight_token", token);
  } else {
    localStorage.removeItem("foresight_token");
  }
}

async function initAuthFlow() {
  const token = getAuthToken();
  if (!token) {
    // 1. FIRST PAGE MUST BE LOGIN
    updateAuthUI(null);
    navigateTo('login');
    return;
  }

  try {
    const resp = await fetch('/api/auth/me', {
      headers: { 'Authorization': `Bearer ${token}` }
    });

    if (resp.ok) {
      const data = await resp.json();
      currentUser = data.user;
      updateAuthUI(currentUser);
      // Take user directly to Main FORESIGHT Page (scanner)
      navigateTo('scanner');
    } else {
      // Invalid/expired token -> return to login
      setAuthToken(null);
      currentUser = null;
      updateAuthUI(null);
      navigateTo('login');
    }
  } catch (err) {
    console.warn("Auth validation error:", err);
    updateAuthUI(null);
    navigateTo('login');
  }
}

function updateAuthUI(user) {
  const loggedInGroup = document.getElementById("auth-state-loggedin");
  const loggedOutGroup = document.getElementById("auth-state-loggedout");
  const desktopNav = document.getElementById("desktop-nav-links");

  if (user) {
    loggedInGroup.style.display = "flex";
    loggedOutGroup.style.display = "none";
    desktopNav.style.display = "flex";
    document.getElementById("header-user-name").textContent = user.name;
    document.getElementById("user-avatar-initial").textContent = user.name.charAt(0).toUpperCase();
  } else {
    loggedInGroup.style.display = "none";
    loggedOutGroup.style.display = "flex";
    desktopNav.style.display = "none";
  }
}

function handleBrandClick() {
  if (currentUser) {
    navigateTo('scanner');
  } else {
    navigateTo('login');
  }
}

function navigateTo(viewName) {
  // If not logged in, only 'login' and 'register' are allowed
  if (!currentUser && viewName !== 'login' && viewName !== 'register') {
    showToast("Please sign in to access FORESIGHT.", "warning");
    viewName = 'login';
  }

  currentView = viewName;

  // Hide all sections
  document.querySelectorAll('.view-section').forEach(sec => sec.classList.remove('active'));

  // Show target section
  const targetSec = document.getElementById(`view-${viewName}`);
  if (targetSec) {
    targetSec.classList.add('active');
  }

  // Update navigation active state
  document.querySelectorAll('.desktop-nav .nav-link').forEach(link => link.classList.remove('active'));
  const activeNavLink = document.getElementById(`nav-${viewName}`);
  if (activeNavLink) {
    activeNavLink.classList.add('active');
  }

  // Stop camera if leaving scanner
  if (viewName !== 'scanner') {
    stopCamera();
  }

  // Scroll to top
  window.scrollTo({ top: 0, behavior: 'smooth' });

  // View specific data loaders
  if (viewName === 'history') {
    loadScanHistory();
  } else if (viewName === 'profile') {
    loadProfile();
  }
}

function toggleMobileNav() {
  const drawer = document.getElementById("mobile-nav-drawer");
  drawer.classList.toggle("active");
}

function togglePasswordVisibility(inputId) {
  const input = document.getElementById(inputId);
  if (!input) return;
  input.type = input.type === 'password' ? 'text' : 'password';
}


// =====================================================================
// AUTHENTICATION LOGIC (LOGIN, REGISTER, LOGOUT)
// =====================================================================

async function handleLoginSubmit(event) {
  event.preventDefault();
  const errorAlert = document.getElementById("login-error-alert");
  errorAlert.style.display = "none";

  const email = document.getElementById("login-email").value.trim();
  const password = document.getElementById("login-password").value;
  const submitBtn = document.getElementById("btn-login-submit");

  if (!email || !password) {
    errorAlert.textContent = "Email and password are required.";
    errorAlert.style.display = "block";
    return;
  }

  submitBtn.disabled = true;
  submitBtn.textContent = "Verifying...";

  try {
    const resp = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password })
    });

    const data = await resp.json();

    if (!resp.ok) {
      errorAlert.textContent = data.detail || "Authentication failed.";
      errorAlert.style.display = "block";
      return;
    }

    setAuthToken(data.token);
    currentUser = data.user;
    updateAuthUI(currentUser);
    showToast(`Welcome back, ${currentUser.name}!`, "success");
    document.getElementById("login-form").reset();
    
    // DIRECTLY TO MAIN FORESIGHT PAGE
    navigateTo('scanner');

  } catch (err) {
    errorAlert.textContent = "Unable to connect to server. Please try again.";
    errorAlert.style.display = "block";
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = "Login to FORESIGHT ➔";
  }
}

async function handleRegisterSubmit(event) {
  event.preventDefault();
  const errorAlert = document.getElementById("register-error-alert");
  errorAlert.style.display = "none";

  const name = document.getElementById("reg-name").value.trim();
  const email = document.getElementById("reg-email").value.trim();
  const password = document.getElementById("reg-password").value;
  const confirmPassword = document.getElementById("reg-confirm-password").value;
  const submitBtn = document.getElementById("btn-register-submit");

  if (password !== confirmPassword) {
    errorAlert.textContent = "Password and Confirm Password do not match.";
    errorAlert.style.display = "block";
    return;
  }

  if (password.length < 6) {
    errorAlert.textContent = "Password must be at least 6 characters long.";
    errorAlert.style.display = "block";
    return;
  }

  submitBtn.disabled = true;
  submitBtn.textContent = "Creating Account...";

  try {
    const resp = await fetch("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name,
        email,
        password,
        confirm_password: confirmPassword
      })
    });

    const data = await resp.json();

    if (!resp.ok) {
      errorAlert.textContent = data.detail || "Registration failed.";
      errorAlert.style.display = "block";
      return;
    }

    setAuthToken(data.token);
    currentUser = data.user;
    updateAuthUI(currentUser);
    showToast("Account created successfully!", "success");
    document.getElementById("register-form").reset();
    
    // DIRECTLY TO MAIN FORESIGHT PAGE
    navigateTo('scanner');

  } catch (err) {
    errorAlert.textContent = "Unable to connect to server. Please try again.";
    errorAlert.style.display = "block";
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = "Create Account ➔";
  }
}

async function handleLogout() {
  const token = getAuthToken();
  if (token) {
    try {
      await fetch("/api/auth/logout", {
        method: "POST",
        headers: { "Authorization": `Bearer ${token}` }
      });
    } catch (e) {
      // Ignore network errors on logout
    }
  }

  setAuthToken(null);
  currentUser = null;
  updateAuthUI(null);
  stopCamera();
  showToast("You have been signed out.", "info");
  
  // Return directly to Login
  navigateTo('login');
}


// =====================================================================
// MAIN FORESIGHT PAGE (SCAN QR CODE LOGIC)
// =====================================================================

function switchScannerTab(mode) {
  // Update button highlights
  document.getElementById('mode-btn-camera').className = mode === 'camera' ? 'cyber-btn' : 'cyber-btn secondary';
  document.getElementById('mode-btn-upload').className = mode === 'upload' ? 'cyber-btn' : 'cyber-btn secondary';
  document.getElementById('mode-btn-manual').className = mode === 'manual' ? 'cyber-btn' : 'cyber-btn secondary';

  document.getElementById('camera-view').style.display = 'none';
  document.getElementById('upload-view').style.display = 'none';
  document.getElementById('manual-view').style.display = 'none';

  stopCamera();

  if (mode === 'camera') {
    document.getElementById('camera-view').style.display = 'block';
  } else if (mode === 'upload') {
    document.getElementById('upload-view').style.display = 'block';
  } else if (mode === 'manual') {
    document.getElementById('manual-view').style.display = 'block';
  }
}

async function toggleCamera() {
  const btn = document.getElementById('btn-toggle-cam');
  if (videoStream) {
    stopCamera();
    btn.textContent = 'Start Camera';
    btn.style.background = 'linear-gradient(135deg, #0284c7, #2563eb)';
  } else {
    try {
      videoStream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: "environment", width: { ideal: 1280 }, height: { ideal: 720 } }
      });
      const video = document.getElementById('video-preview');
      video.srcObject = videoStream;
      video.setAttribute("playsinline", true);
      await video.play();

      btn.textContent = 'Stop Camera';
      btn.style.background = '#dc2626';

      startScanning();
    } catch (err) {
      alert("Unable to access camera. Please check camera permissions or use Upload QR Image.");
      console.error(err);
    }
  }
}

function stopCamera() {
  if (scanInterval) {
    clearInterval(scanInterval);
    scanInterval = null;
  }
  if (videoStream) {
    videoStream.getTracks().forEach(track => track.stop());
    videoStream = null;
  }
  const video = document.getElementById('video-preview');
  if (video) video.srcObject = null;
  const btn = document.getElementById('btn-toggle-cam');
  if (btn) {
    btn.textContent = 'Start Camera';
    btn.style.background = 'linear-gradient(135deg, #0284c7, #2563eb)';
  }
}

function startScanning() {
  const video = document.getElementById('video-preview');
  const canvas = document.getElementById('qr-canvas');
  const ctx = canvas.getContext('2d');

  scanInterval = setInterval(() => {
    if (video.readyState === video.HAVE_ENOUGH_DATA) {
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

      if (window.jsQR) {
        const code = jsQR(imageData.data, imageData.width, imageData.height, {
          inversionAttempts: "attemptBoth",
        });

        if (code && code.data && code.data.trim().length > 0) {
          stopCamera();
          document.getElementById('manual-payload-input').value = code.data;
          analyzePayload(code.data);
        }
      }
    }
  }, 180);
}

function triggerFileInput() {
  document.getElementById('qr-file-input').click();
}

async function handleFileSelected(event) {
  const file = event.target.files[0];
  if (!file) return;

  showLoading(true, "Decoding QR code from uploaded image...");

  // Primary: Universal Server-side Decoder (zxing-cpp + OpenCV)
  try {
    const formData = new FormData();
    formData.append('file', file);

    const token = getAuthToken();
    const headers = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const resp = await fetch('/api/scan-image', {
      method: 'POST',
      headers: headers,
      body: formData
    });

    if (resp.ok) {
      const data = await resp.json();
      if (data.success && data.decoded_text) {
        document.getElementById('manual-payload-input').value = data.decoded_text;
        currentAnalysisData = data;
        renderAnalysisDashboard(data);
        return;
      }
    }
  } catch (backendErr) {
    console.warn("Server-side QR decoding failed, attempting client-side fallback:", backendErr);
  }

  // Fallback: Client-side jsQR canvas scan
  try {
    const reader = new FileReader();
    reader.onload = function(e) {
      const img = new Image();
      img.onload = function() {
        const canvas = document.createElement('canvas');
        canvas.width = img.width;
        canvas.height = img.height;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(img, 0, 0);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

        if (window.jsQR) {
          const code = jsQR(imageData.data, imageData.width, imageData.height, {
            inversionAttempts: "attemptBoth"
          });
          if (code && code.data && code.data.trim().length > 0) {
            document.getElementById('manual-payload-input').value = code.data;
            analyzePayload(code.data);
            return;
          }
        }
        showLoading(false);
        alert("No valid QR code could be detected in this image. Please ensure the QR code is clearly visible, or enter the link directly.");
      };
      img.src = e.target.result;
    };
    reader.readAsDataURL(file);
  } catch (clientErr) {
    showLoading(false);
    alert("Could not read image: " + clientErr.message);
  }
}

// Drag & Drop
const dropzone = document.getElementById('upload-view');
if (dropzone) {
  ['dragenter', 'dragover'].forEach(name => {
    dropzone.addEventListener(name, (e) => {
      e.preventDefault();
      const box = dropzone.querySelector('.dropzone-box');
      if (box) box.classList.add('dragover');
    });
  });
  ['dragleave', 'drop'].forEach(name => {
    dropzone.addEventListener(name, (e) => {
      e.preventDefault();
      const box = dropzone.querySelector('.dropzone-box');
      if (box) box.classList.remove('dragover');
    });
  });
  dropzone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files.length > 0) {
      handleFileSelected({ target: { files: files } });
    }
  });
}

function analyzeManualInput() {
  const payload = document.getElementById('manual-payload-input').value.trim();
  if (!payload) {
    alert("Please enter a destination URL to analyze.");
    return;
  }
  analyzePayload(payload);
}

function loadExampleTarget(type) {
  const url = EXAMPLE_TARGETS[type];
  if (!url) return;
  document.getElementById('manual-payload-input').value = url;
  switchScannerTab('manual');
  analyzePayload(url);
}

async function analyzePayload(payload) {
  showLoading(true, "Analyzing QR destination security indicators...");
  try {
    const token = getAuthToken();
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const resp = await fetch('/api/analyze', {
      method: 'POST',
      headers: headers,
      body: JSON.stringify({ payload: payload, follow_redirects: true, action_taken: 'INSPECTED' })
    });

    if (!resp.ok) {
      throw new Error(`Server returned status: ${resp.status}`);
    }

    const data = await resp.json();
    currentAnalysisData = data;
    renderAnalysisDashboard(data);
  } catch (err) {
    alert("Analysis failed: " + err.message);
    console.error(err);
  } finally {
    showLoading(false);
  }
}

function renderAnalysisDashboard(data) {
  const analysis = data.analysis;
  const tracking = data.access_tracking;

  document.getElementById('analysis-section').style.display = 'flex';
  document.getElementById('analysis-section').scrollIntoView({ behavior: 'smooth' });

  // 1. Score & Status
  const scoreDisplay = document.getElementById('score-display');
  scoreDisplay.textContent = analysis.score;

  const statusBadge = document.getElementById('status-badge');
  statusBadge.textContent = analysis.status;

  const heroCard = document.getElementById('hero-risk-card');
  heroCard.classList.remove('safe-theme', 'suspicious-theme', 'dangerous-theme');

  const btnProceed = document.getElementById('btn-proceed');
  btnProceed.classList.remove('safe');

  if (analysis.status === 'SAFE') {
    heroCard.classList.add('safe-theme');
    btnProceed.classList.add('safe');
  } else if (analysis.status === 'SUSPICIOUS') {
    heroCard.classList.add('suspicious-theme');
  } else {
    heroCard.classList.add('dangerous-theme');
  }

  // 2. Explainability ("Why" list)
  const reasonsList = document.getElementById('reasons-list');
  reasonsList.innerHTML = '';
  if (analysis.reasons && analysis.reasons.length > 0) {
    analysis.reasons.forEach(r => {
      const li = document.createElement('li');
      li.textContent = r;
      reasonsList.appendChild(li);
    });
  } else {
    const li = document.createElement('li');
    li.textContent = "Standard protocols and verified domain indicators found. No adverse risk factors detected.";
    reasonsList.appendChild(li);
  }

  // 3. Destination Forensics
  document.getElementById('detail-orig-url').textContent = analysis.original_url || '-';
  document.getElementById('detail-final-url').textContent = analysis.final_url || analysis.original_url || '-';
  document.getElementById('detail-domain').textContent = (analysis.domain || '-') + (analysis.heuristics?.entropy ? ` (Entropy: ${analysis.heuristics.entropy})` : '');
  document.getElementById('detail-protocol').textContent = (analysis.scheme ? analysis.scheme.toUpperCase() : 'UNKNOWN');

  // Saved to history badge
  const savedBadge = document.getElementById('saved-history-badge');
  if (data.saved_scan) {
    savedBadge.style.display = 'inline-block';
  } else {
    savedBadge.style.display = 'none';
  }

  // 4. Redirect Track
  const track = document.getElementById('redirect-hops-track');
  track.innerHTML = '';
  const hops = analysis.redirects?.hops || [];
  if (hops.length > 0) {
    hops.forEach(hop => {
      const hopDiv = document.createElement('div');
      hopDiv.className = 'hop-item';
      const isRedirect = [301, 302, 303, 307, 308].includes(hop.status_code);
      hopDiv.innerHTML = `
        <span class="hop-num">HOP #${hop.hop}</span>
        <span class="hop-url">${escapeHtml(hop.url)}</span>
        <span class="hop-code ${isRedirect ? 'redirect' : 'ok'}">${hop.status_code}</span>
      `;
      track.appendChild(hopDiv);
    });
  } else {
    track.innerHTML = `
      <div class="hop-item">
        <span class="hop-num">DIRECT</span>
        <span class="hop-url">${escapeHtml(analysis.original_url)}</span>
        <span class="hop-code ok">DIRECT DESTINATION</span>
      </div>
    `;
  }

  if (analysis.redirects?.destination_drift) {
    const driftNotice = document.createElement('div');
    driftNotice.style.cssText = "margin-top: 0.5rem; background: rgba(245, 158, 11, 0.15); border: 1px solid var(--color-suspicious-border); border-radius: 8px; padding: 0.5rem 0.8rem; font-size: 0.8rem; color: #fbbf24;";
    driftNotice.innerHTML = `⚠️ <strong>Destination Drift Warning:</strong> Initial domain ('${escapeHtml(analysis.redirects.initial_domain)}') deviates from final landing domain ('${escapeHtml(analysis.redirects.final_domain)}').`;
    track.appendChild(driftNotice);
  }

  // 5. 24-Hour Unique Access Activity
  const uniqueCount = tracking.unique_accesses_24h || 1;
  document.getElementById('unique-access-count').textContent = uniqueCount;
  
  const pct = Math.min(100, Math.max(1, tracking.progress_percentage || 1));
  document.getElementById('access-progress-fill').style.width = pct + '%';
  document.getElementById('access-progress-text').textContent = `${uniqueCount} unique access(es) (${pct}% of 100 threshold)`;

  const alertBox = document.getElementById('cybercell-alert-box');
  const triggerLabel = document.getElementById('trigger-status-label');

  if (tracking.threshold_met) {
    triggerLabel.textContent = "🚨 THRESHOLD MET: CYBERCELL REPORT ACTIVE";
    triggerLabel.style.color = "#f87171";

    alertBox.style.display = 'flex';
    const incident = tracking.incident_report;
    if (incident) {
      currentIncidentDossier = incident.dossier;
      document.getElementById('cybercell-alert-sub').textContent = 
        `Incident ID: ${incident.incident_id} • ${uniqueCount} unique accesses in 24h • Priority: ${incident.priority}`;
    }
  } else {
    triggerLabel.textContent = "Monitoring Active (Below Threshold)";
    triggerLabel.style.color = "#34d399";
    alertBox.style.display = 'none';
  }

  // 6. User Decision Recommendation
  document.getElementById('decision-recommendation').textContent = analysis.recommendation;
}

function userDecisionAvoid() {
  document.getElementById('analysis-section').style.display = 'none';
  window.scrollTo({ top: 0, behavior: 'smooth' });
  showToast("Shield Active: Destination discarded. You have not visited the link.", "info");
}

function userDecisionProceed() {
  if (!currentAnalysisData) return;
  const analysis = currentAnalysisData.analysis;

  if (analysis.status === 'DANGEROUS' || analysis.status === 'SUSPICIOUS') {
    document.getElementById('proceed-confirm-modal').classList.add('active');
  } else {
    executeProceed();
  }
}

function closeProceedModal() {
  document.getElementById('proceed-confirm-modal').classList.remove('active');
}

function executeProceed() {
  closeProceedModal();
  if (!currentAnalysisData) return;
  const targetUrl = currentAnalysisData.analysis.final_url || currentAnalysisData.analysis.original_url;
  const cleanUrl = targetUrl.startsWith('http') ? targetUrl : 'https://' + targetUrl;
  window.open(cleanUrl, '_blank', 'noopener,noreferrer');
}


// =====================================================================
// SCAN HISTORY PAGE LOGIC
// =====================================================================

function setHistoryFilter(status) {
  historyFilter = status;
  document.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
  const pillId = `pill-${status.toLowerCase()}`;
  const pill = document.getElementById(pillId);
  if (pill) pill.classList.add('active');
  loadScanHistory();
}

function handleHistorySearch(event) {
  clearTimeout(searchDebounceTimer);
  searchDebounceTimer = setTimeout(() => {
    historySearchQuery = event.target.value.trim();
    loadScanHistory();
  }, 250);
}

async function loadScanHistory() {
  if (!currentUser) return;
  const token = getAuthToken();
  const container = document.getElementById("history-table-container");
  container.innerHTML = `<div style="text-align: center; padding: 2rem; color: var(--text-muted);">Loading scan records...</div>`;

  try {
    let url = `/api/user/scans?status=${encodeURIComponent(historyFilter)}`;
    if (historySearchQuery) {
      url += `&search=${encodeURIComponent(historySearchQuery)}`;
    }

    const resp = await fetch(url, {
      headers: { "Authorization": `Bearer ${token}` }
    });

    if (!resp.ok) {
      container.innerHTML = `<div style="text-align: center; padding: 2rem; color: #f87171;">Failed to load scan records.</div>`;
      return;
    }

    const data = await resp.json();
    renderScanHistoryTable(data.scans);

  } catch (err) {
    container.innerHTML = `<div style="text-align: center; padding: 2rem; color: #f87171;">Error connecting to server.</div>`;
  }
}

function renderScanHistoryTable(scans) {
  const container = document.getElementById("history-table-container");

  if (!scans || scans.length === 0) {
    if (historySearchQuery || historyFilter !== 'ALL') {
      container.innerHTML = `
        <div class="empty-state-card">
          <h4 class="empty-state-title">No matching scans found</h4>
          <p class="empty-state-desc">No past scan records match the current filter or search criteria.</p>
          <button class="cyber-btn secondary" onclick="resetHistoryFilters()">Reset Filters</button>
        </div>
      `;
    } else {
      container.innerHTML = `
        <div class="empty-state-card">
          <div class="empty-state-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
          </div>
          <h4 class="empty-state-title">No scans yet</h4>
          <p class="empty-state-desc">Scan your first QR code to start building your personal security history.</p>
          <button class="cyber-btn" onclick="navigateTo('scanner')">Scan QR Now ➔</button>
        </div>
      `;
    }
    return;
  }

  const html = `
    <table class="history-table">
      <thead>
        <tr>
          <th>Date & Time</th>
          <th>Destination Domain</th>
          <th>Final Destination</th>
          <th>Risk Score</th>
          <th>Status</th>
          <th>Details</th>
        </tr>
      </thead>
      <tbody>
        ${scans.map(s => `
          <tr>
            <td data-label="Date & Time">${formatDate(s.created_at)}</td>
            <td data-label="Domain" style="font-family: var(--font-mono); color: var(--cyber-cyan);">${escapeHtml(s.domain || '-')}</td>
            <td data-label="Final Destination" style="font-family: var(--font-mono); max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
              ${escapeHtml(s.final_url || s.original_url)}
            </td>
            <td data-label="Risk Score" style="font-family: var(--font-mono); font-weight: 700;">${s.risk_score}/100</td>
            <td data-label="Status">
              <span class="status-tag ${s.risk_status.toLowerCase()}">${s.risk_status}</span>
            </td>
            <td data-label="Details">
              <button class="cyber-btn secondary" onclick="openScanDetailsModal('${s.scan_id}')" style="padding: 0.3rem 0.75rem; font-size: 0.75rem;">
                View Details
              </button>
            </td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
  container.innerHTML = html;
}

function resetHistoryFilters() {
  historySearchQuery = '';
  document.getElementById("history-search-input").value = '';
  setHistoryFilter('ALL');
}


// =====================================================================
// PREVIOUS SCAN DETAILS MODAL
// =====================================================================

async function openScanDetailsModal(scanId) {
  const token = getAuthToken();
  if (!token) return;

  try {
    const resp = await fetch(`/api/user/scans/${encodeURIComponent(scanId)}`, {
      headers: { "Authorization": `Bearer ${token}` }
    });

    if (!resp.ok) {
      alert("Could not load scan details.");
      return;
    }

    const data = await resp.json();
    const scan = data.scan;

    document.getElementById("modal-scan-id").textContent = scan.scan_id;
    document.getElementById("modal-scan-time").textContent = formatDate(scan.created_at);
    document.getElementById("modal-scan-score").textContent = scan.risk_score;
    
    const badge = document.getElementById("modal-scan-status-badge");
    badge.className = `status-tag ${scan.risk_status.toLowerCase()}`;
    badge.textContent = scan.risk_status;

    document.getElementById("modal-scan-recommendation").textContent = 
      scan.risk_status === 'DANGEROUS' ? 'High risk destination. Strongly advised to avoid.' :
      scan.risk_status === 'SUSPICIOUS' ? 'Exercise caution. Elevated risk factors detected.' :
      'Standard verified destination. Safe to proceed.';

    document.getElementById("modal-scan-orig-url").textContent = scan.original_url || '-';
    document.getElementById("modal-scan-final-url").textContent = scan.final_url || scan.original_url || '-';
    document.getElementById("modal-scan-domain").textContent = scan.domain || '-';
    document.getElementById("modal-scan-action").textContent = scan.action_taken || 'INSPECTED';

    // Reasons List
    const reasonsList = document.getElementById("modal-scan-reasons-list");
    reasonsList.innerHTML = '';
    const reasons = scan.reasons || [];
    if (reasons.length > 0) {
      reasons.forEach(r => {
        const li = document.createElement("li");
        li.textContent = r;
        reasonsList.appendChild(li);
      });
    } else {
      const li = document.createElement("li");
      li.textContent = "Standard verified domain. No risk penalties applied.";
      reasonsList.appendChild(li);
    }

    // Redirect Hops
    const hopsTrack = document.getElementById("modal-scan-hops-track");
    hopsTrack.innerHTML = '';
    const hops = scan.redirects?.hops || [];
    if (hops.length > 0) {
      hops.forEach(hop => {
        const hopDiv = document.createElement("div");
        hopDiv.className = "hop-item";
        const isRedirect = [301, 302, 303, 307, 308].includes(hop.status_code);
        hopDiv.innerHTML = `
          <span class="hop-num">HOP #${hop.hop}</span>
          <span class="hop-url">${escapeHtml(hop.url)}</span>
          <span class="hop-code ${isRedirect ? 'redirect' : 'ok'}">${hop.status_code}</span>
        `;
        hopsTrack.appendChild(hopDiv);
      });
    } else {
      hopsTrack.innerHTML = `
        <div class="hop-item">
          <span class="hop-num">DIRECT</span>
          <span class="hop-url">${escapeHtml(scan.original_url)}</span>
          <span class="hop-code ok">DIRECT DESTINATION</span>
        </div>
      `;
    }

    document.getElementById("scan-details-modal").classList.add("active");

  } catch (err) {
    alert("Error loading scan record: " + err.message);
  }
}

function closeScanDetailsModal() {
  document.getElementById("scan-details-modal").classList.remove("active");
}

function openCybercellModal() {
  if (!currentIncidentDossier) {
    alert("No active incident dossier found.");
    return;
  }
  document.getElementById('modal-incident-id').textContent = currentIncidentDossier.incident_id;
  document.getElementById('modal-dossier-json').textContent = JSON.stringify(currentIncidentDossier, null, 2);
  document.getElementById('cybercell-modal').classList.add('active');
}

function closeCybercellModal() {
  document.getElementById('cybercell-modal').classList.remove('active');
}

function copyDossierJson() {
  if (!currentIncidentDossier) return;
  navigator.clipboard.writeText(JSON.stringify(currentIncidentDossier, null, 2)).then(() => {
    showToast("Cybercell forensic JSON copied to clipboard!", "success");
  });
}


// =====================================================================
// USER PROFILE LOGIC
// =====================================================================

async function loadProfile() {
  if (!currentUser) return;
  const token = getAuthToken();

  document.getElementById("profile-name").textContent = currentUser.name;
  document.getElementById("profile-email").textContent = currentUser.email;
  document.getElementById("profile-avatar").textContent = currentUser.name.charAt(0).toUpperCase();
  document.getElementById("profile-created").textContent = formatDate(currentUser.created_at);

  try {
    const resp = await fetch("/api/auth/me", {
      headers: { "Authorization": `Bearer ${token}` }
    });
    if (resp.ok) {
      const data = await resp.json();
      const s = data.summary;
      document.getElementById("profile-total-scans").textContent = s.total_scans;
      document.getElementById("profile-safe-scans").textContent = s.safe_scans;
      document.getElementById("profile-suspicious-scans").textContent = s.suspicious_scans;
      document.getElementById("profile-dangerous-scans").textContent = s.dangerous_scans;
    }
  } catch (err) {
    console.warn("Profile stats fetch failed:", err);
  }
}


// =====================================================================
// UTILITIES & HELPERS
// =====================================================================

function showLoading(show, message) {
  const spinner = document.getElementById('loading-spinner');
  if (message) {
    const titleElem = document.getElementById('loading-spinner-title');
    if (titleElem) titleElem.textContent = message;
  }
  spinner.style.display = show ? 'block' : 'none';
}

function formatDate(epochSec) {
  if (!epochSec) return '-';
  const d = new Date(epochSec * 1000);
  return d.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit"
  });
}

function escapeHtml(text) {
  if (!text) return '';
  return String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function showToast(message, type = 'info') {
  const container = document.getElementById("toast-container");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = "toast-message";
  toast.textContent = message;

  if (type === 'success') {
    toast.style.borderColor = 'rgba(16, 185, 129, 0.5)';
    toast.style.borderLeft = '4px solid #10b981';
  } else if (type === 'warning') {
    toast.style.borderColor = 'rgba(245, 158, 11, 0.5)';
    toast.style.borderLeft = '4px solid #f59e0b';
  } else if (type === 'error') {
    toast.style.borderColor = 'rgba(239, 68, 68, 0.5)';
    toast.style.borderLeft = '4px solid #ef4444';
  } else {
    toast.style.borderColor = 'rgba(56, 189, 248, 0.5)';
    toast.style.borderLeft = '4px solid #38bdf8';
  }

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}
