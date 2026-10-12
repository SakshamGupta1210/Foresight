/**
 * FORESIGHT: Shared Auth Guard & Navigation Controller
 * Handles session tokens, route protection, shared navbar rendering, and logout.
 */

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

async function requireAuth() {
  const token = getAuthToken();
  if (!token) {
    window.location.href = "/login";
    return null;
  }

  try {
    const resp = await fetch("/api/auth/me", {
      headers: { "Authorization": `Bearer ${token}` }
    });
    if (!resp.ok) {
      setAuthToken(null);
      window.location.href = "/login";
      return null;
    }
    const data = await resp.json();
    setupHeaderUser(data.user);
    return data.user;
  } catch (err) {
    console.warn("Auth check failed:", err);
    window.location.href = "/login";
    return null;
  }
}

async function redirectIfLoggedIn() {
  const token = getAuthToken();
  if (!token) return;

  try {
    const resp = await fetch("/api/auth/me", {
      headers: { "Authorization": `Bearer ${token}` }
    });
    if (resp.ok) {
      window.location.href = "/scan";
    }
  } catch (err) {
    // Ignore and stay on auth page
  }
}

function setupHeaderUser(user) {
  const nameElem = document.getElementById("header-user-name");
  const avatarElem = document.getElementById("user-avatar-initial");
  if (nameElem && user) nameElem.textContent = user.name;
  if (avatarElem && user) avatarElem.textContent = user.name.charAt(0).toUpperCase();
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
      // Ignore network failures on logout
    }
  }
  setAuthToken(null);
  window.location.href = "/login";
}

function toggleMobileNav() {
  const drawer = document.getElementById("mobile-nav-drawer");
  if (drawer) drawer.classList.toggle("active");
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
  let container = document.getElementById("toast-container");
  if (!container) {
    container = document.createElement("div");
    container.id = "toast-container";
    container.className = "toast-container";
    document.body.appendChild(container);
  }

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
