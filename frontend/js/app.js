/**
 * Main Application Navigation and Core Orchestration
 */

const API_BASE = "";

// Global State
const appState = {
  currentKeypair: null,
  lastPlaintext: "",
  lastCiphertext: "",
};

const REQUEST_TIMEOUT_MS = 15000;

async function requestJson(path, options = {}) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(`${API_BASE}${path}`, {
      ...options,
      signal: controller.signal,
    });
    const rawBody = await response.text();
    let data = null;

    if (rawBody) {
      try {
        data = JSON.parse(rawBody);
      } catch (error) {
        throw new Error(`The server returned malformed JSON (HTTP ${response.status}).`);
      }
    }

    if (!response.ok) {
      throw new Error(data?.message || `Request failed with HTTP ${response.status}.`);
    }

    return data;
  } catch (error) {
    if (error.name === "AbortError") {
      throw new Error("The request timed out. Check that the Flask server is available.");
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}

function setOperationState(elementId, state, message) {
  const element = document.getElementById(elementId);
  if (!element) return;

  element.className = `operation-status operation-${state}`;
  element.textContent = message;
  element.hidden = !message;
}

function requireFields(data, fields, operationName) {
  if (!data || typeof data !== "object") {
    throw new Error(`${operationName} returned an empty response.`);
  }

  const missing = fields.filter((field) => data[field] === undefined || data[field] === null);
  if (missing.length > 0) {
    throw new Error(`${operationName} returned an incomplete response: missing ${missing.join(", ")}.`);
  }
}

// Navigation Tab Switching
function initNavigation() {
  const navLinks = document.querySelectorAll(".nav-link");
  navLinks.forEach((link) => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      const targetId = link.getAttribute("data-target");
      navTo(targetId);
    });
  });
}

function navTo(tabId) {
  // Update sidebar active link
  document.querySelectorAll(".nav-link").forEach((link) => {
    if (link.getAttribute("data-target") === tabId) {
      link.classList.add("active");
    } else {
      link.classList.remove("active");
    }
  });

  // Switch tab panes
  document.querySelectorAll(".tab-pane").forEach((pane) => {
    if (pane.id === tabId) {
      pane.classList.add("active");
    } else {
      pane.classList.remove("active");
    }
  });
}

// Modal Controllers
function openKeyModal(title, content) {
  const modal = document.getElementById("key-modal");
  document.getElementById("modal-title").innerText = title;
  document.getElementById("modal-key-content").value = content;
  modal.style.display = "flex";
}

function closeKeyModal() {
  document.getElementById("key-modal").style.display = "none";
}

function copyModalKey() {
  const content = document.getElementById("modal-key-content").value;
  navigator.clipboard.writeText(content).then(() => {
    alert("Key copied to clipboard!");
  });
}

// System Status Polling
async function checkSystemStatus() {
  try {
    const data = await requestJson("/api/status");
    const rsaBadge = document.getElementById("badge-rsa-status");
    const lllBadge = document.getElementById("badge-lll-status");

    if (data?.engines?.rsa_cryptography?.status === "ready") {
      rsaBadge.innerHTML = "&#x2713; RSA Ready";
      rsaBadge.className = "badge badge-success";
    } else {
      rsaBadge.innerHTML = "&#x26A0; RSA Unavailable";
      rsaBadge.className = "badge";
    }

    if (data?.engines?.c_lll_engine?.status === "ready") {
      lllBadge.innerHTML = "&#x2713; C LLL Engine Loaded";
      lllBadge.className = "badge badge-info";
    } else {
      lllBadge.innerHTML = "&#x26A0; C Engine Missing";
      lllBadge.className = "badge";
    }
  } catch (err) {
    document.getElementById("badge-rsa-status").textContent = "! API Unavailable";
    document.getElementById("badge-rsa-status").className = "badge";
    document.getElementById("badge-lll-status").textContent = "! API Unavailable";
    document.getElementById("badge-lll-status").className = "badge";
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initNavigation();
  checkSystemStatus();
});