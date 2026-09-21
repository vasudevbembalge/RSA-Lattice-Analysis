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

async function loadPerformanceMetadata() {
  try {
    const data = await requestJson("/api/performance");
    requireFields(data, ["benchmark_supported", "rsa_sizes", "lattice_presets"], "Performance metadata");
    if (!Array.isArray(data.rsa_sizes) || !Array.isArray(data.lattice_presets)) {
      throw new Error("Performance metadata contains invalid configuration lists.");
    }

    document.getElementById("performance-rsa-sizes").textContent = data.rsa_sizes.join(", ") + " bits";
    document.getElementById("performance-lattice-presets").textContent = data.lattice_presets.join(", ");
    document.getElementById("performance-benchmark-supported").textContent = data.benchmark_supported ? "Available in backend" : "Unavailable";
    document.getElementById("performance-metadata").hidden = false;
  } catch (err) {
    setOperationState("performance-status", "error", `Performance metadata unavailable: ${err.message}`);
  }
}

function validateBenchmarkReport(data) {
  requireFields(data, ["timestamp", "rsa_benchmarks", "lattice_benchmarks"], "Benchmark report");
  if (!Array.isArray(data.rsa_benchmarks) || !Array.isArray(data.lattice_benchmarks.dimension_scaling)) {
    throw new Error("Benchmark report contains malformed measurement lists.");
  }
  const norms = data.lattice_benchmarks.norm_reduction;
  if (!norms || !Array.isArray(norms.vector_indices) || !Array.isArray(norms.original_norms) || !Array.isArray(norms.reduced_norms)) {
    throw new Error("Benchmark report contains malformed norm data.");
  }
  data.rsa_benchmarks.forEach((row) => requireFields(row, ["key_size_bits", "keygen_time_ms", "encryption_time_ms", "decryption_time_ms", "verification_time_ms", "verified"], "RSA benchmark"));
  data.lattice_benchmarks.dimension_scaling.forEach((row) => requireFields(row, ["dimension", "execution_time_ms", "iterations", "swaps"], "LLL benchmark"));
  return data;
}

function appendCell(row, value) {
  const cell = document.createElement("td");
  cell.textContent = String(value);
  row.appendChild(cell);
}

function renderBenchmarkReport(report, source) {
  validateBenchmarkReport(report);
  const rsaRows = document.getElementById("rsa-benchmark-rows");
  const comparisonRows = document.getElementById("comparison-benchmark-rows");
  const lllRows = document.getElementById("lll-benchmark-rows");
  const normRows = document.getElementById("norm-benchmark-rows");
  rsaRows.replaceChildren();
  if (comparisonRows) comparisonRows.replaceChildren();
  lllRows.replaceChildren();
  normRows.replaceChildren();

  report.rsa_benchmarks.forEach((benchmark) => {
    const row = document.createElement("tr");
    appendCell(row, `${benchmark.key_size_bits}-bit`);
    appendCell(row, benchmark.keygen_time_ms);
    appendCell(row, benchmark.encryption_time_ms);
    appendCell(row, benchmark.decryption_time_ms);
    appendCell(row, benchmark.verification_time_ms);
    appendCell(row, benchmark.verified ? "PASSED" : "FAILED");
    rsaRows.appendChild(row);
  });

  if (comparisonRows && Array.isArray(report.comparison_benchmarks)) {
    report.comparison_benchmarks.forEach((benchmark) => {
      const row = document.createElement("tr");
      appendCell(row, benchmark.scheme);
      appendCell(row, benchmark.key_size_bits ? `${benchmark.key_size_bits}-bit` : `n = ${benchmark.dimension}`);
      appendCell(row, benchmark.keygen_time_ms);
      appendCell(row, benchmark.encryption_time_ms);
      appendCell(row, benchmark.decryption_time_ms);
      appendCell(row, benchmark.total_time_ms);
      appendCell(row, benchmark.plaintext_capacity_bytes === null ? "No fixed cryptographic limit" : benchmark.plaintext_capacity_bytes);
      appendCell(row, benchmark.ciphertext_bytes);
      appendCell(row, benchmark.verified ? "PASSED" : "FAILED");
      comparisonRows.appendChild(row);
    });
  }

  report.lattice_benchmarks.dimension_scaling.forEach((benchmark) => {
    const row = document.createElement("tr");
    appendCell(row, benchmark.dimension);
    appendCell(row, benchmark.execution_time_ms);
    appendCell(row, benchmark.iterations);
    appendCell(row, benchmark.swaps);
    lllRows.appendChild(row);
  });

  const norms = report.lattice_benchmarks.norm_reduction;
  const normCount = Math.min(norms.vector_indices.length, norms.original_norms.length, norms.reduced_norms.length);
  if (normCount === 0) {
    throw new Error("Benchmark report contains no norm measurements.");
  }
  for (let index = 0; index < normCount; index += 1) {
    const row = document.createElement("tr");
    appendCell(row, norms.vector_indices[index]);
    appendCell(row, norms.original_norms[index]);
    appendCell(row, norms.reduced_norms[index]);
    normRows.appendChild(row);
  }

  document.getElementById("benchmark-source").textContent = source;
  document.getElementById("benchmark-timestamp").textContent = report.timestamp;
  document.getElementById("benchmark-summary").hidden = false;
  document.getElementById("benchmark-results").hidden = false;
  if (typeof renderBenchmarkCharts === "function") {
    renderBenchmarkCharts(report);
  }
}

async function runBenchmark() {
  const runButton = document.getElementById("btn-run-benchmark");
  const loadButton = document.getElementById("btn-load-benchmark-results");
  runButton.disabled = true;
  loadButton.disabled = true;
  runButton.innerText = "Running benchmark...";
  setOperationState("performance-status", "loading", "Running empirical benchmark. RSA key generation may take some time...");

  try {
    const report = await requestJson("/api/performance/run", { method: "POST" });
    renderBenchmarkReport(report, "NEW RUN");
    setOperationState("performance-status", "success", "Benchmark completed. Measurements below were generated by this run.");
  } catch (err) {
    setOperationState("performance-status", "error", `Benchmark failed: ${err.message}`);
  } finally {
    runButton.disabled = false;
    loadButton.disabled = false;
    runButton.innerText = "Run Benchmark";
  }
}

async function loadLatestBenchmarkResults() {
  const runButton = document.getElementById("btn-run-benchmark");
  const loadButton = document.getElementById("btn-load-benchmark-results");
  runButton.disabled = true;
  loadButton.disabled = true;
  setOperationState("performance-status", "loading", "Loading the latest persisted benchmark results...");

  try {
    const report = await requestJson("/api/performance/results");
    renderBenchmarkReport(report, "LOADED RESULT");
    setOperationState("performance-status", "success", "Persisted benchmark results loaded. These measurements are not a new run.");
  } catch (err) {
    setOperationState("performance-status", "error", `Stored benchmark results unavailable: ${err.message}`);
  } finally {
    runButton.disabled = false;
    loadButton.disabled = false;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initNavigation();
  checkSystemStatus();
  setOperationState("performance-status", "idle", "Ready");
  document.getElementById("btn-run-benchmark")?.addEventListener("click", runBenchmark);
  document.getElementById("btn-load-benchmark-results")?.addEventListener("click", loadLatestBenchmarkResults);
  loadPerformanceMetadata();
});