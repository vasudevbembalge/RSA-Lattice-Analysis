/**
 * Educational LWE public-key encryption demonstration controller.
 *
 * The browser never performs lattice arithmetic. Every displayed value is
 * returned by the existing backend endpoints:
 *   POST /api/lattice/demo    -> key generation: Public Key (A, b), Secret Key s
 *   POST /api/lattice/encrypt -> encryption with the public key: ciphertext (u, v)
 *   POST /api/lattice/decrypt -> decryption with the secret key: plaintext
 */

const lweDemoState = {
  report: null,
  backend: null,
  publicKey: null,
  secretKey: null,
  ciphertext: null,
  encryptedMessage: "",
  keyGenerationTimeMs: null,
  encryptionTimeMs: null,
  decryptionTimeMs: null,
};

const LWE_STEP_IDS = {
  publicKey: "lwe-step-public-key",
  secretKey: "lwe-step-secret-key",
  encrypt: "lwe-step-encrypt",
  ciphertext: "lwe-step-ciphertext",
  decrypt: "lwe-step-decrypt",
  lattice: "lwe-step-lattice",
  lll: "lwe-step-lll",
  benchmark: "lwe-step-benchmark",
  architecture: "lwe-step-architecture",
};

function backendLabel(backend) {
  return backend === "native_c" ? "Native C (lattice_crypto.dll)" : "Python reference";
}

function setLweStepVisible(stepKey, visible) {
  const card = document.getElementById(LWE_STEP_IDS[stepKey]);
  if (card) card.hidden = !visible;
}

function setLweButtonState(buttonId, enabled) {
  const button = document.getElementById(buttonId);
  if (button) button.disabled = !enabled;
}

function setElementText(elementId, text) {
  const element = document.getElementById(elementId);
  if (element) element.textContent = text;
}

function requiredField(data, field, label) {
  const value = data?.[field];
  if (value === undefined || value === null || (typeof value === "number" && !Number.isFinite(value))) {
    throw new Error(`${label}: ${field} is unavailable from the backend.`);
  }
  return value;
}

function formatMilliseconds(value, label = "Execution time") {
  return `${requiredField({ value }, "value", label)} ms`;
}

function renderStatGrid(targetId, entries) {
  const target = document.getElementById(targetId);
  if (!target) return;
  target.replaceChildren();
  entries.forEach(([label, value]) => {
    const item = document.createElement("div");
    const name = document.createElement("span");
    name.textContent = label;
    const content = document.createElement("strong");
    content.textContent = String(value);
    item.append(name, content);
    target.appendChild(item);
  });
}

function renderEquationGrid(targetId, equations) {
  const target = document.getElementById(targetId);
  if (!target) return;
  target.replaceChildren();
  Object.entries(equations).forEach(([name, equation]) => {
    const item = document.createElement("div");
    const label = document.createElement("span");
    label.textContent = name.replaceAll("_", " ");
    const value = document.createElement("code");
    value.textContent = equation;
    item.append(label, value);
    target.appendChild(item);
  });
}

function selectPrimaryBackend(report) {
  const requested = document.getElementById("lwe-demo-backend").value;
  const backends = report?.lwe?.backends || [];
  if (requested === "native_c") {
    return backends.find((item) => item.backend.startsWith("Native C")) || backends[0];
  }
  return backends.find((item) => item.backend === "Python reference") || backends[0];
}

function renderParameters(report) {
  const params = report.lwe.parameters;
  const capacity = report.lwe.message_capacity;
  renderStatGrid("lwe-demo-parameters", [
    ["Dimension n", params.dimension],
    ["Modulus q", params.modulus],
    ["Message modulus p", params.message_modulus],
    ["Noise bound", params.noise_bound],
    ["Samples m", params.samples],
    ["Message scale floor(q/p)", params.message_scale],
    ["Maximum bounded noise", params.max_decryption_noise],
    ["Decoding threshold", params.decoding_threshold],
    ["Correctness margin", params.correctness_margin],
    ["Message bytes", report.lwe.message_bytes],
    ["Requested backend", report.lwe.requested_backend],
    ["Actual backend", backendLabel(lweDemoState.backend.backend)],
    ["Fallback used", report.lwe.fallback ? "Yes" : "No"],
  ]);
  renderMessageConfiguration(capacity);
}

function renderMessageConfiguration(capacity) {
  const message = document.getElementById("lwe-demo-message");
  const text = message ? message.value : "";
  const bytes = new TextEncoder().encode(text).length;
  const maximum = capacity?.maximum_plaintext_bytes;
  renderStatGrid("lwe-demo-message-configuration", [
    ["Bytes per block", capacity?.bytes_per_block ?? "Not measured"],
    ["Message modulus p", capacity?.message_modulus ?? "Not measured"],
    ["Maximum plaintext", maximum === null ? "No fixed cryptographic limit" : (maximum ?? "Not measured")],
    ["Characters", text.length],
    ["UTF-8 bytes", bytes],
    ["Remaining capacity", maximum === null ? "Resource-bound" : (maximum === undefined ? "Not measured" : Math.max(0, maximum - bytes))],
    ["Encoding", capacity?.encoding ?? "Not measured"],
  ]);
}

function renderPublicParameters(backend) {
  const publicKey = backend.public_key;
  const errorVector = Array.isArray(backend.error_vector) ? backend.error_vector : null;
  renderStatGrid("lwe-demo-public-parameters", [
    ["Public parameter A", `${publicKey.matrix_A.length} x ${publicKey.matrix_A[0].length} matrix over Z_q`],
    ["Public parameter q", publicKey.modulus],
    ["Public key dimensions", `${publicKey.matrix_A.length} x ${publicKey.matrix_A[0].length} plus ${publicKey.vector_b.length}`],
    ["Secret key s", `${backend.secret_key.secret.length} small entries`],
    ["Error e", errorVector ? `${errorVector.length} small entries` : "Not returned by the educational backend"],
    ["Public component b", "b = A s + e (mod q)"],
    ["Backend used", backend.backend_used || backend.backend],
  ]);
}

function renderKeyTiming(backend) {
  renderStatGrid("lwe-demo-key-timing", [
    ["Key generation time", formatMilliseconds(backend.key_generation_ms, "Key generation time")],
    ["Backend used", backend.backend_used || backend.backend],
    ["Public key", "A and b returned"],
    ["Secret key", "s returned for educational visualization"],
  ]);
}

function renderPublicKey(backend) {
  const publicKey = backend.public_key;
  MatrixDisplay("lwe-demo-matrix", publicKey.matrix_A, { label: "A = public matrix" });
  MatrixVector("lwe-demo-vector", publicKey.vector_b, "b = public vector");
  setElementText(
    "lwe-demo-flow-publickey",
    `A ${publicKey.matrix_A.length} x ${publicKey.matrix_A[0].length}, b ${publicKey.vector_b.length}`
  );
}

function renderEncryptionPublicKey(backend) {
  MatrixDisplay("lwe-demo-encryption-public-matrix", backend.public_key.matrix_A, { label: "A = public matrix" });
  MatrixVector("lwe-demo-encryption-public-vector", backend.public_key.vector_b, "b = public vector");
}

function renderSecretKey(backend) {
  MatrixVector("lwe-demo-secret", backend.secret_key.secret, "s = secret vector");
  if (Array.isArray(backend.error_vector)) {
    MatrixVector("lwe-demo-error", backend.error_vector, "e = error vector (derived from A, b, s)");
  } else {
    const errorElement = document.getElementById("lwe-demo-error");
    if (errorElement) {
      errorElement.textContent = "The educational backend does not expose the error vector as a separate field.";
      errorElement.className = "matrix-display-empty";
    }
  }
}

function renderLattice(report) {
  const visualization = report.lattice_visualization;
  const legend = document.getElementById("lwe-lattice-legend");
  legend.replaceChildren();
  const basis = visualization.basis;
  const entries = [
    ["Basis b1", `(${basis[0].join(", ")})`, "basis-one"],
    ["Basis b2", `(${basis[1].join(", ")})`, "basis-two"],
    ["Lattice points", `${visualization.points.length} integer combinations`, "point-key"],
  ];
  entries.forEach(([label, value, className]) => {
    const item = document.createElement("div");
    item.className = "lattice-legend-item";
    const swatch = document.createElement("span");
    swatch.className = `legend-swatch ${className}`;
    const text = document.createElement("span");
    const title = document.createElement("strong");
    title.textContent = label;
    const detail = document.createElement("small");
    detail.textContent = value;
    text.append(title, detail);
    item.append(swatch, text);
    legend.appendChild(item);
  });

  MatrixDisplay("lwe-lattice-basis", basis, { label: "Lattice basis B (rows b1, b2)" });

  const note = document.getElementById("lwe-lattice-note");
  note.replaceChildren();
  [
    `Basis combinations: ${visualization.equation}.`,
    `Backend explanation: ${visualization.explanation}`,
    "The numerical LWE encryption is modular arithmetic on the public key: u = Aᵀr + e₁ (mod q) and v = bᵀr + message embedding + e₂ (mod q), shown in steps 03 and 04. This picture is the lattice interpretation of those noisy modular relations only: it is a conceptual basis-combination view, not that numerical calculation, and not an LLL output.",
  ].forEach((paragraph) => {
    const element = document.createElement("p");
    element.textContent = paragraph;
    note.appendChild(element);
  });

  drawLattice(visualization);
}

function drawArrow(context, from, to, color, label) {
  context.strokeStyle = color;
  context.fillStyle = color;
  context.lineWidth = 2;
  context.beginPath();
  context.moveTo(from.x, from.y);
  context.lineTo(to.x, to.y);
  context.stroke();
  const angle = Math.atan2(to.y - from.y, to.x - from.x);
  context.beginPath();
  context.moveTo(to.x, to.y);
  context.lineTo(to.x - 10 * Math.cos(angle - Math.PI / 6), to.y - 10 * Math.sin(angle - Math.PI / 6));
  context.lineTo(to.x - 10 * Math.cos(angle + Math.PI / 6), to.y - 10 * Math.sin(angle + Math.PI / 6));
  context.closePath();
  context.fill();
  context.font = "600 12px Segoe UI, sans-serif";
  context.fillText(label, to.x + 8, to.y - 8);
}

function drawLattice(visualization) {
  const canvas = document.getElementById("lwe-lattice-canvas");
  if (!canvas) return;
  const context = canvas.getContext("2d");
  const width = canvas.width;
  const height = canvas.height;
  context.clearRect(0, 0, width, height);
  context.fillStyle = "#0b0f19";
  context.fillRect(0, 0, width, height);

  const points = visualization.points.map((entry) => entry.point);
  const basis = visualization.basis;
  const all = points.concat([[0, 0], basis[0], basis[1]]);
  const maxX = Math.max(...all.map((point) => Math.abs(point[0])), 1);
  const maxY = Math.max(...all.map((point) => Math.abs(point[1])), 1);
  const scale = Math.min((width - 90) / (2 * maxX), (height - 70) / (2 * maxY));
  const origin = { x: width / 2, y: height / 2 };
  const project = ([x, y]) => ({ x: origin.x + x * scale, y: origin.y - y * scale });

  context.strokeStyle = "rgba(156, 163, 175, 0.2)";
  context.lineWidth = 1;
  context.beginPath();
  context.moveTo(20, origin.y);
  context.lineTo(width - 20, origin.y);
  context.moveTo(origin.x, 20);
  context.lineTo(origin.x, height - 20);
  context.stroke();

  points.forEach((point) => {
    const projected = project(point);
    context.fillStyle = "#8b5cf6";
    context.beginPath();
    context.arc(projected.x, projected.y, 3, 0, Math.PI * 2);
    context.fill();
  });

  drawArrow(context, origin, project(basis[0]), "#22d3ee", "b1");
  drawArrow(context, origin, project(basis[1]), "#34d399", "b2");
  context.fillStyle = "#f3f4f6";
  context.beginPath();
  context.arc(origin.x, origin.y, 4, 0, Math.PI * 2);
  context.fill();
  context.font = "12px Segoe UI, sans-serif";
  context.fillText("origin", origin.x + 8, origin.y + 18);
}

function renderLLL(report) {
  const lll = report.lll;
  MatrixDisplay("lwe-demo-lll-original", lll.original_basis, { label: "Original basis" });
  MatrixDisplay("lwe-demo-lll-reduced", lll.reduced_basis, { label: "Reduced basis" });
  MatrixDisplay("lwe-demo-lll-norms", [lll.original_norms, lll.reduced_norms], { label: "Euclidean vector norms" });
  renderStatGrid("lwe-demo-lll-stats", [
    ["Iterations", lll.iterations],
    ["Swaps", lll.swaps],
    ["Execution time", `${lll.execution_time_ms} ms`],
    ["Reduction status", lll.reduction_status],
  ]);
}

function renderTotalPerformance() {
  renderStatGrid("lwe-demo-total-performance", [
    ["Key generation time", formatMilliseconds(lweDemoState.keyGenerationTimeMs, "Key generation time")],
    ["Encryption time", formatMilliseconds(lweDemoState.encryptionTimeMs, "Encryption time")],
    ["Decryption time", formatMilliseconds(lweDemoState.decryptionTimeMs, "Decryption time")],
    ["Total workflow time", formatMilliseconds(
      Number(lweDemoState.keyGenerationTimeMs) + Number(lweDemoState.encryptionTimeMs) + Number(lweDemoState.decryptionTimeMs),
      "Total workflow time"
    )],
  ]);
}

function ciphertextIsWellFormed(ciphertext, publicKey) {
  const dimension = publicKey.matrix_A[0].length;
  return Array.isArray(ciphertext.ciphertexts)
    && ciphertext.ciphertexts.length > 0
    && ciphertext.ciphertexts.every((block) => Array.isArray(block.samples)
      && block.samples.length === dimension
      && block.samples.every((sample) => Array.isArray(sample.u)
        && sample.u.length === dimension
        && sample.u.every((value) => Number.isInteger(value))
        && Number.isInteger(sample.v)));
}

function resetEncryptionDisplay() {
  ["lwe-demo-flow-plaintext", "lwe-demo-flow-encoding", "lwe-demo-flow-encryption", "lwe-demo-flow-ciphertext"]
    .forEach((elementId) => setElementText(elementId, "-"));
  const status = document.getElementById("lwe-demo-encrypt-status");
  if (status) {
    status.textContent = "-";
    status.className = "status-value";
  }
}

function renderEncryptionStep(message, ciphertext) {
  const blocks = ciphertext.ciphertexts;
  const samplesPerBlock = blocks[0].samples.length;
  const [uEquation, vEquation] = lweDemoState.report.lwe.equations.encryption.split(";").map((part) => part.trim());

  setElementText("lwe-demo-flow-plaintext", message);
  setElementText("lwe-demo-flow-encoding", `${blocks.length} blocks x ${samplesPerBlock} symbols`);
  setElementText("lwe-demo-flow-encryption", uEquation);
  setElementText("lwe-demo-flow-ciphertext", `${blocks.length} blocks, ${blocks.length * samplesPerBlock} (u, v) samples`);
  renderEquationGrid("lwe-demo-equations", { "u equation": uEquation, "v equation": vEquation });

  const wellFormed = ciphertextIsWellFormed(ciphertext, lweDemoState.publicKey);
  const status = document.getElementById("lwe-demo-encrypt-status");
  if (status) {
    status.textContent = wellFormed ? "\u2713 ENCRYPTION SUCCESSFUL" : "\u2717 ENCRYPTION FAILED";
    status.className = `status-value ${wellFormed ? "status-pass" : "status-fail"}`;
  }

  MatrixDisplay("lwe-demo-encoded", blocks.map((block) => block.message_block), { label: "Encoded message blocks (symbols)" });
  renderEncryptionPublicKey(lweDemoState.backend);
  MatrixCiphertext("lwe-demo-ciphertext", ciphertext);
  renderStatGrid("lwe-demo-ciphertext-meta", [
    ["Ciphertext form", "(u, v) per message symbol"],
    ["Blocks", blocks.length],
    ["Samples per block", samplesPerBlock],
    ["Modulus q", ciphertext.modulus],
    ["Message modulus p", ciphertext.message_modulus],
    ["Noise bound", ciphertext.noise_bound],
    ["Message bytes", ciphertext.message_length_bytes],
    ["Padding bytes", ciphertext.padding_bytes],
    ["Ciphertext JSON bytes", ciphertext.ciphertext_bytes_length],
    ["Encryption time", formatMilliseconds(ciphertext.encryption_time_ms, "Encryption time")],
    ["Backend used", ciphertext.backend_used || lweDemoState.backend.backend_used || lweDemoState.backend.backend],
  ]);
  return wellFormed;
}

function resetDecryptionDisplay() {
  renderEquationGrid("lwe-demo-decrypt-equations", {});
  setElementText("lwe-demo-original", "-");
  setElementText("lwe-demo-recovered", "-");
  setElementText("lwe-demo-recovered-encoded", "-");
  setElementText("lwe-demo-decryption-time", "-");
  setElementText("lwe-demo-verification", "-");
  const result = document.getElementById("lwe-demo-roundtrip");
  if (result) {
    result.textContent = "-";
    result.className = "status-value";
  }
}

function renderDecryptionStep(result) {
  const plaintext = requiredField(result, "plaintext", "Decryption response");
  const decryptionTime = requiredField(result, "decryption_time_ms", "Decryption response");
  const blocks = lweDemoState.ciphertext.ciphertexts;
  const samples = blocks.flatMap((block) => block.samples);
  MatrixVector("lwe-demo-decrypt-secret", lweDemoState.secretKey.secret, "s = secret vector");
  MatrixCiphertext("lwe-demo-decrypt-ciphertext-values", lweDemoState.ciphertext);
  renderStatGrid("lwe-demo-decrypt-ciphertext", [
    ["Ciphertext (u, v)", `${blocks.length} blocks, ${samples.length} samples`],
    ["First sample u", `[${samples[0].u.join(", ")}]`],
    ["First sample v", samples[0].v],
    ["Decryption time", formatMilliseconds(decryptionTime, "Decryption time")],
    ["Backend used", result.backend_used || lweDemoState.backend.backend_used || lweDemoState.backend.backend],
  ]);

  const [tEquation, symbolEquation] = lweDemoState.report.lwe.equations.decryption
    .split(";").map((part) => part.trim());
  renderEquationGrid("lwe-demo-decrypt-equations", {
    "t equation": tEquation,
    "symbol equation": symbolEquation,
  });

  const matches = plaintext === lweDemoState.encryptedMessage;
  setElementText("lwe-demo-original", lweDemoState.encryptedMessage);
  setElementText("lwe-demo-recovered-encoded", Array.isArray(result.recovered_encoded_message)
    ? `[${result.recovered_encoded_message.join(", ")}]`
    : "Execution data unavailable from backend.");
  setElementText("lwe-demo-recovered", plaintext);
  setElementText("lwe-demo-decryption-time", formatMilliseconds(decryptionTime, "Decryption time"));
  const verificationPassed = result.verification?.passed ?? matches;
  setElementText("lwe-demo-verification", verificationPassed ? "PASSED" : "FAILED");
  const verificationElement = document.getElementById("lwe-demo-verification");
  if (verificationElement) verificationElement.className = `status-value ${verificationPassed ? "status-pass" : "status-fail"}`;
  const resultElement = document.getElementById("lwe-demo-roundtrip");
  if (resultElement) {
    resultElement.textContent = matches ? "\u2713 DECRYPTION SUCCESSFUL" : "\u2717 DECRYPTION FAILED";
    resultElement.className = `status-value ${matches ? "status-pass" : "status-fail"}`;
  }
  return matches;
}

function resetDownstreamSteps() {
  ["encrypt", "ciphertext", "decrypt"].forEach((step) => setLweStepVisible(step, false));
  ["publicKey", "secretKey", "lattice", "lll", "benchmark", "architecture"].forEach((step) => setLweStepVisible(step, true));
  resetDecryptionDisplay();
}

async function generateLWEDemo() {
  const generateButton = document.getElementById("btn-lwe-generate");
  const message = document.getElementById("lwe-demo-message").value;
  const dimension = parseInt(document.getElementById("lwe-demo-dimension").value, 10);
  const backend = document.getElementById("lwe-demo-backend").value;

  if (!message) {
    setOperationState("lwe-demo-status", "invalid", "Enter a plaintext message first.");
    return;
  }
  if (![2, 3].includes(dimension)) {
    setOperationState("lwe-demo-status", "invalid", "Choose a supported demonstration dimension: 2 or 3.");
    return;
  }

  generateButton.disabled = true;
  setLweButtonState("btn-lwe-encrypt", false);
  setLweButtonState("btn-lwe-decrypt", false);
  setOperationState("lwe-demo-status", "loading", "Step 1 of 3 - generating the LWE key pair with the existing backend...");

  try {
    const report = await requestJson("/api/lattice/demo", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message, dimension, backend }),
    });
    if (report.status !== "PASS") throw new Error("The backend demonstration did not pass its round-trip check.");
    const payload = selectPrimaryBackend(report);
    if (!payload) throw new Error("The demonstration returned no backend result.");

    lweDemoState.report = report;
    lweDemoState.backend = payload;
    lweDemoState.publicKey = payload.public_key;
    lweDemoState.secretKey = payload.secret_key;
    lweDemoState.ciphertext = null;
    lweDemoState.encryptedMessage = "";
    lweDemoState.keyGenerationTimeMs = requiredField(payload, "key_generation_ms", "Key generation response");
    lweDemoState.encryptionTimeMs = null;
    lweDemoState.decryptionTimeMs = null;

    renderParameters(report);
    renderPublicParameters(payload);
    renderKeyTiming(payload);
    renderPublicKey(payload);
    renderSecretKey(payload);
    renderEquationGrid("lwe-demo-key-equation", { key_generation: report.lwe.equations.key_generation });
    renderLattice(report);
    renderLLL(report);
    resetDownstreamSteps();
    resetEncryptionDisplay();

    document.getElementById("lwe-demo-output").hidden = false;
    setLweButtonState("btn-lwe-encrypt", true);
    const fallbackNotice = report.lwe.fallback
      ? " Native C LWE backend is unavailable on this system. Using Python reference backend."
      : "";
    setOperationState(
      "lwe-demo-status",
      "success",
      `Step 1 of 3 complete: Public Key (A, b) and Secret Key s are shown above. The next step encrypts using only (A, b).${fallbackNotice}`
    );
  } catch (error) {
    lweDemoState.report = null;
    lweDemoState.backend = null;
    lweDemoState.publicKey = null;
    lweDemoState.secretKey = null;
    setOperationState("lwe-demo-status", "error", `Key generation unavailable: ${error.message}`);
  } finally {
    generateButton.disabled = false;
  }
}

async function encryptWithPublicKey() {
  const encryptButton = document.getElementById("btn-lwe-encrypt");
  if (!lweDemoState.publicKey) {
    setOperationState("lwe-demo-status", "invalid", "Step 1 must run first: encryption needs the generated Public Key (A, b).");
    return;
  }
  const message = document.getElementById("lwe-demo-message").value;
  if (!message) {
    setOperationState("lwe-demo-status", "invalid", "Enter a plaintext message to encrypt.");
    return;
  }

  encryptButton.disabled = true;
  setLweButtonState("btn-lwe-decrypt", false);
  setOperationState("lwe-demo-status", "loading", "Step 2 of 3 - encrypting with Public Key (A, b) through the existing backend...");

  try {
    const ciphertext = await requestJson("/api/lattice/encrypt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ plaintext: message, public_key: lweDemoState.publicKey }),
    });
    requiredField(ciphertext, "encryption_time_ms", "Encryption response");
    if (!Array.isArray(ciphertext.ciphertexts) || ciphertext.ciphertexts.length === 0) {
      throw new Error("The encryption endpoint returned no ciphertext.");
    }

    lweDemoState.ciphertext = ciphertext;
    lweDemoState.encryptedMessage = message;
    lweDemoState.encryptionTimeMs = ciphertext.encryption_time_ms;
    const wellFormed = renderEncryptionStep(message, ciphertext);

    setLweStepVisible("encrypt", true);
    setLweStepVisible("ciphertext", true);
    setLweStepVisible("decrypt", false);
    setLweButtonState("btn-lwe-decrypt", true);
    document.getElementById(LWE_STEP_IDS.ciphertext)?.scrollIntoView({ behavior: "smooth", block: "start" });
    setOperationState(
      "lwe-demo-status",
      wellFormed ? "success" : "error",
      wellFormed
        ? "Step 2 of 3 complete: LWE encryption with the public key produced the ciphertext (u, v). The next step decrypts using only Secret Key s."
        : "Encryption returned a malformed ciphertext, so it cannot be decrypted."
    );
  } catch (error) {
    lweDemoState.ciphertext = null;
    lweDemoState.encryptedMessage = "";
    setLweStepVisible("ciphertext", false);
    setOperationState("lwe-demo-status", "error", `Encryption failed: ${error.message}`);
  } finally {
    encryptButton.disabled = false;
  }
}

async function decryptWithSecretKey() {
  const decryptButton = document.getElementById("btn-lwe-decrypt");
  if (!lweDemoState.ciphertext || !lweDemoState.secretKey) {
    setOperationState("lwe-demo-status", "invalid", "Step 2 must run first: decryption needs the ciphertext (u, v) and Secret Key s.");
    return;
  }

  decryptButton.disabled = true;
  setOperationState("lwe-demo-status", "loading", "Step 3 of 3 - decrypting Ciphertext (u,v) to plaintext with Private Key s...");

  try {
    const result = await requestJson("/api/lattice/decrypt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ciphertext: lweDemoState.ciphertext,
        private_key: lweDemoState.secretKey,
        original_message: lweDemoState.encryptedMessage,
      }),
    });
    lweDemoState.decryptionTimeMs = requiredField(result, "decryption_time_ms", "Decryption response");
    const matches = renderDecryptionStep(result);
    renderTotalPerformance();
    setLweStepVisible("decrypt", true);
    document.getElementById(LWE_STEP_IDS.decrypt)?.scrollIntoView({ behavior: "smooth", block: "start" });
    setOperationState(
      "lwe-demo-status",
      matches ? "success" : "error",
      matches
        ? "Step 3 of 3 complete: Ciphertext (u,v) was decrypted to the recovered plaintext."
        : "The recovered plaintext does not match the encrypted message."
    );
  } catch (error) {
    setOperationState("lwe-demo-status", "error", `Decryption failed: ${error.message}`);
  } finally {
    decryptButton.disabled = false;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("btn-lwe-generate")?.addEventListener("click", generateLWEDemo);
  document.getElementById("btn-lwe-encrypt")?.addEventListener("click", encryptWithPublicKey);
  document.getElementById("btn-lwe-decrypt")?.addEventListener("click", decryptWithSecretKey);
  document.getElementById("btn-lwe-regenerate-lattice")?.addEventListener("click", generateLWEDemo);
  document.getElementById("lwe-demo-message")?.addEventListener("input", () => {
    renderMessageConfiguration(lweDemoState.report?.lwe?.message_capacity);
  });
});

