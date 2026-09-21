/**
 * RSA Cryptography Client Controller
 * Handles Key Generation, Key Metadata Inspection, Encryption, Decryption, and Verification.
 */

// 1. RSA Key Generation
async function generateKey() {
  const sizeSelect = document.getElementById("keygen-size");
  const keySize = parseInt(sizeSelect.value, 10);
  const btn = document.getElementById("btn-generate-key");

  btn.disabled = true;
  btn.innerText = "Generating...";
  setOperationState("keygen-status", "loading", "Generating RSA key pair...");

  try {
    const data = await requestJson("/api/rsa/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key_size: keySize }),
    });
    requireFields(data, ["key_size", "public_exponent", "generation_time_ms", "public_key_pem", "private_key_pem"], "Key generation");

    appState.currentKeypair = data;

    // Enable view buttons
    document.getElementById("btn-view-pub").disabled = false;
    document.getElementById("btn-view-priv").disabled = false;

    // Display summary
    document.getElementById("sum-alg").innerText = "RSA";
    document.getElementById("sum-size").innerText = `${data.key_size} bits`;
    document.getElementById("sum-exp").innerText = `${data.public_exponent}`;
    document.getElementById("sum-time").innerText = `${data.generation_time_ms} ms`;
    document.getElementById("keygen-summary").style.display = "block";

    // Update active key size label on encryption tab
    const encKeyLabel = document.getElementById("enc-active-keysize");
    if (encKeyLabel) {
      encKeyLabel.innerText = `${data.key_size} bits`;
    }

    setOperationState("keygen-status", "success", `RSA ${data.key_size}-bit key pair generated successfully in ${data.generation_time_ms} ms.`);
  } catch (err) {
    setOperationState("keygen-status", "error", `Key generation failed: ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.innerText = "Generate Key Pair";
  }
}

// 2. View Keys in Modal
function viewPublicKey() {
  if (!appState.currentKeypair) return;
  openKeyModal("RSA Public Key (PEM)", appState.currentKeypair.public_key_pem);
}

function viewPrivateKey() {
  if (!appState.currentKeypair) return;
  openKeyModal("RSA Private Key (PEM)", appState.currentKeypair.private_key_pem);
}

// 3. Inspect Key Metadata
async function inspectKey() {
  const pemInput = document.getElementById("keyinfo-input").value.trim();
  if (!pemInput) {
    setOperationState("keyinfo-status", "invalid", "Paste a public or private PEM key first.");
    return;
  }

  setOperationState("keyinfo-status", "loading", "Inspecting key metadata...");

  const payload = pemInput.includes("PRIVATE KEY")
    ? { private_key_pem: pemInput }
    : { public_key_pem: pemInput };

  try {
    const data = await requestJson("/api/rsa/info", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    requireFields(data, ["info"], "Key inspection");
    const infoObj = data.info.public_key || data.info.private_key;
    if (!infoObj || typeof infoObj !== "object") {
      throw new Error("Key inspection returned no metadata.");
    }
    const detailsDiv = document.getElementById("keyinfo-details");

    let formatted = "";
    for (const [key, val] of Object.entries(infoObj)) {
      formatted += `${key.padEnd(20)}: ${val}\n`;
    }

    detailsDiv.innerText = formatted;
    document.getElementById("keyinfo-result").style.display = "block";
    setOperationState("keyinfo-status", "success", "Key metadata loaded successfully.");
  } catch (err) {
    setOperationState("keyinfo-status", "error", `Key inspection failed: ${err.message}`);
  }
}

// 4. RSA Encryption
async function encryptMessage() {
  const plaintext = document.getElementById("enc-plaintext").value;
  if (!plaintext) {
    setOperationState("encryption-status", "invalid", "Enter a plaintext message first.");
    return;
  }

  if (!appState.currentKeypair) {
    setOperationState("encryption-status", "invalid", "Generate an RSA key pair before encrypting.");
    navTo("tab-keygen");
    return;
  }

  const btn = document.getElementById("btn-encrypt-msg");
  btn.disabled = true;
  btn.innerText = "Encrypting...";
  setOperationState("encryption-status", "loading", "Encrypting with RSA-OAEP...");

  try {
    const data = await requestJson("/api/rsa/encrypt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        plaintext: plaintext,
        public_key_pem: appState.currentKeypair.public_key_pem,
      }),
    });
    requireFields(data, ["ciphertext_base64", "encryption_time_ms", "plaintext_bytes_length", "ciphertext_bytes_length"], "Encryption");

    appState.lastPlaintext = plaintext;
    appState.lastCiphertext = data.ciphertext_base64;

    document.getElementById("enc-ciphertext").value = data.ciphertext_base64;
    document.getElementById("enc-time").innerText = `${data.encryption_time_ms} ms`;
    document.getElementById("enc-bytes").innerText = `${data.plaintext_bytes_length} bytes -> ${data.ciphertext_bytes_length} bytes`;
    document.getElementById("enc-result-box").style.display = "block";
    setOperationState("encryption-status", "success", "Message encrypted successfully.");
  } catch (err) {
    setOperationState("encryption-status", "error", `Encryption failed: ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.innerText = "Encrypt Message";
  }
}

function copyCiphertext() {
  const cipher = document.getElementById("enc-ciphertext").value;
  navigator.clipboard.writeText(cipher).then(() => {
    alert("Ciphertext copied to clipboard!");
  });
}

function transferToDecrypt() {
  const cipher = document.getElementById("enc-ciphertext").value;
  document.getElementById("dec-ciphertext").value = cipher;
  navTo("tab-decryption");
}

// 5. RSA Decryption & Verification
async function decryptMessage() {
  const ciphertext = document.getElementById("dec-ciphertext").value.trim();
  if (!ciphertext) {
    setOperationState("decryption-status", "invalid", "Enter or paste a Base64 ciphertext first.");
    return;
  }

  if (!appState.currentKeypair) {
    setOperationState("decryption-status", "invalid", "Generate an RSA key pair before decrypting.");
    navTo("tab-keygen");
    return;
  }

  const btn = document.getElementById("btn-decrypt-msg");
  btn.disabled = true;
  btn.innerText = "Decrypting...";
  setOperationState("decryption-status", "loading", "Decrypting with RSA-OAEP...");

  try {
    const data = await requestJson("/api/rsa/decrypt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ciphertext_base64: ciphertext,
        private_key_pem: appState.currentKeypair.private_key_pem,
      }),
    });
    requireFields(data, ["decrypted_plaintext", "decryption_time_ms"], "Decryption");

    const decryptedText = data.decrypted_plaintext;
    document.getElementById("dec-plaintext").value = decryptedText;
    document.getElementById("dec-time").innerText = `${data.decryption_time_ms} ms`;
    document.getElementById("dec-result-box").style.display = "block";
    setOperationState("decryption-status", "success", "Message decrypted successfully.");

    // Trigger Verification
    verifyRoundtrip(decryptedText);
  } catch (err) {
    setOperationState("decryption-status", "error", `Decryption failed: ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.innerText = "Decrypt Message";
  }
}

async function verifyRoundtrip(decryptedText) {
  const original = appState.lastPlaintext;
  const banner = document.getElementById("verification-banner");
  const icon = document.getElementById("verif-icon");
  const text = document.getElementById("verif-text");

  if (!original) {
    banner.className = "verif-box verif-pass";
    icon.innerHTML = "&#x2713;";
    text.innerText = "DECRYPTION SUCCESSFUL (Original message not cached in session for direct match)";
    setOperationState("verification-status", "success", "Decryption succeeded; no original message is cached for comparison.");
    return;
  }

  try {
    const data = await requestJson("/api/rsa/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        original_message: original,
        decrypted_message: decryptedText,
      }),
    });
    requireFields(data, ["passed", "status"], "Verification");
    if (data.passed) {
      banner.className = "verif-box verif-pass";
      icon.innerHTML = "&#x2713;";
      text.innerText = "VERIFICATION PASSED: Decrypted message matches original plaintext exactly.";
    } else {
      banner.className = "verif-box verif-fail";
      icon.innerHTML = "&#x2717;";
      text.innerText = "VERIFICATION FAILED: Decrypted message does not match original plaintext.";
    }
    setOperationState("verification-status", data.passed ? "success" : "error", data.status);
  } catch (err) {
    banner.className = "verif-box verif-fail";
    icon.innerHTML = "&#x2717;";
    text.innerText = "VERIFICATION ERROR";
    setOperationState("verification-status", "error", `Verification failed: ${err.message}`);
  }
}

// Bind DOM event listeners
document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("btn-generate-key")?.addEventListener("click", generateKey);
  document.getElementById("btn-view-pub")?.addEventListener("click", viewPublicKey);
  document.getElementById("btn-view-priv")?.addEventListener("click", viewPrivateKey);
  document.getElementById("btn-inspect-key")?.addEventListener("click", inspectKey);
  document.getElementById("btn-encrypt-msg")?.addEventListener("click", encryptMessage);
  document.getElementById("btn-decrypt-msg")?.addEventListener("click", decryptMessage);
});