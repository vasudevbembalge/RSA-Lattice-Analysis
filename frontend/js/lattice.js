/**
 * Lattice Analysis Client Controller
 * Handles Matrix Grid Editing, Preset Loading, Random Matrix Generation,
 * and Native C LLL Invocation.
 */

let currentMatrix = [
  [105, 821, 404],
  [31, 57, 91],
  [12, 34, 77],
];

function renderMatrixGrid(matrix) {
  const container = document.getElementById("matrix-editor-container");
  if (!container) return;

  if (!Array.isArray(matrix) || matrix.length === 0 || !Array.isArray(matrix[0]) || matrix[0].length === 0) {
    setOperationState("lattice-status", "error", "The matrix response is empty or malformed.");
    return;
  }

  const rows = matrix.length;
  const cols = matrix[0].length;
  if (!matrix.every((row) => Array.isArray(row) && row.length === cols && row.every((value) => Number.isInteger(value)))) {
    setOperationState("lattice-status", "error", "The matrix response contains invalid or inconsistent entries.");
    return;
  }

  document.getElementById("lat-rows").value = rows;
  document.getElementById("lat-cols").value = cols;

  let html = '<table class="matrix-table">';
  for (let r = 0; r < rows; r++) {
    html += "<tr>";
    for (let c = 0; c < cols; c++) {
      const val = matrix[r][c];
      html += `<td class="matrix-cell">
        <input type="number" id="cell-${r}-${c}" value="${String(val)}">
      </td>`;
    }
    html += "</tr>";
  }
  html += "</table>";
  container.innerHTML = html;
}

function readMatrixGrid() {
  const rows = parseInt(document.getElementById("lat-rows").value, 10);
  const cols = parseInt(document.getElementById("lat-cols").value, 10);
  const matrix = [];

  for (let r = 0; r < rows; r++) {
    const row = [];
    for (let c = 0; c < cols; c++) {
      const cell = document.getElementById(`cell-${r}-${c}`);
      if (!cell) {
        throw new Error(`Missing input at cell (${r}, ${c})`);
      }
      const val = parseInt(cell.value, 10);
      if (isNaN(val)) {
        throw new Error(`Matrix cell (${r + 1}, ${c + 1}) must contain a valid integer.`);
      }
      row.push(val);
    }
    matrix.push(row);
  }
  return matrix;
}

function resizeGrid() {
  const rows = parseInt(document.getElementById("lat-rows").value, 10);
  const cols = parseInt(document.getElementById("lat-cols").value, 10);

  if (!Number.isInteger(rows) || !Number.isInteger(cols) || rows <= 0 || cols < rows) {
    setOperationState("lattice-status", "invalid", "Invalid dimensions: rows must be positive and no greater than columns.");
    return;
  }
  if (rows > 10 || cols > 10) {
    setOperationState("lattice-status", "invalid", "The interactive editor supports dimensions up to 10x10.");
    return;
  }

  const newMat = [];
  for (let r = 0; r < rows; r++) {
    const row = [];
    for (let c = 0; c < cols; c++) {
      const existing = currentMatrix[r] && currentMatrix[r][c] !== undefined ? currentMatrix[r][c] : (r === c ? 1 : 0);
      row.push(existing);
    }
    newMat.push(row);
  }
  currentMatrix = newMat;
  renderMatrixGrid(currentMatrix);
}

async function loadPreset() {
  const presetType = document.getElementById("lat-preset").value;
  setOperationState("lattice-status", "loading", "Loading lattice preset...");
  try {
    const data = await requestJson("/api/lattice/samples");
    const sample = data?.samples?.[presetType];
    if (sample && Array.isArray(sample.matrix)) {
      currentMatrix = sample.matrix;
      renderMatrixGrid(currentMatrix);
      setOperationState("lattice-status", "success", `${sample.name || "Preset"} loaded.`);
      return;
    }
    throw new Error("The selected preset was not included in the API response.");
  } catch (err) {
    setOperationState("lattice-status", "error", `Preset loading failed: ${err.message}`);
    return;
  }
}

async function generateRandom() {
  const rows = parseInt(document.getElementById("lat-rows").value, 10);
  const cols = parseInt(document.getElementById("lat-cols").value, 10);

  if (!Number.isInteger(rows) || !Number.isInteger(cols) || rows <= 0 || cols < rows || rows > 10 || cols > 10) {
    setOperationState("lattice-status", "invalid", "Choose valid dimensions with 1 <= rows <= columns <= 10.");
    return;
  }

  setOperationState("lattice-status", "loading", "Generating random lattice matrix...");

  try {
    const data = await requestJson("/api/lattice/random", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rows: rows, cols: cols }),
    });
    requireFields(data, ["matrix", "rows", "cols"], "Random matrix generation");
    if (!Array.isArray(data.matrix) || data.matrix.length !== rows ||
        data.matrix.some((row) => !Array.isArray(row) || row.length !== cols ||
          row.some((value) => !Number.isInteger(value)))) {
      throw new Error("The random matrix response has invalid dimensions.");
    }
    currentMatrix = data.matrix;
    renderMatrixGrid(currentMatrix);
    setOperationState("lattice-status", "success", "Random lattice matrix generated.");
  } catch (err) {
    setOperationState("lattice-status", "error", `Random matrix generation failed: ${err.message}`);
  }
}

function clearMatrix() {
  const rows = parseInt(document.getElementById("lat-rows").value, 10);
  const cols = parseInt(document.getElementById("lat-cols").value, 10);
  const emptyMat = [];
  for (let r = 0; r < rows; r++) {
    emptyMat.push(new Array(cols).fill(0));
  }
  currentMatrix = emptyMat;
  renderMatrixGrid(currentMatrix);
}

async function runLLL() {
  let matrix;
  try {
    matrix = readMatrixGrid();
  } catch (err) {
    setOperationState("lattice-status", "invalid", err.message);
    return;
  }

  const delta = parseFloat(document.getElementById("lat-delta").value);
  if (isNaN(delta) || delta <= 0.25 || delta > 1.0) {
    setOperationState("lattice-status", "invalid", "Lovasz parameter delta must satisfy 0.25 < delta <= 1.0.");
    return;
  }

  const btn = document.getElementById("btn-run-lll");
  btn.disabled = true;
  btn.innerText = "Reducing with C Engine...";
  setOperationState("lattice-status", "loading", "Running lattice basis reduction with the native C engine...");

  try {
    const data = await requestJson("/api/lattice/reduce", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ matrix: matrix, delta: delta }),
    });
    requireFields(data, ["original_basis", "reduced_basis", "original_norms", "reduced_norms", "iterations", "swaps", "execution_time_ms", "reduction_status"], "LLL reduction");
    if (!Array.isArray(data.reduced_basis) || !Array.isArray(data.original_norms) || !Array.isArray(data.reduced_norms)) {
      throw new Error("LLL reduction returned malformed basis or norm data.");
    }

    // Display telemetry
    MatrixDisplay("disp-orig-basis", data.original_basis, { label: "Original Basis" });
    MatrixDisplay("disp-red-basis", data.reduced_basis, { label: "Reduced Basis" });

    document.getElementById("lll-res-iter").innerText = data.iterations;
    document.getElementById("lll-res-swaps").innerText = data.swaps;
    document.getElementById("lll-res-time").innerText = `${data.execution_time_ms} ms`;
    document.getElementById("lll-res-status").innerText = data.reduction_status;
    document.getElementById("lll-orig-norms").innerText = data.original_norms.join(", ");
    document.getElementById("lll-red-norms").innerText = data.reduced_norms.join(", ");

    document.getElementById("lll-output-container").style.display = "block";
    setOperationState("lattice-status", "success", "Lattice basis reduction completed successfully.");
  } catch (err) {
    setOperationState("lattice-status", "error", `LLL reduction failed: ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.innerText = "Run LLL Reduction";
  }
}

document.addEventListener("DOMContentLoaded", () => {
  renderMatrixGrid(currentMatrix);

  document.getElementById("btn-resize-grid")?.addEventListener("click", resizeGrid);
  document.getElementById("btn-load-preset")?.addEventListener("click", loadPreset);
  document.getElementById("btn-random-matrix")?.addEventListener("click", generateRandom);
  document.getElementById("btn-clear-matrix")?.addEventListener("click", clearMatrix);
  document.getElementById("btn-run-lll")?.addEventListener("click", runLLL);
});