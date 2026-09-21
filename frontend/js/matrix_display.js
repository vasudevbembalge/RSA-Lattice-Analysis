/**
 * Reusable educational matrix and vector renderer.
 * This is presentation-only; it never changes the returned values.
 */

function normalizeMatrix(value) {
  if (!Array.isArray(value) || value.length === 0) return null;
  if (value.every((row) => !Array.isArray(row))) return [value];
  if (!value.every((row) => Array.isArray(row))) return null;
  const columns = value[0].length;
  if (!columns || !value.every((row) => row.length === columns)) return null;
  return value;
}

function MatrixDisplay(container, value, options = {}) {
  const target = typeof container === "string" ? document.getElementById(container) : container;
  if (!target) return;
  const matrix = normalizeMatrix(value);
  target.replaceChildren();
  target.classList.add("matrix-component");
  if (!matrix) {
    target.textContent = "No matrix data available.";
    target.classList.add("matrix-invalid");
    return;
  }

  const rows = matrix.length;
  const columns = matrix[0].length;
  const label = options.label || (rows === 1 || columns === 1 ? "Vector" : "Matrix");
  const header = document.createElement("div");
  header.className = "matrix-component-header";
  const title = document.createElement("strong");
  title.textContent = label;
  const dimensions = document.createElement("span");
  dimensions.textContent = `${rows} × ${columns}`;
  header.append(title, dimensions);
  target.appendChild(header);

  const viewport = document.createElement("div");
  viewport.className = "matrix-viewport";
  const frame = document.createElement("div");
  frame.className = "matrix-frame";
  const table = document.createElement("table");
  table.className = "matrix-table-readable";
  table.setAttribute("aria-label", `${label}, ${rows} by ${columns}`);
  const body = document.createElement("tbody");

  matrix.forEach((row) => {
    const tableRow = document.createElement("tr");
    row.forEach((cell) => {
      const tableCell = document.createElement("td");
      tableCell.textContent = String(cell);
      tableRow.appendChild(tableCell);
    });
    body.appendChild(tableRow);
  });
  table.appendChild(body);
  frame.appendChild(table);
  viewport.appendChild(frame);
  target.appendChild(viewport);

  if (rows * columns > 80) {
    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "matrix-toggle";
    toggle.textContent = "Collapse";
    toggle.addEventListener("click", () => {
      const collapsed = viewport.classList.toggle("matrix-collapsed");
      toggle.textContent = collapsed ? "Show matrix" : "Collapse";
    });
    target.appendChild(toggle);
  }
}

function MatrixVector(container, value, label) {
  MatrixDisplay(container, value, { label: label || "Vector" });
}

/**
 * Render an LWE ciphertext exactly as returned by the backend.
 *
 * Each message symbol has one independent LWE sample, so every ciphertext block
 * is displayed as the sample vectors u and the matching sample scalars v.
 */
function MatrixCiphertext(container, ciphertext, options = {}) {
  const target = typeof container === "string" ? document.getElementById(container) : container;
  if (!target) return;
  target.replaceChildren();
  const blocks = ciphertext?.ciphertexts;
  if (!Array.isArray(blocks) || blocks.length === 0) {
    target.textContent = "No ciphertext data available.";
    return;
  }

  blocks.forEach((block, blockIndex) => {
    const samples = Array.isArray(block.samples) ? block.samples : [];
    const wrapper = document.createElement("div");
    wrapper.className = "ciphertext-block";

    const heading = document.createElement("div");
    heading.className = "ciphertext-block-heading";
    const symbols = samples.map((sample, index) => String(
      sample.symbol !== undefined ? sample.symbol : (Array.isArray(block.message_block) ? block.message_block[index] : index)
    ));
    heading.textContent = symbols.length > 0
      ? `Ciphertext block ${blockIndex + 1} - encoded symbols [${symbols.join(", ")}]`
      : `Ciphertext block ${blockIndex + 1}`;
    wrapper.appendChild(heading);

    const grid = document.createElement("div");
    grid.className = "ciphertext-uv-grid";

    const uHost = document.createElement("div");
    MatrixDisplay(uHost, samples.map((sample) => sample.u), {
      label: options.uLabel || "u = LWE sample vectors",
    });

    const vHost = document.createElement("div");
    MatrixVector(vHost, samples.map((sample) => sample.v), options.vLabel || "v = LWE sample scalars");

    grid.append(uHost, vHost);
    wrapper.appendChild(grid);
    target.appendChild(wrapper);
  });
}
