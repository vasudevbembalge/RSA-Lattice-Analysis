/**
 * Chart.js rendering for validated empirical benchmark reports.
 * Charts display operational measurements only, not cryptanalytic results.
 */

const benchmarkCharts = {
  rsaPerformance: null,
  lllExecution: null,
  lllIterations: null,
  normReduction: null,
};

const chartPalette = {
  blue: "#60a5fa",
  cyan: "#22d3ee",
  emerald: "#34d399",
  amber: "#fbbf24",
  rose: "#fb7185",
};

function setChartState(chartId, state, message) {
  const canvas = document.getElementById(chartId);
  const status = document.getElementById(`${chartId}-status`);
  if (!canvas || !status) return;

  canvas.hidden = state !== "success";
  status.className = `chart-status chart-${state}`;
  status.textContent = message;
  status.hidden = state === "success";
}

function destroyChart(chartKey, chartId) {
  if (benchmarkCharts[chartKey]) {
    benchmarkCharts[chartKey].destroy();
    benchmarkCharts[chartKey] = null;
  }
  setChartState(chartId, "loading", "Loading benchmark data...");
}

function chartOptions(yTitle) {
  return {
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    plugins: {
      legend: { labels: { color: "#f3f4f6" } },
    },
    scales: {
      x: {
        title: { display: true, text: "Measured configuration", color: "#9ca3af" },
        ticks: { color: "#9ca3af" },
        grid: { color: "" },
      },
      y: {
        title: { display: true, text: yTitle, color: "#9ca3af" },
        ticks: { color: "#9ca3af" },
        grid: { color: "rgba(156, 163, 175, 0.16)" },
        beginAtZero: true,
      },
    },
  };
}

function makeDataset(label, data, color) {
  return {
    label,
    data,
    borderColor: color,
    backgroundColor: `${color}55`,
    borderWidth: 2,
    pointRadius: 3,
    tension: 0.15,
    fill: false,
  };
}

function validNumber(value) {
  return typeof value === "number" && Number.isFinite(value);
}

function validateChartReport(report) {
  if (!report || !Array.isArray(report.rsa_benchmarks) || !report.lattice_benchmarks) {
    throw new Error("Benchmark data is incomplete or invalid.");
  }
  const dimensions = report.lattice_benchmarks.dimension_scaling;
  const norms = report.lattice_benchmarks.norm_reduction;
  if (!Array.isArray(dimensions) || !norms || !Array.isArray(norms.vector_indices) ||
      !Array.isArray(norms.original_norms) || !Array.isArray(norms.reduced_norms)) {
    throw new Error("Benchmark data is incomplete or invalid.");
  }
  if (report.rsa_benchmarks.some((row) => !validNumber(row.key_size_bits) ||
      !validNumber(row.keygen_time_ms) || !validNumber(row.encryption_time_ms) ||
      !validNumber(row.decryption_time_ms) || !validNumber(row.verification_time_ms))) {
    throw new Error("Benchmark data is incomplete or invalid.");
  }
  if (dimensions.some((row) => typeof row.dimension !== "string" ||
      !validNumber(row.execution_time_ms) || !validNumber(row.iterations))) {
    throw new Error("Benchmark data is incomplete or invalid.");
  }
  if (norms.vector_indices.length === 0 ||
      norms.vector_indices.length !== norms.original_norms.length ||
      norms.vector_indices.length !== norms.reduced_norms.length ||
      norms.original_norms.some((value) => !validNumber(value)) ||
      norms.reduced_norms.some((value) => !validNumber(value))) {
    throw new Error("Benchmark data is incomplete or invalid.");
  }
}

function renderBenchmarkCharts(report) {
  const chartIds = [
    "chart-rsa-performance",
    "chart-lll-execution",
    "chart-lll-iterations",
    "chart-norm-reduction",
  ];
  chartIds.forEach((chartId) => setChartState(chartId, "loading", "Loading benchmark data..."));

  if (typeof Chart === "undefined") {
    chartIds.forEach((chartId) => setChartState(chartId, "error", "Unable to load benchmark data: Chart.js is unavailable."));
    return;
  }

  try {
    validateChartReport(report);
    const rsa = report.rsa_benchmarks;
    const dimensions = report.lattice_benchmarks.dimension_scaling;
    const norms = report.lattice_benchmarks.norm_reduction;

    destroyChart("rsaPerformance", "chart-rsa-performance");
    benchmarkCharts.rsaPerformance = new Chart(document.getElementById("chart-rsa-performance"), {
      type: "line",
      data: {
        labels: rsa.map((row) => `${row.key_size_bits} bit`),
        datasets: [
          makeDataset("Key generation (ms)", rsa.map((row) => row.keygen_time_ms), chartPalette.blue),
          makeDataset("Encryption (ms)", rsa.map((row) => row.encryption_time_ms), chartPalette.cyan),
          makeDataset("Decryption (ms)", rsa.map((row) => row.decryption_time_ms), chartPalette.amber),
          makeDataset("Verification (ms)", rsa.map((row) => row.verification_time_ms), chartPalette.emerald),
        ],
      },
      options: chartOptions("Execution time (ms)"),
    });
    setChartState("chart-rsa-performance", "success", "");

    destroyChart("lllExecution", "chart-lll-execution");
    benchmarkCharts.lllExecution = new Chart(document.getElementById("chart-lll-execution"), {
      type: "line",
      data: {
        labels: dimensions.map((row) => row.dimension),
        datasets: [makeDataset("LLL execution time (ms)", dimensions.map((row) => row.execution_time_ms), chartPalette.rose)],
      },
      options: chartOptions("Execution time (ms)"),
    });
    setChartState("chart-lll-execution", "success", "");

    destroyChart("lllIterations", "chart-lll-iterations");
    benchmarkCharts.lllIterations = new Chart(document.getElementById("chart-lll-iterations"), {
      type: "line",
      data: {
        labels: dimensions.map((row) => row.dimension),
        datasets: [makeDataset("LLL iterations", dimensions.map((row) => row.iterations), chartPalette.cyan)],
      },
      options: chartOptions("Iteration count"),
    });
    setChartState("chart-lll-iterations", "success", "");

    destroyChart("normReduction", "chart-norm-reduction");
    benchmarkCharts.normReduction = new Chart(document.getElementById("chart-norm-reduction"), {
      type: "bar",
      data: {
        labels: norms.vector_indices,
        datasets: [
          makeDataset("Original norm", norms.original_norms, chartPalette.amber),
          makeDataset("Reduced norm", norms.reduced_norms, chartPalette.emerald),
        ],
      },
      options: chartOptions("Euclidean norm"),
    });
    setChartState("chart-norm-reduction", "success", "");
  } catch (error) {
    chartIds.forEach((chartId) => setChartState(chartId, "error", error.message || "Unable to load benchmark data."));
  }
}