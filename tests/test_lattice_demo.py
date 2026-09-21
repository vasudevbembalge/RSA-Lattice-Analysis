from backend.lattice.lattice_demo import run_educational_demonstration, run_lwe_demo


def test_lwe_demo_runs_both_backends():
    result = run_lwe_demo("HELLO LWE", dimension=3)

    assert result["status"] == "PASS"
    assert result["equations"]["encryption"] == "u = A^T*r + e1 mod q; v = b^T*r + floor(q/p)*symbol + e2 mod q"
    assert {backend["status"] for backend in result["backends"]} == {"PASS"}
    assert {backend["recovered_plaintext"] for backend in result["backends"]} == {"HELLO LWE"}
    assert result["actual_backend"] == ("both" if result["native_backend_available"] else "python")


def test_complete_demo_contains_separate_lattice_and_lll_sections():
    result = run_educational_demonstration("DEMO", dimension=2)

    assert result["status"] == "PASS"
    assert result["lattice_visualization"]["dimension"] == 2
    assert len(result["lattice_visualization"]["points"]) == 49
    assert result["lll"]["reduction_status"] == "LLL REDUCTION COMPLETED"
    assert result["lll"]["iterations"] >= 0
    assert "does not encrypt or decrypt" in result["lll"]["relationship"]
    assert result["performance"]["benchmark_report"]["benchmark"] == "Educational LWE Python vs native C"


def test_demo_supports_dimension_four_with_corrected_blockwise_validation():
    result = run_lwe_demo("DEMO", dimension=4, backend="python")

    assert result["status"] == "PASS"
    assert result["parameters"]["dimension"] == 4
    assert result["backends"][0]["status"] == "PASS"


def test_native_request_falls_back_to_python_when_native_is_unavailable(monkeypatch):
    monkeypatch.setattr(
        "backend.lattice.lattice_demo.native_backend_status",
        lambda: {"available": False, "reason": "Windows Code Integrity blocked the native DLL."},
    )
    result = run_lwe_demo("HELLO LATTICE", dimension=3, backend="native_c")

    assert result["status"] == "PASS"
    assert result["requested_backend"] == "native_c"
    assert result["actual_backend"] == "python"
    assert result["fallback"] is True
    assert result["backends"][0]["backend"] == "Python reference"
    assert result["backends"][0]["recovered_plaintext"] == "HELLO LATTICE"
