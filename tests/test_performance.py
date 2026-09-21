import json

from backend.performance import benchmark


def test_full_benchmark_persists_real_report(tmp_path, monkeypatch):
    monkeypatch.setattr(benchmark, "BENCHMARK_DIR", str(tmp_path))

    report = benchmark.run_full_benchmark_suite()

    json_path = tmp_path / "benchmark_latest.json"
    csv_path = tmp_path / "rsa_benchmarks.csv"
    assert json_path.exists()
    assert csv_path.exists()

    persisted = json.loads(json_path.read_text(encoding="utf-8"))
    assert persisted["timestamp"] == report["timestamp"]
    assert len(persisted["rsa_benchmarks"]) == 3
    assert len(persisted["lwe_comparison_benchmarks"]) == 4
    assert len(persisted["comparison_benchmarks"]) == 7
    assert {row["scheme"] for row in persisted["comparison_benchmarks"]} == {"RSA-OAEP", "Educational LWE"}
    assert all(
        row["verified"] is True
        and row["public_key_bytes"] > 0
        and row["private_key_bytes"] > 0
        and row["ciphertext_bytes"] > 0
        for row in persisted["comparison_benchmarks"]
    )
    assert persisted["lattice_benchmarks"]["dimension_scaling"]
    assert all(
        isinstance(row["keygen_time_ms"], (int, float)) and row["keygen_time_ms"] >= 0
        for row in persisted["rsa_benchmarks"]
    )
    assert "key_size_bits" in csv_path.read_text(encoding="utf-8").splitlines()[0]


def test_load_latest_benchmarks_reads_persisted_report(tmp_path, monkeypatch):
    monkeypatch.setattr(benchmark, "BENCHMARK_DIR", str(tmp_path))
    expected = {"timestamp": "2026-09-19 12:30:15", "rsa_benchmarks": [], "lattice_benchmarks": {}}
    (tmp_path / "benchmark_latest.json").write_text(json.dumps(expected), encoding="utf-8")

    assert benchmark.load_latest_benchmarks() == expected