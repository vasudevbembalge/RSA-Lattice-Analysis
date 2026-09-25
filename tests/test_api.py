import pytest
import json
import backend.app as app_module
from backend.app import create_app


@pytest.fixture(scope="module")
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_api_status(client):
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "operational"
    assert data["engines"]["rsa_cryptography"]["status"] == "ready"
    assert data["engines"]["c_lll_engine"]["status"] == "ready"
    assert "Private-key recovery is outside the scope" in data["scope_notice"]


def test_api_rsa_generate_default(client):
    res = client.post("/api/rsa/generate", json={})
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "success"
    assert data["key_size"] == 2048
    assert "BEGIN PUBLIC KEY" in data["public_key_pem"]
    assert "BEGIN PRIVATE KEY" in data["private_key_pem"]
    assert data["public_key_info"]["algorithm"] == "RSA"


def test_api_rsa_generate_custom_size(client):
    res = client.post("/api/rsa/generate", json={"key_size": 1024})
    assert res.status_code == 200
    data = res.get_json()
    assert data["key_size"] == 1024


def test_api_rsa_generate_invalid_size(client):
    res = client.post("/api/rsa/generate", json={"key_size": 512})
    assert res.status_code == 400
    data = res.get_json()
    assert data["status"] == "error"


def test_api_rsa_generate_rejects_malformed_key_size(client):
    res = client.post("/api/rsa/generate", json={"key_size": "not-an-integer"})
    assert res.status_code == 400
    assert res.get_json()["status"] == "error"


def test_api_rsa_info(client):
    keygen = client.post("/api/rsa/generate", json={"key_size": 1024}).get_json()
    res = client.post("/api/rsa/info", json={
        "public_key_pem": keygen["public_key_pem"],
        "private_key_pem": keygen["private_key_pem"],
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["info"]["public_key"]["key_size"] == 1024
    assert data["info"]["private_key"]["key_size"] == 1024


def test_api_rsa_info_rejects_missing_and_malformed_keys(client):
    missing = client.post("/api/rsa/info", json={})
    assert missing.status_code == 400

    malformed = client.post("/api/rsa/info", json={"public_key_pem": "not-a-key"})
    assert malformed.status_code == 400


def test_api_rsa_unicode_and_oaep_boundary(client):
    keygen = client.post("/api/rsa/generate", json={"key_size": 1024}).get_json()
    message = "é" * 30  # 60 UTF-8 bytes, within the 62-byte OAEP limit.
    encrypted = client.post("/api/rsa/encrypt", json={
        "plaintext": message,
        "public_key_pem": keygen["public_key_pem"],
    })
    assert encrypted.status_code == 200

    decrypted = client.post("/api/rsa/decrypt", json={
        "ciphertext_base64": encrypted.get_json()["ciphertext_base64"],
        "private_key_pem": keygen["private_key_pem"],
    })
    assert decrypted.status_code == 200
    assert decrypted.get_json()["decrypted_plaintext"] == message

    oversized = client.post("/api/rsa/encrypt", json={
        "plaintext": "é" * 32,
        "public_key_pem": keygen["public_key_pem"],
    })
    assert oversized.status_code == 400


def test_api_rsa_encrypt_decrypt_roundtrip(client):
    # 1. Keygen
    keygen = client.post("/api/rsa/generate", json={"key_size": 1024}).get_json()
    pub_pem = keygen["public_key_pem"]
    priv_pem = keygen["private_key_pem"]
    msg = "Test academic message via REST API"

    # 2. Encrypt
    enc_res = client.post("/api/rsa/encrypt", json={
        "plaintext": msg,
        "public_key_pem": pub_pem,
    })
    assert enc_res.status_code == 200
    enc_data = enc_res.get_json()
    assert enc_data["status"] == "success"
    assert "ciphertext_base64" in enc_data

    # 3. Decrypt
    dec_res = client.post("/api/rsa/decrypt", json={
        "ciphertext_base64": enc_data["ciphertext_base64"],
        "private_key_pem": priv_pem,
    })
    assert dec_res.status_code == 200
    dec_data = dec_res.get_json()
    assert dec_data["status"] == "success"
    assert dec_data["decrypted_plaintext"] == msg


def test_api_rsa_encrypt_empty_message(client):
    keygen = client.post("/api/rsa/generate", json={"key_size": 1024}).get_json()
    res = client.post("/api/rsa/encrypt", json={
        "plaintext": "",
        "public_key_pem": keygen["public_key_pem"],
    })
    assert res.status_code == 400


def test_api_rsa_decrypt_corrupted(client):
    keygen = client.post("/api/rsa/generate", json={"key_size": 1024}).get_json()
    res = client.post("/api/rsa/decrypt", json={
        "ciphertext_base64": "AAAABBBBCCCC",
        "private_key_pem": keygen["private_key_pem"],
    })
    assert res.status_code == 400


def test_api_rsa_decrypt_rejects_missing_and_malformed_private_key(client):
    missing = client.post("/api/rsa/decrypt", json={})
    assert missing.status_code == 400

    malformed = client.post("/api/rsa/decrypt", json={
        "ciphertext_base64": "AAAA",
        "private_key_pem": "not-a-key",
    })
    assert malformed.status_code == 400


def test_api_rsa_verify_roundtrip(client):
    keygen = client.post("/api/rsa/generate", json={"key_size": 1024}).get_json()
    res = client.post("/api/rsa/verify", json={
        "original_message": "Verify API roundtrip",
        "public_key_pem": keygen["public_key_pem"],
        "private_key_pem": keygen["private_key_pem"],
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "VERIFICATION PASSED"
    assert data["passed"] is True


def test_api_rsa_verify_direct_comparison(client):
    res_pass = client.post("/api/rsa/verify", json={
        "original_message": "Equal",
        "decrypted_message": "Equal",
    })
    assert res_pass.status_code == 200
    assert res_pass.get_json()["status"] == "VERIFICATION PASSED"

    res_fail = client.post("/api/rsa/verify", json={
        "original_message": "Equal",
        "decrypted_message": "Not Equal",
    })
    assert res_fail.status_code == 200
    assert res_fail.get_json()["status"] == "VERIFICATION FAILED"


def test_api_lattice_reduce_valid(client):
    mat = [
        [105, 821, 404],
        [31, 57, 91],
        [12, 34, 77],
    ]
    res = client.post("/api/lattice/reduce", json={"matrix": mat, "delta": 0.75})
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "success"
    assert data["reduction_status"] == "LLL REDUCTION COMPLETED"
    assert data["reduced_basis"] == [
        [-19, -23, -14],
        [-26, -12, 49],
        [-292, 282, -93],
    ]
    assert "Private-key recovery is outside the scope" in data["disclaimer"]


def test_api_lattice_reduce_invalid_input(client):
    # Non-integer matrix
    res = client.post("/api/lattice/reduce", json={"matrix": [[1, 2.5], [3, 4]]})
    assert res.status_code == 400

    # Singular matrix
    res_sing = client.post("/api/lattice/reduce", json={"matrix": [[1, 2], [2, 4]]})
    assert res_sing.status_code == 400


def test_api_lattice_reduce_rejects_missing_and_boundary_invalid_dimensions(client):
    missing = client.post("/api/lattice/reduce", json={})
    assert missing.status_code == 400

    invalid_dimensions = client.post("/api/lattice/reduce", json={
        "matrix": [[1, 2, 3], [4, 5, 6], [7, 8, 9], [10, 11, 12]],
    })
    assert invalid_dimensions.status_code == 400

    malformed_delta = client.post("/api/lattice/reduce", json={
        "matrix": [[1, 0], [0, 1]],
        "delta": "not-a-number",
    })
    assert malformed_delta.status_code == 400


def test_api_lattice_samples(client):
    res = client.get("/api/lattice/samples")
    assert res.status_code == 200
    data = res.get_json()
    assert "textbook_3x3" in data["samples"]
    assert "rsa_analysis_basis" in data["samples"]


def test_api_lattice_random(client):
    res = client.post("/api/lattice/random", json={"rows": 3, "cols": 3})
    assert res.status_code == 200
    data = res.get_json()
    assert len(data["matrix"]) == 3
    assert len(data["matrix"][0]) == 3


def test_api_lattice_random_rejects_invalid_dimensions(client):
    res = client.post("/api/lattice/random", json={"rows": 3, "cols": 2})
    assert res.status_code == 400


def test_api_lwe_roundtrip_returns_structured_metadata(client):
    keygen = client.post("/api/lattice/keygen", json={
        "dimension": 4,
        "parameters": {
            "modulus": 1000003,
            "message_modulus": 256,
            "noise_bound": 2,
            "samples": 8,
        },
    })
    assert keygen.status_code == 200
    key_data = keygen.get_json()
    assert key_data["parameters"]["correctness_guaranteed"] is True
    assert key_data["message_capacity"]["maximum_plaintext_bytes"] is None
    assert key_data["message_capacity"]["capacity_type"] == "unbounded_by_lwe_parameters"
    assert key_data["key_generation_time_ms"] >= 0
    assert key_data["backend_used"] == "Python reference"
    assert key_data["key_dimensions"]["public_matrix"] == [8, 4]
    assert key_data["representation_sizes"]["public_key_json_bytes"] > 0

    encrypted = client.post("/api/lattice/encrypt", json={
        "plaintext": "API LWE\x00",
        "public_key": key_data["public_key"],
    })
    assert encrypted.status_code == 200
    ciphertext = encrypted.get_json()
    assert ciphertext["encryption_time_ms"] >= 0
    assert ciphertext["ciphertext_bytes_length"] > 0
    assert ciphertext["message_length_bytes"] == len("API LWE\x00".encode("utf-8"))

    decrypted = client.post("/api/lattice/decrypt", json={
        "ciphertext": ciphertext,
        "key_id": key_data["key_id"],
        "original_message": "API LWE\x00",
    })
    assert decrypted.status_code == 200
    plaintext = decrypted.get_json()
    assert plaintext["plaintext"] == "API LWE\x00"
    assert plaintext["decryption_time_ms"] >= 0
    assert plaintext["backend_used"] == "Python reference"
    assert plaintext["verification"]["passed"] is True

    verified = client.post("/api/lattice/verify", json={
        "original_message": "API LWE\x00",
        "decrypted_message": plaintext["plaintext"],
    })
    assert verified.status_code == 200
    assert verified.get_json()["passed"] is True
    assert verified.get_json()["algorithm"] == "Educational LWE"


def test_api_lwe_rejects_malformed_requests(client):
    assert client.post("/api/lattice/keygen", json={"dimension": "bad"}).status_code == 400
    assert client.post("/api/lattice/encrypt", json={"plaintext": "x"}).status_code == 400
    assert client.post("/api/lattice/decrypt", json={"ciphertext": {}}).status_code == 400
    assert client.post("/api/lattice/verify", json={}).status_code == 400


def test_api_lattice_demo_returns_complete_educational_flow(client):
    res = client.post("/api/lattice/demo", json={"message": "API DEMO", "dimension": 3})
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "PASS"
    assert data["lwe"]["status"] == "PASS"
    assert data["lll"]["reduction_status"] == "LLL REDUCTION COMPLETED"
    assert data["lattice_visualization"]["dimension"] == 2
    assert data["component_separation"]["lll"].endswith("lll.dll.")


def test_api_lattice_demo_supports_dimension_four(client):
    res = client.post("/api/lattice/demo", json={"message": "API DEMO", "dimension": 4})
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "PASS"
    assert data["lwe"]["parameters"]["dimension"] == 4


def test_api_lattice_demo_native_request_falls_back_to_python(client, monkeypatch):
    monkeypatch.setattr(
        app_module,
        "native_backend_status",
        lambda: {"available": False, "reason": "Windows Code Integrity blocked the native DLL."},
    )
    res = client.post("/api/lattice/demo", json={
        "message": "HELLO LATTICE",
        "dimension": 3,
        "backend": "native_c",
    })

    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "PASS"
    assert data["lwe"]["requested_backend"] == "native_c"
    assert data["lwe"]["actual_backend"] == "python"
    assert data["lwe"]["fallback"] is True
    assert data["lwe"]["backends"][0]["backend"] == "Python reference"
    assert data["lwe"]["backends"][0]["recovered_plaintext"] == "HELLO LATTICE"


def test_api_global_not_found_and_method_handlers(client):
    not_found = client.get("/api/does-not-exist")
    assert not_found.status_code == 404
    assert not_found.get_json()["error_code"] == "NOT_FOUND"

    method_not_allowed = client.post("/api/status")
    assert method_not_allowed.status_code == 405
    assert method_not_allowed.get_json()["error_code"] == "METHOD_NOT_ALLOWED"