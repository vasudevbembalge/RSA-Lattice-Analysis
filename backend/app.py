"""
RSA Cryptography and Lattice-Based Analysis Framework
Flask Application Server & REST API Gateway

Strict Academic Boundaries:
- RSA Cryptography: Key generation, encryption, decryption, verification.
- Lattice Analysis: Basis construction, LLL reduction, norm telemetry.
- Private-key recovery is strictly outside the implementation scope.
"""

import os
import json
import logging
import time
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

from backend.rsa.key_generation import (
    generate_rsa_keypair,
    SUPPORTED_KEY_SIZES,
    DEFAULT_KEY_SIZE,
)
from backend.rsa.key_info import get_public_key_info, get_private_key_info
from backend.rsa.encryption import encrypt_message
from backend.rsa.decryption import decrypt_message
from backend.verification.verifier import verify_messages, verify_rsa_roundtrip
from backend.lattice.lll_interface import run_lll_reduction
from backend.lattice.lattice_operations import (
    generate_sample_matrix,
    generate_random_matrix,
)
from backend.lattice.educational_lwe import (
    DEFAULT_LATTICE_PARAMETERS,
    decrypt_lattice,
    encrypt_lattice,
    generate_lattice_keypair,
    get_message_capacity,
    run_lattice_demo,
    validate_lattice_parameters,
)
from backend.lattice.lattice_demo import run_educational_demonstration
from backend.lattice.lattice_crypto_native import native_backend_status


# Configure secure logging (never logs private keys)
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("RSA_Lattice_API")

# Paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")


def create_app() -> Flask:
    """Application factory for Flask REST backend."""
    app = Flask(
        __name__,
        static_folder=FRONTEND_DIR,
        static_url_path="",
    )

    # Enable CORS for local development and academic demos
    CORS(app)

    # Request timing middleware
    @app.before_request
    def before_request():
        request.start_time = time.perf_counter()

    @app.after_request
    def after_request(response):
        if hasattr(request, "start_time"):
            duration = (time.perf_counter() - request.start_time) * 1000.0
            # Log route access safely without request body
            logger.info("%s %s %s (%.2f ms)", request.method, request.path, response.status_code, duration)
        return response

    # Global Error Handlers
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({
            "status": "error",
            "error_code": "BAD_REQUEST",
            "message": str(error.description if hasattr(error, "description") else error),
        }), 400

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            "status": "error",
            "error_code": "NOT_FOUND",
            "message": "The requested resource was not found on this server.",
        }), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        return jsonify({
            "status": "error",
            "error_code": "METHOD_NOT_ALLOWED",
            "message": "HTTP method not allowed for this endpoint.",
        }), 405

    @app.errorhandler(500)
    def internal_server_error(error):
        logger.error("Internal Server Error: %s", error)
        return jsonify({
            "status": "error",
            "error_code": "INTERNAL_SERVER_ERROR",
            "message": "An unexpected internal server error occurred.",
        }), 500

    # Static UI Routes
    @app.route("/")
    def serve_index():
        index_file = os.path.join(FRONTEND_DIR, "index.html")
        if os.path.exists(index_file):
            return send_from_directory(FRONTEND_DIR, "index.html")
        return jsonify({
            "message": "RSA Cryptography and Lattice-Based Analysis Framework API",
            "status": "running",
            "frontend": "Frontend files will be served from /frontend",
        })

    # System Status & Health Check
    @app.route("/api/status", methods=["GET"])
    def get_status():
        """Returns the health status and engine readiness of the framework."""
        dll_path = os.path.join(BASE_DIR, "c_lll", "bin", "lll.dll")
        c_engine_ready = os.path.exists(dll_path)
        native_lwe_status = native_backend_status()

        return jsonify({
            "status": "operational",
            "system_title": "RSA Cryptography and Lattice-Based Analysis Framework",
            "version": "1.0.0",
            "engines": {
                "rsa_cryptography": {
                    "backend": "cryptography (OpenSSL)",
                    "status": "ready",
                    "supported_key_sizes": [1024, 2048, 3072, 4096],
                    "default_padding": "RSA-OAEP with SHA-256",
                },
                "c_lll_engine": {
                    "status": "ready" if c_engine_ready else "not_compiled",
                    "dll_location": dll_path if c_engine_ready else None,
                    "max_dimension": 64,
                    "max_integer_entry": 2147483647,
                    "default_delta": 0.75,
                },
                "native_lwe_engine": {
                    "status": "ready" if native_lwe_status["available"] else "unavailable",
                    "library": "c_lattice_crypto/bin/lattice_crypto.dll",
                    "reason": native_lwe_status["reason"],
                },
            },
            "scope_notice": (
                "LLL reduction is demonstrated as a lattice-analysis technique. "
                "Private-key recovery is outside the scope of this implementation."
            ),
        }), 200

    # 1. RSA Key Generation
    @app.route("/api/rsa/generate", methods=["POST"])
    def api_rsa_generate():
        data = request.get_json(silent=True) or {}
        key_size = data.get("key_size", DEFAULT_KEY_SIZE)

        try:
            key_size = int(key_size)
        except (ValueError, TypeError):
            return jsonify({"status": "error", "message": "Key size must be an integer."}), 400

        try:
            result = generate_rsa_keypair(key_size)
            pub_info = get_public_key_info(result["public_key_pem"])
            result["public_key_info"] = pub_info
            return jsonify(result), 200
        except ValueError as exc:
            return jsonify({"status": "error", "message": str(exc)}), 400

    # 2. RSA Key Info Extraction
    @app.route("/api/rsa/info", methods=["POST"])
    def api_rsa_info():
        data = request.get_json(silent=True) or {}
        public_pem = data.get("public_key_pem")
        private_pem = data.get("private_key_pem")

        if not public_pem and not private_pem:
            return jsonify({"status": "error", "message": "Provide either public_key_pem or private_key_pem."}), 400

        try:
            info = {}
            if public_pem:
                info["public_key"] = get_public_key_info(public_pem)
            if private_pem:
                info["private_key"] = get_private_key_info(private_pem)
            return jsonify({"status": "success", "info": info}), 200
        except ValueError as exc:
            return jsonify({"status": "error", "message": str(exc)}), 400

    # 3. RSA Encryption
    @app.route("/api/rsa/encrypt", methods=["POST"])
    def api_rsa_encrypt():
        data = request.get_json(silent=True) or {}
        plaintext = data.get("plaintext")
        public_key_pem = data.get("public_key_pem")

        if plaintext is None:
            return jsonify({"status": "error", "message": "Missing 'plaintext' in request."}), 400
        if not public_key_pem:
            return jsonify({"status": "error", "message": "Missing 'public_key_pem' in request."}), 400

        try:
            result = encrypt_message(plaintext, public_key_pem)
            return jsonify(result), 200
        except ValueError as exc:
            return jsonify({"status": "error", "message": str(exc)}), 400

    # 4. RSA Decryption
    @app.route("/api/rsa/decrypt", methods=["POST"])
    def api_rsa_decrypt():
        data = request.get_json(silent=True) or {}
        ciphertext_b64 = data.get("ciphertext_base64")
        private_key_pem = data.get("private_key_pem")

        if not ciphertext_b64:
            return jsonify({"status": "error", "message": "Missing 'ciphertext_base64' in request."}), 400
        if not private_key_pem:
            return jsonify({"status": "error", "message": "Missing 'private_key_pem' in request."}), 400

        try:
            result = decrypt_message(ciphertext_b64, private_key_pem)
            return jsonify(result), 200
        except ValueError as exc:
            return jsonify({"status": "error", "message": str(exc)}), 400

    # 5. RSA Verification
    @app.route("/api/rsa/verify", methods=["POST"])
    def api_rsa_verify():
        data = request.get_json(silent=True) or {}

        # Roundtrip verification mode
        if "public_key_pem" in data and "private_key_pem" in data and "original_message" in data:
            result = verify_rsa_roundtrip(
                data["original_message"],
                data["public_key_pem"],
                data["private_key_pem"],
            )
            return jsonify(result), 200

        # Direct message comparison mode
        if "original_message" in data and "decrypted_message" in data:
            result = verify_messages(data["original_message"], data["decrypted_message"])
            return jsonify(result), 200

        return jsonify({
            "status": "error",
            "message": "Invalid verification payload. Provide ('original_message', 'public_key_pem', 'private_key_pem') or ('original_message', 'decrypted_message').",
        }), 400

    # 6. Lattice LLL Reduction
    @app.route("/api/lattice/reduce", methods=["POST"])
    def api_lattice_reduce():
        data = request.get_json(silent=True) or {}
        matrix = data.get("matrix")
        delta = data.get("delta", 0.75)

        if matrix is None:
            return jsonify({"status": "error", "message": "Missing 'matrix' in request."}), 400

        try:
            delta = float(delta)
        except (ValueError, TypeError):
            return jsonify({"status": "error", "message": "Delta must be a floating point number."}), 400

        try:
            result = run_lll_reduction(matrix, delta)
            return jsonify(result), 200
        except ValueError as exc:
            return jsonify({"status": "error", "message": str(exc)}), 400

    # 7. Educational n-dimensional lattice key generation
    @app.route("/api/lattice/keygen", methods=["POST"])
    def api_lattice_keygen():
        data = request.get_json(silent=True) or {}

        try:
            dimension = int(data.get("dimension", DEFAULT_LATTICE_PARAMETERS["dimension"]))
            parameters = data.get("parameters") or {}
            parameters = dict(parameters)
            parameters["dimension"] = dimension
            validated = validate_lattice_parameters(parameters)
            started = time.perf_counter()
            public_key, private_key = generate_lattice_keypair(dimension, validated)
            key_generation_time_ms = round((time.perf_counter() - started) * 1000.0, 3)
            public_key["backend_used"] = "Python reference"
            private_key["backend_used"] = "Python reference"
            key_id = f"lattice_key_{len(app.config.setdefault('lattice_key_store', {})) + 1}"
            app.config["lattice_key_store"][key_id] = private_key

            public_view = {
                "dimension": public_key["dimension"],
                "modulus": public_key["modulus"],
                "message_modulus": public_key["message_modulus"],
                "noise_bound": public_key["noise_bound"],
                "samples": public_key["samples"],
                "matrix_A": public_key["matrix_A"],
                "vector_b": public_key["vector_b"],
                "correctness": public_key["correctness"],
                "backend_used": public_key["backend_used"],
                "description": public_key["description"],
            }
            return jsonify({
                "status": "success",
                "key_id": key_id,
                "public_key": public_view,
                "parameters": validated,
                "message_capacity": get_message_capacity(validated),
                "backend_requested": "python",
                "backend_used": "Python reference",
                "fallback": False,
                "key_generation_time_ms": key_generation_time_ms,
                "key_dimensions": {
                    "public_matrix": [public_key["samples"], public_key["dimension"]],
                    "public_vector": [public_key["samples"]],
                    "private_secret": [private_key["dimension"]],
                },
                "representation_sizes": {
                    "public_key_json_bytes": len(json.dumps(public_view, separators=(",", ":")).encode("utf-8")),
                    "private_key_json_bytes": len(json.dumps(private_key, separators=(",", ":")).encode("utf-8")),
                },
                "disclaimer": "This is a small educational lattice construction and not production cryptography.",
            }), 200
        except (TypeError, ValueError, RuntimeError) as exc:
            return jsonify({"status": "error", "message": str(exc)}), 400

    # 8. Educational lattice encryption
    @app.route("/api/lattice/encrypt", methods=["POST"])
    def api_lattice_encrypt():
        data = request.get_json(silent=True) or {}
        plaintext = data.get("plaintext")
        public_key = data.get("public_key")

        if plaintext is None:
            return jsonify({"status": "error", "message": "Missing 'plaintext' in request."}), 400
        if not public_key:
            return jsonify({"status": "error", "message": "Missing 'public_key' in request."}), 400

        try:
            started = time.perf_counter()
            result = encrypt_lattice(str(plaintext), public_key)
            result["encryption_time_ms"] = round((time.perf_counter() - started) * 1000.0, 3)
            result["backend_used"] = public_key.get("backend_used", "Python reference")
            result["ciphertext_bytes_length"] = len(json.dumps(result, separators=(",", ":")).encode("utf-8"))
            return jsonify(result), 200
        except (TypeError, ValueError) as exc:
            return jsonify({"status": "error", "message": str(exc)}), 400

    # 9. Educational lattice decryption
    @app.route("/api/lattice/decrypt", methods=["POST"])
    def api_lattice_decrypt():
        data = request.get_json(silent=True) or {}
        ciphertext = data.get("ciphertext")
        private_key = data.get("private_key")
        key_id = data.get("key_id")

        if ciphertext is None:
            return jsonify({"status": "error", "message": "Missing 'ciphertext' in request."}), 400

        if private_key is None and key_id:
            private_key = app.config.get("lattice_key_store", {}).get(key_id)

        try:
            if private_key is None:
                return jsonify({"status": "error", "message": "Missing private key or key_id for decryption."}), 400
            started = time.perf_counter()
            result = decrypt_lattice(ciphertext, private_key)
            original_message = data.get("original_message")
            verification = verify_messages(original_message, result) if original_message is not None else None
            return jsonify({
                "status": "success",
                "plaintext": result,
                "recovered_encoded_message": list(result.encode("utf-8")),
                "decryption_time_ms": round((time.perf_counter() - started) * 1000.0, 3),
                "plaintext_bytes_length": len(result.encode("utf-8")),
                "backend_used": private_key.get("backend_used", "Python reference"),
                "verification": verification,
            }), 200
        except (TypeError, ValueError, UnicodeDecodeError) as exc:
            return jsonify({"status": "error", "message": str(exc)}), 400

    # 10. Educational lattice verification
    @app.route("/api/lattice/verify", methods=["POST"])
    def api_lattice_verify():
        data = request.get_json(silent=True) or {}
        if "original_message" not in data or "decrypted_message" not in data:
            return jsonify({
                "status": "error",
                "message": "Provide 'original_message' and 'decrypted_message'.",
            }), 400
        result = verify_messages(data["original_message"], data["decrypted_message"])
        return jsonify({
            **result,
            "algorithm": "Educational LWE",
            "disclaimer": "Verification confirms a message round trip; it does not establish production security.",
        }), 200

    # 10. Educational lattice demo
    @app.route("/api/lattice/demo", methods=["POST"])
    def api_lattice_demo():
        data = request.get_json(silent=True) or {}
        message = data.get("message", "HELLO LWE")
        backend = data.get("backend", "both")
        try:
            dimension = int(data.get("dimension", 3))
            result = run_educational_demonstration(
                str(message),
                dimension,
                str(backend),
                backend_status=native_backend_status(),
            )
            return jsonify(result), 200
        except (TypeError, ValueError, RuntimeError) as exc:
            return jsonify({"status": "error", "message": str(exc)}), 400

    # 11. Preset Lattice Samples
    @app.route("/api/lattice/samples", methods=["GET"])
    def api_lattice_samples():
        sample_types = ["textbook_3x3", "skewed_2x2", "dimension_4x4", "modular_relation_basis", "rsa_analysis_basis"]
        samples = {st: generate_sample_matrix(st) for st in sample_types}
        return jsonify({
            "status": "success",
            "samples": samples,
            "disclaimer": "LLL reduction is demonstrated as a lattice-analysis technique. Private-key recovery is outside the scope of this implementation.",
        }), 200

    # 12. Lattice Random Matrix Generator
    @app.route("/api/lattice/random", methods=["POST"])
    def api_lattice_random():
        data = request.get_json(silent=True) or {}
        try:
            rows = int(data.get("rows", 3))
            cols = int(data.get("cols", 3))
            mat = generate_random_matrix(rows, cols)
            return jsonify({"status": "success", "matrix": mat, "rows": rows, "cols": cols}), 200
        except ValueError as exc:
            return jsonify({"status": "error", "message": str(exc)}), 400


    return app


app = create_app()

if __name__ == "__main__":
    logger.info("Starting RSA & Lattice Analysis Server on http://localhost:5000 ...")
    app.run(host="127.0.0.1", port=5000, debug=False)