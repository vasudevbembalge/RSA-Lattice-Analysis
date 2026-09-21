# RSA versus LWE Educational Comparison

An academic and educational software framework demonstrating RSA-OAEP encryption/decryption alongside a mathematically defined educational LWE-based lattice encryption/decryption construction, with LLL retained as a separate lattice-analysis tool.

## Project Scope and Disclaimers
- **Educational Scope**: This software is designed for academic demonstration and laboratory analysis.
- **Clear Separation**: RSA cryptography and lattice-based reduction are implemented as distinct, independent modules.
- **Strict Cryptanalytic Disclaimer**: *LLL reduction is demonstrated strictly as a lattice-analysis technique. Private-key recovery and arbitrary RSA factorization are outside the scope of this implementation.*

## System Features
1. **RSA Cryptography**:
   - Industry-standard key generation (1024, 2048, 3072, 4096-bit).
   - Public-key metadata inspection (algorithm, bit length, public exponent, PEM format).
   - RSA-OAEP encryption with SHA-256 digest and Base64 ciphertext representation.
   - Robust RSA-OAEP decryption with error handling.
   - Cryptographic verification engine validating plaintext round-trip integrity.
2. **LWE-Based Lattice Encryption**:
   - Configurable n-dimensional educational LWE construction.
   - Public/private key generation, byte encoding, encryption, decryption, and verification.
   - Derived bounded-noise correctness information and real operation measurements.
3. **Lattice Analysis & LLL Engine**:
   - Interactive matrix basis builder and sample lattice generators.
   - Native C computational core (c_lll) implementing Gram-Schmidt orthogonalization, size reduction, Lovász condition checking ($\delta=0.75$), and basis swapping.
   - Strict numerical bounds checking in C to prevent integer overflow.
   - Seamless Python-C integration using ctypes.
4. **Educational LWE Demonstration**:
   - Python educational LWE reference implementation.
   - Separate native C LWE backend (`lattice_crypto.dll`) accessed through a dedicated ctypes wrapper.
   - Python/native parity tests, dimensional validation, benchmark reporting, and CLI/API demonstration.

### LWE Plaintext Capacity

The educational LWE path encodes UTF-8 bytes independently and groups them into blocks of `n` symbols. Each ciphertext records the exact UTF-8 byte length, so final-block padding does not lose message boundaries. Additional blocks can be generated, so the construction has no fixed cryptographic plaintext-size maximum determined by `n`, `p`, or `q`; practical limits are transport and system-resource limits. The API reports `capacity_type = unbounded_by_lwe_parameters` instead of inventing a byte limit. Lossless byte encoding requires `p >= 256`.
5. **Performance Benchmarking & Visualization**:
   - Real empirical RSA-versus-LWE timing and serialized-size measurements across key sizes and dimensions.
   - Responsive Chart.js visualization for operational latency and vector norm reduction.

## Architecture
- **Backend**: Python 3.14, Flask, and Flask-CORS.
- **Crypto Engine**: Python `cryptography` library with the OpenSSL backend.
- **Lattice Engine**: Native C DLL (`c_lll/bin/lll.dll`) accessed through `ctypes`.
- **Educational LWE**: Python reference plus separate native C DLL (`c_lattice_crypto/bin/lattice_crypto.dll`).
- **Demonstration**: `backend/lattice/lattice_demo.py` keeps LWE, lattice visualization, LLL, and performance comparison separate.
- **Frontend**: Static HTML/CSS/ES6 JavaScript single-page interface with Chart.js loaded from CDN.
- **Persistence**: JSON and CSV benchmark reports under `data/benchmarks/`.

## Setup

From the project root on Windows:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

The repository includes compiled Windows LLL and educational LWE libraries at `c_lll/bin/lll.dll` and `c_lattice_crypto/bin/lattice_crypto.dll`. Rebuild them with their respective batch files from a compatible MSVC build environment.

## Run The Application

Start Flask from the project root so package imports resolve correctly:

```powershell
.\.venv\Scripts\python.exe -m flask --app backend.app run --host 127.0.0.1 --port 5000
```

Open `http://127.0.0.1:5000/` in a browser.

## REST API

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/status` | Health and engine readiness |
| `POST` | `/api/rsa/generate` | Generate an RSA key pair |
| `POST` | `/api/rsa/info` | Inspect RSA public metadata |
| `POST` | `/api/rsa/encrypt` | RSA-OAEP/SHA-256 encryption |
| `POST` | `/api/rsa/decrypt` | RSA-OAEP/SHA-256 decryption |
| `POST` | `/api/rsa/verify` | Compare or verify a round trip |
| `POST` | `/api/lattice/reduce` | Run native C LLL reduction |
| `POST` | `/api/lattice/demo` | Run the complete educational LWE/lattice/LLL demonstration |
| `GET` | `/api/lattice/samples` | Retrieve educational lattice presets |
| `POST` | `/api/lattice/random` | Generate a random integer matrix |
| `GET` | `/api/performance` | Read benchmark configuration metadata |
| `POST` | `/api/performance/run` | Execute and persist a real benchmark suite |
| `GET` | `/api/performance/results` | Load the latest persisted benchmark suite |

Private key PEM is used for the local educational workflow, but private RSA factors (`p`, `q`, and `d`) are not exposed by metadata endpoints.

### Demonstration UI Flow

The `Lattice-Based Public-Key Encryption` page (sidebar entry for `#tab-lwe-demo`, also linked from the dashboard) presents the educational LWE construction as an explicit lattice-based public-key encryption sequence:

1. **1. Generate Key Pair** — `POST /api/lattice/demo`, displaying the public parameters `A` and `q`, the secret key `s`, the error `e`, and the public component `b = A s + e (mod q)` as Public Key `(A, b)`.
2. **2. Encrypt with Public Key** — `POST /api/lattice/encrypt` using `(A, b)` only, displaying the encryption inputs (plaintext `m`, message encoding, public key `(A, b)`, randomness `r`, encryption noise `e1`/`e2`), the equations `u = A^T r + e1 (mod q)` and `v = b^T r + floor(q/p) * symbol + e2 (mod q)`, and the resulting Ciphertext `(u, v)` with a `✓ ENCRYPTION SUCCESSFUL` check.
3. **3. Decrypt with Secret Key** — `POST /api/lattice/decrypt` using `s` and that ciphertext, displaying `t = v - u^T s mod q` and the `symbol = round(t / floor(q/p)) mod p` decode step (both returned by the backend), the recovered plaintext, and `✓ DECRYPTION SUCCESSFUL`.

Steps 2 and 3 stay hidden until the previous step completes, so the order `KEY GENERATION -> PUBLIC KEY (A, b) -> ENCRYPT -> CIPHERTEXT (u, v) -> DECRYPT -> RECOVERED MESSAGE` is visible, and the ciphertext on screen is the value produced by the encryption call rather than the demonstration payload. The suggested walkthrough message is `HELLO LATTICE`.

The encryption card also states why the construction is lattice-based ("LWE encryption is based on noisy modular linear equations. These equations have an underlying lattice-based mathematical structure.") and shows the chain `A, b -> LWE public key -> public-key encryption -> (u, v) -> secret key s -> decryption`. The randomness `r` and the encryption noise `e1`/`e2` are generated inside the backend and are not returned by the endpoint, so no values are shown for them.

All matrix and vector values — `A`, `b`, `s`, `e`, the ciphertext `u` and `v`, and both LLL bases — are rendered by the reusable presentation component in `frontend/js/matrix_display.js` with aligned columns, bracketing, and horizontal/vertical scrolling instead of raw JSON. No cryptographic calculation is performed in JavaScript. The `LATTICE REPRESENTATION` card shows the chain from `LWE public-key encryption` through `noisy modular relations` to the conceptual `lattice interpretation`, and is explicitly distinguished from the numerical modular arithmetic of steps 03 and 04. `LLL LATTICE REDUCTION` remains a separate basis-reduction algorithm: it neither encrypts nor decrypts the message and is not required by this LWE implementation.

## Benchmarking And Charts

`POST /api/performance/run` measures actual RSA key generation, encryption, decryption, and verification timings, plus native C LLL execution time, iterations, swaps, and norm comparisons. It writes:

- `data/benchmarks/benchmark_latest.json`
- `data/benchmarks/rsa_benchmarks.csv`

The frontend Performance section can run a new benchmark or load the latest persisted result. It renders four Chart.js visualizations from the same returned report used by the tables:

1. RSA performance versus key size
2. LLL execution time versus lattice dimension
3. LLL iterations versus lattice dimension
4. Vector norms before and after LLL reduction

These measurements describe computational performance only. They do not measure RSA private-key recovery or cryptanalytic success.

## Testing

Run the Python suite:

```powershell
.\.venv\Scripts\python.exe -m pytest tests -v
```

The native LWE tests run when Windows permits loading `c_lattice_crypto/bin/lattice_crypto.dll`. If Windows Application Control blocks that unsigned educational DLL, the native tests are skipped with an explicit reason; the Python LWE, RSA, API, benchmark, and LLL tests continue to run.

The verified Python suite currently contains **104 passing tests**. The educational demonstration can also be run directly:

```powershell
.\.venv\Scripts\python.exe -m backend.lattice.lattice_demo
```

Run the native C LLL regression executable separately:

```powershell
.\c_lll\bin\test_lll.exe
```

The native suite currently reports **7 / 7 passed**. JavaScript modules can be syntax-checked with:

```powershell
node --check frontend\js\app.js
node --check frontend\js\charts.js
node --check frontend\js\rsa.js
node --check frontend\js\lattice.js
node --check frontend\js\matrix_display.js
node --check frontend\js\lwe_demo.js
```

## Research Scope And Limitations

- This project demonstrates RSA operations and lattice basis reduction for education and experimentation.
- LLL is presented as a lattice-analysis technique, not as a general RSA-breaking method.
- The application does not recover arbitrary real-world RSA private keys.
- The RSA benchmark measures operational cryptographic latency.
- The LLL benchmark measures native reduction performance and vector-norm changes.
- Benchmark timing does not imply cryptanalytic success.
- The native LLL implementation is bounded to dimensions and integer ranges documented in `c_lll/include/lll.h`.
- The frontend is intended for local academic demonstrations, not production key management.

## Project Status

Phases 1 through 19 are implemented and verified. Phase 20 documentation and final review are complete in this document. Future work may include stronger deployment configuration, browser-test automation, arbitrary-precision lattice arithmetic, and additional research documentation.
