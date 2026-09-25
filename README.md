# RSA-Lattice-Analysis

An educational RSA and lattice-based LWE encryption/decryption demonstration with a separate LLL lattice-reduction component.

## Scope

This project demonstrates three distinct workflows:

- RSA/OAEP encryption and decryption
- Educational LWE-style public-key encryption and decryption
- LLL lattice-basis reduction as a separate lattice-analysis tool

The software is explicitly educational. It does not claim practical RSA breaking, private-key recovery, or production-grade cryptographic security.

## RSA workflow

The RSA section preserves the existing OAEP implementation and shows:

- key generation
- public key and private key
- plaintext to ciphertext encryption
- ciphertext to plaintext decryption
- verification of the round trip
- execution timing for encryption and decryption

## LWE workflow

The LWE workflow uses the existing educational construction from the backend implementation.

It demonstrates:

- parameter selection and key generation
- public key and secret key display
- plaintext encoding
- LWE encryption using the public key
- ciphertext display
- decryption using the secret key
- verification of round-trip recovery

The LWE implementation is intentionally a small teaching-oriented construction, not a production system.

## LLL workflow

LLL is kept separate from the LWE encryption/decryption path.

It is shown as lattice basis reduction and analysis:

- input basis
- reduced basis
- iteration and swap telemetry
- norm comparison

LLL reduces lattice bases; it does not perform LWE encryption or decryption.

## Native C backend handling

The application preserves native C support for both the LLL and LWE paths when available.

If Windows Code Integrity blocks the native DLL, the backend reports:

- requested_backend: native_c
- actual_backend: python
- fallback: true

This is reported without claiming native execution occurred when it did not.

## Execution notes

- RSA and LWE timing values are kept as part of the encryption/decryption workflow.
- The old generic benchmark system has been removed.
- The project remains focused on educational demonstration and comparison rather than performance benchmarking.

## Running the app

Use the Flask app in the repository root or open the frontend served by the backend.

## Project status

The current implementation is intentionally simple and understandable, with a clear separation between:

- RSA/OAEP
- educational LWE encryption/decryption
- separate LLL lattice reduction

