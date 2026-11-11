# Kyber-KEM

![Tests](https://github.com/tomciolowsky/Kyber-KEM/actions/workflows/test.yml/badge.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)
![uv](https://img.shields.io/badge/uv-managed-DE5FE9.svg?logo=uv)
![Standards](https://img.shields.io/badge/NIST-FIPS%20203-green.svg)

Pure-Python implementation of **ML-KEM** (Module-Lattice-Based Key-Encapsulation Mechanism), standardized by NIST in **FIPS 203** (formerly CRYSTALS-Kyber). Supports `ML-KEM-512`, `ML-KEM-768`, and `ML-KEM-1024`, validated against **240 official NIST ACVP Known Answer Test (KAT)** vectors across key generation, encapsulation, decapsulation, and key checks.

> **Security Notice:** This implementation is written in pure Python for educational, research, and prototyping purposes. Python integer arithmetic and list indexing are not constant-time and are not hardened against side-channel attacks; do not use directly in production security-critical systems.

## Quick Start

Simple example of key generation, encapsulation, and decapsulation between Alice and Bob:

```python
from kyber import CommunicationPartyKEM, ML_KEM_768

# Choose parameters (ML_KEM_512, ML_KEM_768, or ML_KEM_1024)
kyber_parameters = ML_KEM_768  # or string: "ML_KEM_768"

# Initialize parties
Alice = CommunicationPartyKEM(kyber_parameters)
Bob = CommunicationPartyKEM(kyber_parameters)

# 1. Alice generates a key pair
public_key, secret_key = Alice.key_generation()

# 2. Bob encapsulates a shared secret using Alice's public key
Bob_shared_secret, Bob_ciphertext = Bob.encapsulate(public_key)

# 3. Alice decapsulates the shared secret using her secret key
Alice_shared_secret = Alice.decapsulate(secret_key, Bob_ciphertext)
```

Run examples from the repo root:

```bash
uv run python working_examples/kyber_kem_demo.py
uv run python working_examples/kyber_pke_demo.py
```

## Installation

### Using uv:
Requires [uv](https://github.com/astral-sh/uv)

```bash
git clone https://github.com/tomciolowsky/Kyber-KEM.git
cd Kyber-KEM

# Install runtime and dev dependencies (pytest, ruff)
uv sync --all-groups
```

### Using pip:

```bash
git clone https://github.com/tomciolowsky/Kyber-KEM.git
cd Kyber-KEM
pip install -e .[dev]
```

## Testing & Linting

Validated against 240 official NIST ACVP FIPS 203 test vectors plus unit tests:

```bash
# Run linter
uv run ruff check .

# Run tests
uv run pytest -v
```

## Resources

### Learning Materials
* [Cryptography 101 YouTube course by Alfred Menezes](https://www.youtube.com/@cryptography101-alfred)
* [A Gentle Introduction to Lattice-Based Cryptography by Alfred Menezes](https://cryptography101.ca/wp-content/uploads/lattice-based-cryptography.pdf)

### Papers & Standards
* [NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
* [NIST FIPS 202 — SHA-3 Standard (SHA3 & SHAKE)](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf)

### Test Vectors
* [NIST ACVP-Server Repository](https://github.com/usnistgov/ACVP-Server)
* [ML-KEM KeyGen Vectors](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-keyGen-FIPS203)
* [ML-KEM EncapDecap Vectors](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-encapDecap-FIPS203)