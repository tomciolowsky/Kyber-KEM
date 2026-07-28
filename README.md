# Kyber-KEM

![Tests](https://github.com/tomciolowsky/Kyber-KEM/actions/workflows/test.yml/badge.svg)

My implementation of the Kyber Key Encapsulation Mechanism - standardized by NIST as **ML-KEM**. 
This cryptographic approach was designed as quantum-secure, which means that it makes key exchanges viable even in case of future quantum attacks. 

## Quick Start

Simple example of key generation, encapsulation and decapsulation between Alice and Bob:

```python
from kyber import CommunicationPartyKEM, ML_KEM_768

# choose parameters (ML_KEM_512, ML_KEM_768 or ML_KEM_1024)
kyber_parameters = ML_KEM_768 # or string: "ML_KEM_768"

# initialize parties
Alice = CommunicationPartyKEM(kyber_parameters)
Bob = CommunicationPartyKEM(kyber_parameters)

# 1. Alice generates a key pair
public_key, secret_key = Alice.key_generation()

# 2. Bob encapsulates a shared secret using Alice's public key
Bob_shared_secret, Bob_ciphertext = Bob.encapsulate(public_key)

# 3. Alice decapsulates the shared secret using her secret key
Alice_shared_secret = Alice.decapsulate(secret_key, Bob_ciphertext)
```

Run example from the repo:
```bash
python working_examples/kyber_kem_demo.py
```

## Installation

Standard Installation:

```bash
git clone https://github.com/tomciolowsky/Kyber-KEM.git
cd Kyber-KEM
pip install .
```

Development Installation (modify or run tests):

```bash
git clone https://github.com/tomciolowsky/Kyber-KEM.git
cd Kyber-KEM
pip install -e .[dev]
```

## Running Tests

I used `pytest` and KAT (Known Answer Tests) from NIST for testing.

To run tests:

```bash
pytest
```

## Resources

### Learning Materials

* Ideas and general information: 

    [Cryptography 101 YouTube course by Alfred Menezes](https://www.youtube.com/@cryptography101-alfred)

    [A Gentle Introduction to Lattice-Based Cryptography by Alfred Menezes](https://cryptography101.ca/wp-content/uploads/lattice-based-cryptography.pdf)

### Papers and Standards
* Kyber KEM paper:

    [FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)

* Hash Functions paper:

    [FIPS 202](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf)

* Dilithium paper:

    [FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)

### Test vectors
* Official NIST repository:

    [ACVP REPO](https://github.com/usnistgov/ACVP-Server)

* Test vector files:

    [ENCAP-DECAP](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-encapDecap-FIPS203)

    [KEYGEN](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-keyGen-FIPS203)