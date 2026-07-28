# Kyber-KEM

![Tests](https://github.com/tomciolowsky/Kyber-KEM/actions/workflows/test.yml/badge.svg)

My implementation of the Kyber Key Encapsulation Mechanism - standardized by NIST as **ML-KEM**. 
This cryptographic approach was designed as quantum-secure, which means that It makes key exchanges viable even in case of future quantum attacks. 


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