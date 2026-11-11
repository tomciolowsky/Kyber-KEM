import pytest

from kyber import (
    ML_KEM_512,
    ML_KEM_768,
    ML_KEM_1024,
    CommunicationPartyKEM,
    CommunicationPartyPKE,
    Conversion,
    KyberParameters,
)
from kyber.ntt import NTT


@pytest.mark.parametrize("param_name,expected", [
    ("ML_KEM_512", ML_KEM_512),
    ("ML-KEM-768", ML_KEM_768),
    ("ml_kem_1024", ML_KEM_1024),
])
def test_parameter_match_name(param_name, expected):
    assert KyberParameters.match_name(param_name) == expected


def test_parameter_match_name_invalid():
    with pytest.raises(ValueError):
        KyberParameters.match_name("invalid_512")


@pytest.mark.parametrize("param_set", [ML_KEM_512, ML_KEM_768, ML_KEM_1024])
def test_kem_roundtrip_and_implicit_rejection(param_set):
    kem = CommunicationPartyKEM(param_set)
    ek, dk = kem.key_generation()

    assert kem.check_valid_ek(ek)
    assert kem.check_valid_dk(dk)

    shared_secret, ciphertext = kem.encapsulate(ek)
    recovered_secret = kem.decapsulate(dk, ciphertext)
    assert recovered_secret == shared_secret

    tampered_ct = bytearray(ciphertext)
    tampered_ct[0] ^= 0xFF
    rejected_secret = kem.decapsulate(dk, bytes(tampered_ct))
    assert len(rejected_secret) == 32
    assert rejected_secret != shared_secret


def test_check_valid_ek_rejects_out_of_range_coefficients():
    kem = CommunicationPartyKEM(ML_KEM_512)
    ek, _ = kem.key_generation()

    bad_t_hat = [4095] + [0] * (256 * ML_KEM_512.k - 1)
    bad_ek = Conversion.byte_encode(bad_t_hat, 12) + ek[-32:]
    assert kem.check_valid_ek(bad_ek) is False


def test_decapsulate_rejects_invalid_ciphertext_length():
    kem = CommunicationPartyKEM(ML_KEM_768)
    _, dk = kem.key_generation()
    with pytest.raises(ValueError, match="ciphertext length"):
        kem.decapsulate(dk, b"too_short")


def test_pke_roundtrip():
    pke = CommunicationPartyPKE(ML_KEM_768)
    ek_pke, dk_pke = pke.key_generation_PKE()
    message = b"0123456789abcdef0123456789abcdef"
    ct = pke.encrypt(ek_pke, message)
    assert pke.decrypt(dk_pke, ct) == message


def test_no_input_mutation_in_conversion_and_ntt():
    original_ints = [12, 200, 255]
    snapshot = original_ints.copy()
    _ = Conversion.ints_to_bits(original_ints)
    assert original_ints == snapshot

    poly = list(range(256))
    poly_snapshot = poly.copy()
    zetas = NTT.generate_zetas_for_NTT(128, ML_KEM_768.z, ML_KEM_768.q)
    ntt_poly = NTT.computeNTT(poly, ML_KEM_768.q, ML_KEM_768.n, zetas)
    assert poly == poly_snapshot
    assert ntt_poly != poly
