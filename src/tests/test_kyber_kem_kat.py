import json
import pathlib
import pytest

from .adapters import NIST_to_CommunicationPartyKEM

VECTORS_PATH = pathlib.Path(__file__).parent / "vectors" / "internalProjection.json"


def load_test_cases():
    if not VECTORS_PATH.exists():
        return []
    
    with open(VECTORS_PATH, "r") as f:
        data = json.load(f)
    
    cases = []
    for group in data.get("testGroups", []):

        param_set = group["parameterSet"]
        function_type = group["function"]

        for test in group.get("tests", []):
            test_id = f"{param_set}-{function_type}-tcId_{test['tcId']}"
            cases.append(pytest.param(param_set, function_type, test, id=test_id))
            
    return cases


ALL_TEST_CASES = load_test_cases()

@pytest.mark.parametrize("param_set, function_type, test_case", ALL_TEST_CASES)
def test_kem_with_nist_vectors(param_set, function_type, test_case):
    """
    Test the KEM implementation with NIST test vectors.
    """

    adapter = NIST_to_CommunicationPartyKEM(param_set)
    kem = adapter.kem

    if function_type == "encapsulation":
        ek_hex = test_case["ek"]
        m_hex = test_case["m"]

        expected_c_hex = test_case["c"]
        expected_k_hex = test_case["k"]

        ek_bytes = bytes.fromhex(ek_hex)

        ek = adapter.unpack_encapsulation_key(ek_bytes)
        m_bytes = bytes.fromhex(m_hex)

        K, c = kem.encapsulate_internal(ek, m_bytes)

        K_computed = bytearray(K).hex().upper()
        c_computed = adapter.pack_ciphertext(c).hex().upper()
    
        assert K_computed == expected_k_hex
        assert c_computed == expected_c_hex

    elif function_type == "decapsulation":
        dk_hex = test_case["dk"]
        c_hex = test_case["c"]

        k_hex = test_case["k"]

        dk_bytes = bytes.fromhex(dk_hex)
        dk = adapter.unpack_decapsulation_key(dk_bytes)

        c_bytes = bytes.fromhex(c_hex)
        c = adapter.unpack_ciphertext(c_bytes)

        K = kem.decapsulate_internal(dk, c)
        K_computed = bytearray(K).hex().upper()

        assert K_computed == k_hex