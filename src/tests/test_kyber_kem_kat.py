import json
import pathlib
import pytest

from .adapters import NIST_to_CommunicationPartyKEM

VECTORS_DIR = pathlib.Path(__file__).parent / "vectors"
VECTOR_FILES = ["encap_decap.json", "key_gen.json"]


def load_test_cases():
    if not VECTORS_DIR.exists():
        return []
    
    cases = []

    for vector_file in VECTOR_FILES:
        file_path = VECTORS_DIR / vector_file
        if not file_path.exists():
            continue

        with open(file_path, "r") as f:
            data = json.load(f)

        file_mode = data.get("mode", None)

        for group in data.get("testGroups", []):

            param_set = group["parameterSet"]
            function_type = group.get("function", file_mode)

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

    match function_type:

        case "keyGen":
            z_hex = test_case["z"]
            d_hex = test_case["d"]
            expected_ek_hex = test_case["ek"]
            expected_dk_hex = test_case["dk"]

            z_bytes = bytes.fromhex(z_hex)
            d_bytes = bytes.fromhex(d_hex)

            ek, dk = kem.key_generation_internal(d_bytes, z_bytes)
            ek_computed = adapter.pack_encapsulation_key(ek)
            dk_computed = adapter.pack_decapsulation_key(dk)

            assert ek_computed == expected_ek_hex
            assert dk_computed == expected_dk_hex

        case "encapsulation":
            ek_hex = test_case["ek"]
            m_hex = test_case["m"]
    
            expected_c_hex = test_case["c"]
            expected_k_hex = test_case["k"]
    
            ek = adapter.unpack_encapsulation_key(ek_hex)
            m_bytes = bytes.fromhex(m_hex)
    
            K, c = kem.encapsulate_internal(ek, m_bytes)
    
            K_computed = adapter.pack_shared_secret(K)
            c_computed = adapter.pack_ciphertext(c)
        
            assert K_computed == expected_k_hex
            assert c_computed == expected_c_hex

        case "decapsulation":
            dk_hex = test_case["dk"]
            c_hex = test_case["c"]
    
            expected_k_hex = test_case["k"]
    
            dk = adapter.unpack_decapsulation_key(dk_hex)
            c = adapter.unpack_ciphertext(c_hex)
    
            K = kem.decapsulate_internal(dk, c)
            K_computed = adapter.pack_shared_secret(K)
    
            assert K_computed == expected_k_hex

        case "encapsulationKeyCheck":
            ek_hex = test_case["ek"]
            ek = adapter.unpack_encapsulation_key(ek_hex)
            is_valid = kem.check_valid_ek(ek)

            assert is_valid == test_case["testPassed"]

        case "decapsulationKeyCheck":
            dk_hex = test_case["dk"]
            dk = adapter.unpack_decapsulation_key(dk_hex)
            is_valid = kem.check_valid_dk(dk)

            assert is_valid == test_case["testPassed"]