from dataclasses import dataclass

@dataclass(frozen=True)
class SimplifiedKyberParameters:
    ''' ML-KEM-768 domain parameters used in simplified Kyber PKE '''
    q: int = 3329
    n: int = 256
    k: int = 3
    eta1: int = 2
    eta2: int = 2

@dataclass(frozen=True)
class KyberParameters:
    ''' ML-KEM domain parameters used in Kyber PKE and Kyber KEM defined in FIPS 203 '''
    k: int
    eta1: int
    eta2: int
    du: int
    dv: int
    q: int = 3329
    n: int = 256
    z: int = 17
    n_inv: int = 3303

    @classmethod
    def match_name(cls, name: str) -> "KyberParameters":
        if "512" in name:
            return ML_KEM_512
        elif "768" in name:
            return ML_KEM_768
        elif "1024" in name:
            return ML_KEM_1024
        else:
            raise ValueError(f"Unknown Kyber parameter set: {name}. Try: 'ML_KEM_512', 'ML_KEM_768', or 'ML_KEM_1024'.")


ML_KEM_512 = KyberParameters(k=2, eta1=3, eta2=2, du=10, dv=4)
ML_KEM_768 = KyberParameters(k=3, eta1=2, eta2=2, du=10, dv=4)
ML_KEM_1024 = KyberParameters(k=4, eta1=2, eta2=2, du=11, dv=5)