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
    ''' ML-KEM-768 domain parameters used in Kyber PKE '''
    q: int = 3329
    n: int = 256
    k: int = 3
    eta1: int = 2
    eta2: int = 2
    du: int = 10
    dv: int = 4
    z: int = 17
    n_inv: int = 3303