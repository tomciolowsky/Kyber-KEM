from random import randint

from .compression import Compression
from .conversion import Conversion
from .ntt import NTT
from .math_operations import MathOperations
from .parameters import SimplifiedKyberParameters, KyberParameters
from .randomness import Randomness
from .hash import Hash


class SimplifiedCommunicationParty:
    def __init__(self, parameters: SimplifiedKyberParameters):
        self.parameters = parameters
        self.A = None
        self.s = None
        self.e = None
        self.t = None

    def generate_public_key(self):

        def select_A(q, k, n):
            A = []
            for i in range(k):
                row = []
                for j in range(k):
                    polynomial = [randint(0, q-1) for _ in range(n)]
                    row.append(polynomial)
                A.append(row)
            return A

        def select_s(k, n, eta1):
            s = []
            for i in range(k):
                polynomial = [randint(-eta1, eta1) for _ in range(n)]
                s.append(polynomial)
            return s

        def select_e(k, n, eta1):
            e = []
            for i in range(k):
                polynomial = [randint(-eta1, eta1) for _ in range(n)]
                e.append(polynomial)
            return e


        self.A = select_A(self.parameters.q, self.parameters.k, self.parameters.n)
        self.s = select_s(self.parameters.k, self.parameters.n, self.parameters.eta1)
        self.e = select_e(self.parameters.k, self.parameters.n, self.parameters.eta1)

        As = MathOperations.multiply_square_matrix_by_vector(self.A, self.s, self.parameters.q, self.parameters.k, self.parameters.n)
        self.t = MathOperations.add_vectors(As, self.e, self.parameters.q, self.parameters.k)

        return (self.A, self.t)

    def encrypt(self, text_in_bytes):
        def select_r(k, n, eta1):
            r = []
            for i in range(k):
                polynomial = [randint(-eta1, eta1) for _ in range(n)]
                r.append(polynomial)
            return r

        def select_e1(k, n, eta2):
            e1 = []
            for i in range(k):
                polynomial = [randint(-eta2, eta2) for _ in range(n)]
                e1.append(polynomial)
            return e1

        def select_e2(n, eta2):
            e2 = [randint(-eta2, eta2) for _ in range(n)]
            return e2

        bitstring = Conversion.text_in_bytes_to_bitstring(text_in_bytes, self.parameters.n)
        m = Conversion.bitstring_to_polynomial(bitstring, self.parameters.n)

        r = select_r(self.parameters.k, self.parameters.n, self.parameters.eta1)
        e1 = select_e1(self.parameters.k, self.parameters.n, self.parameters.eta2)
        e2 = select_e2(self.parameters.n, self.parameters.eta2)

        AT = MathOperations.matrix_transpose(self.A, self.parameters.k, self.parameters.k)
        ATr = MathOperations.multiply_square_matrix_by_vector(AT, r, self.parameters.q, self.parameters.k, self.parameters.n)
        u = MathOperations.add_vectors(ATr, e1, self.parameters.q, self.parameters.k)

        tTr = MathOperations.multiply_vectors(self.t, r, self.parameters.q, self.parameters.k, self.parameters.n)
        half_qm = MathOperations.multiply_polynomial_by_scalar(m, (self.parameters.q+1)//2, self.parameters.q)
        tTr_e2 = MathOperations.add_polynomials(tTr, e2, self.parameters.q)
        v = MathOperations.add_polynomials(tTr_e2, half_qm, self.parameters.q)
        
        return (u, v)

    def decrypt(self, ciphertext):
        u, v = ciphertext
        sTu = MathOperations.multiply_vectors(self.s, u, self.parameters.q, self.parameters.k, self.parameters.n)
        v_sub_sTu = MathOperations.subtract_polynomials(v, sTu, self.parameters.q)
        m_recovered = MathOperations.round_polynomial(v_sub_sTu, self.parameters.q)
        bitstring_recovered = Conversion.polynomial_to_bitstring(m_recovered, self.parameters.n)
        text_in_bytes_recovered = Conversion.bitstring_to_text_in_bytes(bitstring_recovered, self.parameters.n)

        return text_in_bytes_recovered
    

class CommunicationPartyPKE:
    """
    Public Key Encryption (PKE) class used in Kyber.
    """
    def __init__(self, parameters: KyberParameters | str = "ML_KEM_768"):
        if isinstance(parameters, str):
            parameters = KyberParameters.match_name(parameters)

        self.parameters = parameters
        self.zetas_for_NTT = NTT.generate_zetas_for_NTT(self.parameters.n//2, self.parameters.z, self.parameters.q)
        self.zetas_for_multiply = NTT.generate_zetas_for_multiply(self.parameters.n//2, self.parameters.z, self.parameters.q)

    def key_generation_PKE(self, d_bytes:bytes = None) -> tuple[tuple[list[int], bytes], bytes]:
        """
        K-PKE.KeyGen - generate public key (ro, t_hat) and private key s_hat.
        """
        if d_bytes is None:
            d_bytes = Randomness.random_bytes(self.parameters.n)

        ro, sigma = Hash.G(d_bytes + bytes([self.parameters.k]))
        A_hat = NTT.generate_square_matrix_NTT_from_ro(ro, self.parameters.q, self.parameters.k, self.parameters.n)

        n_counter = 0
        
        s = Randomness.generate_vector(self.parameters.q, self.parameters.k, self.parameters.n, self.parameters.eta1, sigma, n_counter)
        n_counter += self.parameters.k
        e = Randomness.generate_vector(self.parameters.q, self.parameters.k, self.parameters.n, self.parameters.eta1, sigma, n_counter)
        
        s_hat = NTT.compute_vector_NTT(s, self.parameters.q, self.parameters.k, self.parameters.n, self.zetas_for_NTT)
        e_hat = NTT.compute_vector_NTT(e, self.parameters.q, self.parameters.k, self.parameters.n, self.zetas_for_NTT)

        A_hat_s_hat = NTT.multiply_square_matrix_by_vector_NTT(A_hat, s_hat, self.parameters.q, self.parameters.k, self.parameters.n, self.zetas_for_multiply)

        t_hat = MathOperations.add_vectors(A_hat_s_hat, e_hat, self.parameters.q, self.parameters.k)

        t_hat_encoded = Conversion.vector_byte_encode(t_hat, 12)
        s_hat_encoded = Conversion.vector_byte_encode(s_hat, 12)

        ek_PKE = (ro, t_hat_encoded)
        dk_PKE = s_hat_encoded

        return (ek_PKE, dk_PKE)

    def encrypt(self, ek_PKE:tuple[list[int], bytes], text_in_bytes:bytes, randomness:list[int] = None) -> tuple[bytes, bytes]:
        """
        K-PKE.Encrypt - encrypt a byte message using public key (ro, t_hat) and randomness r.
        """
        if randomness is None:
            randomness = Randomness.random_ints(self.parameters.n)

        ro, t_hat_encoded = ek_PKE
        t_hat = Conversion.vector_byte_decode(t_hat_encoded, self.parameters.k, 12)
        
        m = Conversion.byte_decode(text_in_bytes, 1)

        n_counter = 0

        A_hat = NTT.generate_square_matrix_NTT_from_ro(ro, self.parameters.q, self.parameters.k, self.parameters.n)
        
        r = Randomness.generate_vector(self.parameters.q, self.parameters.k, self.parameters.n, self.parameters.eta1, randomness, n_counter)
        n_counter += self.parameters.k

        e1 = Randomness.generate_vector(self.parameters.q, self.parameters.k, self.parameters.n, self.parameters.eta2, randomness, n_counter)
        n_counter += self.parameters.k

        e2 = Randomness.generate_polynomial(self.parameters.q, self.parameters.n, self.parameters.eta2, randomness, n_counter)
        
        r_hat = NTT.compute_vector_NTT(r, self.parameters.q, self.parameters.k, self.parameters.n, self.zetas_for_NTT)
        
        A_hatT = MathOperations.matrix_transpose(A_hat, self.parameters.k)
        A_hatT_r = NTT.multiply_square_matrix_by_vector_NTT(A_hatT, r_hat, self.parameters.q, self.parameters.k, self.parameters.n, self.zetas_for_multiply)
        ntt_inv_A_hatT_r = NTT.compute_vector_NTT_inverse(A_hatT_r, self.parameters.q, self.parameters.k, self.parameters.n, self.parameters.n_inv, self.zetas_for_NTT)
        u = MathOperations.add_vectors(ntt_inv_A_hatT_r, e1, self.parameters.q, self.parameters.k)

        t_hatT_r_hat = NTT.multiply_vectors_NTT(t_hat, r_hat, self.parameters.q, self.parameters.k, self.parameters.n, self.zetas_for_multiply)
        ntt_inv_t_hatT_r_hat = NTT.computeNTT_inverse(t_hatT_r_hat, self.parameters.q, self.parameters.n, self.parameters.n_inv, self.zetas_for_NTT)
        half_qm = MathOperations.multiply_polynomial_by_scalar(m, (self.parameters.q+1)//2, self.parameters.q)
        ntt_inv_t_hatT_r_hat_e2 = MathOperations.add_polynomials(ntt_inv_t_hatT_r_hat, e2, self.parameters.q)
        v = MathOperations.add_polynomials(ntt_inv_t_hatT_r_hat_e2, half_qm, self.parameters.q)
        
        c1 = Compression.compress_vector(u, self.parameters.q, self.parameters.du)
        c2 = Compression.compress_polynomial(v, self.parameters.q, self.parameters.dv)

        c1_encoded = Conversion.vector_byte_encode(c1, self.parameters.du)
        c2_encoded = Conversion.byte_encode(c2, self.parameters.dv)

        return (c1_encoded, c2_encoded)

    def decrypt(self, dk_PKE:bytes, ciphertext:tuple[bytes, bytes]) -> bytes:
        """
        K-PKE.Decrypt - decrypt a ciphertext using private key s_hat.
        """
        c1_encoded, c2_encoded = ciphertext
        c1 = Conversion.vector_byte_decode(c1_encoded, self.parameters.k, self.parameters.du)
        c2 = Conversion.byte_decode(c2_encoded, self.parameters.dv)
        u_prim = Compression.decompress_vector(c1, self.parameters.q, self.parameters.du)
        v_prim = Compression.decompress_polynomial(c2, self.parameters.q, self.parameters.dv)
        ntt_u_prim = NTT.compute_vector_NTT(u_prim, self.parameters.q, self.parameters.k, self.parameters.n, self.zetas_for_NTT)
        s_hat_encoded = dk_PKE
        s_hat = Conversion.vector_byte_decode(s_hat_encoded, self.parameters.k, 12)
        s_hatT_ntt_u_prim = NTT.multiply_vectors_NTT(s_hat, ntt_u_prim, self.parameters.q, self.parameters.k, self.parameters.n, self.zetas_for_multiply)
        ntt_inv_s_hatT_ntt_u_prim = NTT.computeNTT_inverse(s_hatT_ntt_u_prim, self.parameters.q, self.parameters.n, self.parameters.n_inv, self.zetas_for_NTT)
        w = MathOperations.subtract_polynomials(v_prim, ntt_inv_s_hatT_ntt_u_prim, self.parameters.q)
        
        w_compressed = Compression.compress_polynomial(w, self.parameters.q, 1)
        m = Conversion.byte_encode(w_compressed, 1)

        return m
    

class CommunicationPartyKEM(CommunicationPartyPKE):
    """
    Key Encapsulation Mechanism (KEM) class used in Kyber.
    """
    def __init__(self, parameters: KyberParameters | str = "ML_KEM_768"):
        super().__init__(parameters)

    def key_generation_internal(self, d_bytes:bytes, z_bytes:bytes) -> tuple[tuple[list[int], bytes], tuple[bytes, tuple[list[int], bytes], bytes, bytes]]:
        """
        ML-KEM.KeyGen_internal - generate encapsulation and decapsulation keys (ek, dk) using randomness d and z.
        """
        ek_PKE, dk_PKE = self.key_generation_PKE(d_bytes)

        ro, t_hat_encoded = ek_PKE
        ek_bytes = t_hat_encoded + bytes(ro)

        H_ek = Hash.H(ek_bytes)
        H_ek_bytes = bytes(H_ek)

        dk = (dk_PKE, ek_PKE, H_ek_bytes, z_bytes)

        return (ek_PKE, dk)

    def key_generation(self) -> tuple[tuple[list[int], bytes], tuple[bytes, tuple[list[int], bytes], bytes, bytes]]:
        """
        ML-KEM.KeyGen - generate encapsulation and decapsulation keys (ek, dk)
        """
        d_bytes = Randomness.random_bytes(self.parameters.n)
        z_bytes = Randomness.random_bytes(self.parameters.n)

        ek, dk = self.key_generation_internal(d_bytes, z_bytes)

        return (ek, dk)

    def check_valid_ek(self, ek:tuple[list[int], bytes]) -> bool:
        """
        Check if the encapsulation key ek is valid.
        """
        ro, t_hat_encoded = ek
        if len(ro) != 32:
            return False
        if len(t_hat_encoded) != self.parameters.k * 384:
            return False

        t_hat = Conversion.vector_byte_decode(t_hat_encoded, self.parameters.k, 12)
        test = Conversion.vector_byte_encode(t_hat, 12)
        if test != t_hat_encoded:
            return False

        return True

    def encapsulate_internal(self, ek:tuple[list[int], bytes], m_bytes:bytes) -> tuple[list[int], tuple[bytes, bytes]]:
        """
        ML-KEM.Encaps_internal - generate a key and an associated ciphertext using encapsulation key ek and randomness m.
        """
        ro, t_hat_encoded = ek
        ek_bytes = t_hat_encoded + bytes(ro)

        H_ek = Hash.H(ek_bytes)
        H_ek_bytes = bytes(H_ek)

        K, r = Hash.G(m_bytes + H_ek_bytes)

        c = self.encrypt(ek, m_bytes, r)

        return (K, c)
    
    def encapsulate(self, ek:tuple[list[int], bytes]) -> tuple[list[int], tuple[bytes, bytes]]:
        """
        ML-KEM.Encaps - generate a shared secret key and an associated ciphertext using encapsulation key ek.
        """
        if not self.check_valid_ek(ek):
            raise ValueError("Invalid encapsulation key.")

        m_bytes = Randomness.random_bytes(self.parameters.n)

        K, c = self.encapsulate_internal(ek, m_bytes)
        
        return (K, c)

    def check_valid_dk(self, dk:tuple[bytes, tuple[list[int], bytes], bytes, bytes]) -> bool:
        """
        Check if the decapsulation key dk is valid.
        """
        dk_PKE, ek_PKE, H_ek_bytes, z_bytes = dk

        if len(dk_PKE) != self.parameters.k * 384:
            return False
        if not self.check_valid_ek(ek_PKE):
            return False
        if len(H_ek_bytes) != 32:
            return False
        if len(z_bytes) != 32:
            return False

        ro, t_hat_encoded = ek_PKE
        ek_bytes = t_hat_encoded + bytes(ro)
        test = Hash.H(ek_bytes)
        if bytes(test) != H_ek_bytes:
            return False

        return True
    
    def decapsulate_internal(self, dk:tuple[bytes, tuple[list[int], bytes], bytes, bytes], ciphertext:tuple[bytes, bytes]) -> list[int]:
        """
        ML-KEM.Decaps_internal - produce a shared secret key from ciphertext using the decapsulation key dk.
        """
        dk_PKE, ek_PKE, H_ek_bytes, z_bytes = dk

        m_prime = self.decrypt(dk_PKE, ciphertext)
    
        K_prime, r_prime = Hash.G(m_prime + H_ek_bytes)

        c_bytes = ciphertext[0] + ciphertext[1]

        K_bar = Hash.J(z_bytes + c_bytes)

        c_prime = self.encrypt(ek_PKE, m_prime, r_prime)

        if ciphertext != c_prime:
            return K_bar
        else:
            return K_prime

    def decapsulate(self, dk:tuple[bytes, tuple[list[int], bytes], bytes, bytes], ciphertext:tuple[bytes, bytes]) -> list[int]:
        """
        ML-KEM.Decaps - produce a shared secret key from ciphertext using the decapsulation key dk.
        """
        if not self.check_valid_dk(dk):
            raise ValueError("Invalid decapsulation key.")

        K_prime = self.decapsulate_internal(dk, ciphertext)
        return K_prime