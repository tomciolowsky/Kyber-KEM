from random import randint
from modules.Compression import Compression
from modules.Conversion import Conversion
from modules.NTT import NTT
from modules.MathOperations import MathOperations
from modules.KyberParameters import SimplifiedKyberParameters, KyberParameters
from modules.Randomness import Randomness
from modules.Hash import Hash


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
    

class CommunicationParty:
    def __init__(self, parameters: KyberParameters):
        self.parameters = parameters
        self.A_hat = None
        self.s_hat = None
        self.e_hat = None
        self.t_hat = None
        self.ro = None
        self.zetas_for_NTT = NTT.generate_zetas_for_NTT(self.parameters.n//2, self.parameters.z, self.parameters.q)
        self.zetas_for_multiply = NTT.generate_zetas_for_multiply(self.parameters.n//2, self.parameters.z, self.parameters.q)

    def generate_public_key(self):

        def select_ro(n):
            ro_length = n // (n.bit_length()-1)
            return [randint(0, n-1) for _ in range(ro_length)]

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

        self.ro = select_ro(self.parameters.n)
        self.A_hat = NTT.generate_square_matrix_NTT_from_ro(self.ro, self.parameters.q, self.parameters.k, self.parameters.n)

        s = select_s(self.parameters.k, self.parameters.n, self.parameters.eta1)
        e = select_e(self.parameters.k, self.parameters.n, self.parameters.eta1)
        
        self.s_hat = NTT.compute_vector_NTT(s, self.parameters.q, self.parameters.k, self.parameters.n, self.zetas_for_NTT)
        self.e_hat = NTT.compute_vector_NTT(e, self.parameters.q, self.parameters.k, self.parameters.n, self.zetas_for_NTT)

        A_hat_s_hat = NTT.multiply_square_matrix_by_vector_NTT(self.A_hat, self.s_hat, self.parameters.q, self.parameters.k, self.parameters.n, self.zetas_for_multiply)

        self.t_hat = MathOperations.add_vectors(A_hat_s_hat, self.e_hat, self.parameters.q, self.parameters.k)

        return (self.ro, self.t_hat)

    def obtain_key(self, key):
        self.ro = key[0]
        self.t_hat = key[1]
        self.A_hat = NTT.generate_square_matrix_NTT_from_ro(self.ro, self.parameters.q, self.parameters.k, self.parameters.n)

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
        m  = Conversion.bitstring_to_polynomial(bitstring, self.parameters.n)

        r = select_r(self.parameters.k, self.parameters.n, self.parameters.eta1)
        e1 = select_e1(self.parameters.k, self.parameters.n, self.parameters.eta2)
        e2 = select_e2(self.parameters.n, self.parameters.eta2)

        r_hat = NTT.compute_vector_NTT(r, self.parameters.q, self.parameters.k, self.parameters.n, self.zetas_for_NTT)

        A_hatT = MathOperations.matrix_transpose(self.A_hat, self.parameters.k, self.parameters.k)
        A_hatT_r = NTT.multiply_square_matrix_by_vector_NTT(A_hatT, r_hat, self.parameters.q, self.parameters.k, self.parameters.n, self.zetas_for_multiply)
        ntt_inv_A_hatT_r = NTT.compute_vector_NTT_inverse(A_hatT_r, self.parameters.q, self.parameters.k, self.parameters.n, self.parameters.n_inv, self.zetas_for_NTT)
        u = MathOperations.add_vectors(ntt_inv_A_hatT_r, e1, self.parameters.q, self.parameters.k)

        t_hatT_r_hat = NTT.multiply_vectors_NTT(self.t_hat, r_hat, self.parameters.q, self.parameters.k, self.parameters.n, self.zetas_for_multiply)
        ntt_inv_t_hatT_r_hat = NTT.computeNTT_inverse(t_hatT_r_hat, self.parameters.q, self.parameters.n, self.parameters.n_inv, self.zetas_for_NTT)
        half_qm = MathOperations.multiply_polynomial_by_scalar(m, (self.parameters.q+1)//2, self.parameters.q)
        ntt_inv_t_hatT_r_hat_e2 = MathOperations.add_polynomials(ntt_inv_t_hatT_r_hat, e2, self.parameters.q)
        v = MathOperations.add_polynomials(ntt_inv_t_hatT_r_hat_e2, half_qm, self.parameters.q)
        
        c1 = Compression.compress_vector(u, self.parameters.q, self.parameters.du)
        c2 = Compression.compress_polynomial(v, self.parameters.q, self.parameters.dv)

        return (c1, c2)

    def decrypt(self, ciphertext):
        c1, c2 = ciphertext
        u_prim = Compression.decompress_vector(c1, self.parameters.q, self.parameters.du)
        v_prim = Compression.decompress_polynomial(c2, self.parameters.q, self.parameters.dv)
        ntt_u_prim = NTT.compute_vector_NTT(u_prim, self.parameters.q, self.parameters.k, self.parameters.n, self.zetas_for_NTT)
        s_hatT_ntt_u_prim = NTT.multiply_vectors_NTT(self.s_hat, ntt_u_prim, self.parameters.q, self.parameters.k, self.parameters.n, self.zetas_for_multiply)
        ntt_inv_s_hatT_ntt_u_prim = NTT.computeNTT_inverse(s_hatT_ntt_u_prim, self.parameters.q, self.parameters.n, self.parameters.n_inv, self.zetas_for_NTT)
        w = MathOperations.subtract_polynomials(v_prim, ntt_inv_s_hatT_ntt_u_prim, self.parameters.q)
        
        m_recovered = MathOperations.round_polynomial(w, self.parameters.q)
        bitstring_recovered = Conversion.polynomial_to_bitstring(m_recovered, self.parameters.n)
        text_in_bytes_recovered = Conversion.bitstring_to_text_in_bytes(bitstring_recovered, self.parameters.n)

        return text_in_bytes_recovered
    

class CommunicationPartyKEM:
    def __init__(self, parameters: KyberParameters):
        self.dk = None

        self.ek = None
        self.A_hat = None
        self.parameters = parameters
        self.zetas_for_NTT = NTT.generate_zetas_for_NTT(self.parameters.n//2, self.parameters.z, self.parameters.q)
        self.zetas_for_multiply = NTT.generate_zetas_for_multiply(self.parameters.n//2, self.parameters.z, self.parameters.q)

    def key_generation(self):

        d_bytes = Randomness.random_bytes(self.parameters.n)
        z_bytes = Randomness.random_bytes(self.parameters.n)
        ek_PKE, dk_PKE = self.key_generation_internal(d_bytes)

        ek_ints = ek_PKE[0] + [coefficient for polynomial in ek_PKE[1] for coefficient in polynomial]
        ek_bytes = b''.join(num.to_bytes(2, 'big') for num in ek_ints)
        H_ek = Hash.H(ek_bytes)
        dk = (dk_PKE, ek_PKE, H_ek, z_bytes)

        self.dk = dk
        self.ek = ek_PKE

        return ek_PKE

    def key_generation_internal(self, d_bytes):

        ro, sigma = Hash.G(d_bytes + bytes([self.parameters.k]))

        self.A_hat = NTT.generate_square_matrix_NTT_from_ro(ro, self.parameters.q, self.parameters.k, self.parameters.n)

        n_counter = 0

        s = Randomness.generate_vector(self.parameters.q, self.parameters.k, self.parameters.n, self.parameters.eta1, sigma, n_counter)
        n_counter += self.parameters.k
        e = Randomness.generate_vector(self.parameters.q, self.parameters.k, self.parameters.n, self.parameters.eta1, sigma, n_counter)

        s_hat = NTT.compute_vector_NTT(s, self.parameters.q, self.parameters.k, self.parameters.n, self.zetas_for_NTT)
        e_hat = NTT.compute_vector_NTT(e, self.parameters.q, self.parameters.k, self.parameters.n, self.zetas_for_NTT)

        A_hat_s_hat = NTT.multiply_square_matrix_by_vector_NTT(self.A_hat, s_hat, self.parameters.q, self.parameters.k, self.parameters.n, self.zetas_for_multiply)

        t_hat = MathOperations.add_vectors(A_hat_s_hat, e_hat, self.parameters.q, self.parameters.k)

        ek = (ro, t_hat)
        dk = s_hat

        return (ek, dk)

    def obtain_key(self, key):
        self.ek = key
        ro = key[0]
        self.A_hat = NTT.generate_square_matrix_NTT_from_ro(ro, self.parameters.q, self.parameters.k, self.parameters.n)

    def encrypt(self, text_in_bytes, randomness):

        bitstring = Conversion.text_in_bytes_to_bitstring(text_in_bytes, self.parameters.n)
        m  = Conversion.bitstring_to_polynomial(bitstring, self.parameters.n)

        n_counter = 0

        r = Randomness.generate_vector(self.parameters.q, self.parameters.k, self.parameters.n, self.parameters.eta1, randomness, n_counter)
        n_counter += self.parameters.k

        e1 = Randomness.generate_vector(self.parameters.q, self.parameters.k, self.parameters.n, self.parameters.eta2, randomness, n_counter)
        n_counter += self.parameters.k

        e2 = Randomness.generate_polynomial(self.parameters.q, self.parameters.n, self.parameters.eta2, randomness, n_counter)
        
        r_hat = NTT.compute_vector_NTT(r, self.parameters.q, self.parameters.k, self.parameters.n, self.zetas_for_NTT)

        A_hatT = MathOperations.matrix_transpose(self.A_hat, self.parameters.k, self.parameters.k)
        A_hatT_r = NTT.multiply_square_matrix_by_vector_NTT(A_hatT, r_hat, self.parameters.q, self.parameters.k, self.parameters.n, self.zetas_for_multiply)
        ntt_inv_A_hatT_r = NTT.compute_vector_NTT_inverse(A_hatT_r, self.parameters.q, self.parameters.k, self.parameters.n, self.parameters.n_inv, self.zetas_for_NTT)
        u = MathOperations.add_vectors(ntt_inv_A_hatT_r, e1, self.parameters.q, self.parameters.k)

        t_hat = self.ek[1]
        t_hatT_r_hat = NTT.multiply_vectors_NTT(t_hat, r_hat, self.parameters.q, self.parameters.k, self.parameters.n, self.zetas_for_multiply)
        ntt_inv_t_hatT_r_hat = NTT.computeNTT_inverse(t_hatT_r_hat, self.parameters.q, self.parameters.n, self.parameters.n_inv, self.zetas_for_NTT)
        half_qm = MathOperations.multiply_polynomial_by_scalar(m, (self.parameters.q+1)//2, self.parameters.q)
        ntt_inv_t_hatT_r_hat_e2 = MathOperations.add_polynomials(ntt_inv_t_hatT_r_hat, e2, self.parameters.q)
        v = MathOperations.add_polynomials(ntt_inv_t_hatT_r_hat_e2, half_qm, self.parameters.q)
        
        c1 = Compression.compress_vector(u, self.parameters.q, self.parameters.du)
        c2 = Compression.compress_polynomial(v, self.parameters.q, self.parameters.dv)

        return (c1, c2)
    
    def encapsulate(self):

        m_bytes = Randomness.random_bytes(self.parameters.n)

        ek_ints = self.ek[0] + [coefficient for polynomial in self.ek[1] for coefficient in polynomial]
        ek_bytes = b''.join(num.to_bytes(2, 'big') for num in ek_ints)
        H_ek = Hash.H(ek_bytes)

        H_ek_bytes = bytes(H_ek)

        K, r = Hash.G(m_bytes + H_ek_bytes)

        c = self.encrypt(m_bytes, r)
        
        return (K, c)

    def decrypt(self, ciphertext):
        c1, c2 = ciphertext
        u_prim = Compression.decompress_vector(c1, self.parameters.q, self.parameters.du)
        v_prim = Compression.decompress_polynomial(c2, self.parameters.q, self.parameters.dv)
        ntt_u_prim = NTT.compute_vector_NTT(u_prim, self.parameters.q, self.parameters.k, self.parameters.n, self.zetas_for_NTT)
        s_hat = self.dk[0]
        s_hatT_ntt_u_prim = NTT.multiply_vectors_NTT(s_hat, ntt_u_prim, self.parameters.q, self.parameters.k, self.parameters.n, self.zetas_for_multiply)
        ntt_inv_s_hatT_ntt_u_prim = NTT.computeNTT_inverse(s_hatT_ntt_u_prim, self.parameters.q, self.parameters.n, self.parameters.n_inv, self.zetas_for_NTT)
        w = MathOperations.subtract_polynomials(v_prim, ntt_inv_s_hatT_ntt_u_prim, self.parameters.q)
        
        m_recovered = MathOperations.round_polynomial(w, self.parameters.q)
        bitstring_recovered = Conversion.polynomial_to_bitstring(m_recovered, self.parameters.n)
        text_in_bytes_recovered = Conversion.bitstring_to_text_in_bytes(bitstring_recovered, self.parameters.n)

        return text_in_bytes_recovered
    
    def decapsulate(self, ciphertext):
        m_prime = self.decrypt(ciphertext)

        ek_ints = self.ek[0] + [coefficient for polynomial in self.ek[1] for coefficient in polynomial]
        ek_bytes = b''.join(num.to_bytes(2, 'big') for num in ek_ints)
        H_ek = Hash.H(ek_bytes)
        
        H_ek_bytes = bytes(H_ek)

        K_prime, r_prime = Hash.G(m_prime + H_ek_bytes)

        c_ints = [coefficient for polynomial in ciphertext[0] for coefficient in polynomial] + ciphertext[1]
        c_bytes = b''.join(num.to_bytes(2, 'big') for num in c_ints)
        z_bytes = self.dk[3]
        K_bar = Hash.J(z_bytes + c_bytes)

        c_prime = self.encrypt(m_prime, r_prime)

        if ciphertext != c_prime:
            return K_bar
        else:
            return K_prime