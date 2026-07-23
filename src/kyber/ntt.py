from hashlib import shake_128
from .math_operations import MathOperations

class NTT:
    ''' Functions for working in the Kyber Number Theoretic Transform **(NTT)** domain. '''

    @staticmethod
    def brv(v:int, n:int) -> int:
        bits_in_n = n.bit_length() - 1
        binary_string = format(v, f'0{bits_in_n}b')
        reversed_binary_string = binary_string[::-1]
        reversed_v = int(reversed_binary_string, 2)
        return reversed_v

    @staticmethod
    def generate_zetas_for_NTT(n, z, q):
        zetas = [0] * n
        
        for i in range(n):
            zetas[i] = (z**NTT.brv(i, n))%q
        return zetas

    @staticmethod
    def generate_zetas_for_multiply(n, z, q):
        zetas = [0] * n
        
        for i in range(n):
            zetas[i] = (z**(2*NTT.brv(i, n) + 1))%q
        return zetas

    @staticmethod
    def sampleNTT(ro,j,i, n, q):
        seed = bytes(ro+[j]+[i])
        shake = shake_128(seed)
        j = 0
        a_hat = [0] * n
        while j < n:
            hash_bytes = shake.digest(3)
            shake.update(hash_bytes)
            hash_ints = [int(byte) for byte in hash_bytes]
            d1 = hash_ints[0] + n*(hash_ints[1]%16)
            d2 = int(hash_ints[1]//16) + 16*hash_ints[2]

            if d1 < q:
                a_hat[j] = d1
                j = j+1
            if d2 < q and j < n:
                a_hat[j] = d2
                j = j+1
        return a_hat

    @staticmethod
    def computeNTT(f, q, n, zetas):
        ''' compute NTT of polynomial f '''
        f_hat = f
        i = 1
        length = n//2

        while length >= 2:
            start = 0
            while start < n:
                zeta = zetas[i]
                i = i+1
                for j in range(start, start+length):
                    t = (zeta * f_hat[j+length]) % q
                    f_hat[j+length] = (f_hat[j] - t) % q
                    f_hat[j] = (f_hat[j] + t) % q
                start = start + 2*length
            length = length // 2
        
        return f_hat

    @staticmethod
    def computeNTT_inverse(f_hat, q, n, n_inv, zetas):
        f = f_hat
        i = n//2 - 1
        length = 2
        while length <= n//2:
            start = 0
            while start < n:
                zeta = zetas[i]
                i = i-1
                for j in range(start, start+length):
                    t = f[j]
                    f[j] = (t + f[j+length]) % q
                    f[j+length] = (zeta * (f[j+length] - t)) % q
                start = start + 2*length
            length = 2*length

        f = [(coefficient * n_inv) % q for coefficient in f]

        return f

    @staticmethod
    def compute_vector_NTT(a, q, k, n, zetas):
        ''' compute NTT of k-length vector a '''
        a_hat = [0]*k
        for i in range(k):
            polynomial_hat = NTT.computeNTT(a[i], q, n, zetas)
            a_hat[i] = polynomial_hat
        return a_hat

    @staticmethod
    def compute_vector_NTT_inverse(a_hat, q, k, n, n_inv, zetas):
        ''' compute inverse NTT of k-length vector a_hat '''
        a = [0]*k
        for i in range(k):
            polynomial = NTT.computeNTT_inverse(a_hat[i], q, n, n_inv, zetas)
            a[i] = polynomial
        return a

    @staticmethod
    def base_case_multiply(a0, a1, b0, b1, q, z):
        c0 = (a0*b0 + a1*b1*z) % q
        c1 = (a0*b1 + a1*b0) % q
        return c0, c1

    @staticmethod
    def multiplyNTT(f_hat, g_hat, q, n, zetas):
        ''' multiply two polynomials in NTT domain '''
        h = [0] * n
        for i in range(n//2):
            a0 = f_hat[2*i]
            a1 = f_hat[2*i + 1]
            b0 = g_hat[2*i]
            b1 = g_hat[2*i + 1]
            h[2*i], h[2*i + 1] = NTT.base_case_multiply(a0, a1, b0, b1, q, zetas[i])

        return h

    @staticmethod
    def multiply_vectors_NTT(a_hat, b_hat, q, k, n, zetas):
        ''' multiply two k-length vectors in NTT domain '''
        result = []
        for i in range(k):
            multiplied = NTT.multiplyNTT(a_hat[i], b_hat[i], q, n, zetas)
            result = MathOperations.add_polynomials(result, multiplied, q)
        return result

    @staticmethod
    def multiply_square_matrix_by_vector_NTT(A_hat, b_hat, q, k, n, zetas):
        ''' multiply k x k matrix by k-length vector in NTT domain '''
        result = [[] for _ in range(k)]

        for row_A in range(len(A_hat)):
            result[row_A] = NTT.multiply_vectors_NTT(A_hat[row_A], b_hat, q, k, n, zetas)

        return result

    @staticmethod
    def generate_square_matrix_NTT_from_ro(ro, q, k, n):
        A_hat = []
        for i in range(k):
            row = []
            for j in range(k):
                polynomial = NTT.sampleNTT(ro,j,i,n,q)
                row.append(polynomial)
            A_hat.append(row)
        return A_hat