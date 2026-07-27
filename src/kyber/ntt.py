from hashlib import shake_128
from .math_operations import MathOperations

class NTT:
    ''' Functions for working in the Kyber Number Theoretic Transform **(NTT)** domain. '''

    @staticmethod
    def brv(v:int, n:int) -> int:
        """
        Compute the integer value of reversed bit representation of v.

        Args:
            v (int): The integer to be reversed, from range [0, n//2).
            n (int): The upper limit of the range.
        """
        bits_in_n = n.bit_length() - 1
        binary_string = format(v, f'0{bits_in_n}b')
        reversed_binary_string = binary_string[::-1]
        reversed_v = int(reversed_binary_string, 2)
        return reversed_v

    @staticmethod
    def generate_zetas_for_NTT(n:int, z:int, q:int) -> list[int]:
        """
        Generate the zeta values used for computing NTT and inverse NTT.

        Args:
            n (int): The size of the zetas array.
            z (int): The primitive n-th root of unity modulo q.
            q (int): The modulus.
        """
        zetas = [0] * n
        
        for i in range(n):
            zetas[i] = (z**NTT.brv(i, n))%q
        return zetas

    @staticmethod
    def generate_zetas_for_multiply(n:int, z:int, q:int) -> list[int]:
        """
        Generate the zeta values used for multiplication in the NTT domain.

        Args:
            n (int): The size of the zetas array.
            z (int): The primitive n-th root of unity modulo q.
            q (int): The modulus.
        """
        zetas = [0] * n
        
        for i in range(n):
            zetas[i] = (z**(2*NTT.brv(i, n) + 1))%q
        return zetas

    @staticmethod
    def sampleNTT(seed:bytes, n:int, q:int) -> list[int]:
        """
        Generate a pseudorandom polynomial from the NTT domain.

        Args:
            seed (bytes): The seed for the random number generator.
            n (int): The size of the polynomial.
            q (int): The modulus.

        Returns:
            list[int]: The sampled polynomial.
        """
        shake = shake_128(seed)
        stream = shake.digest(n*4)
        j = 0
        offset = 0
        a_hat = [0] * n
        while j < n:
            
            hash_bytes = stream[offset*3:(offset+1)*3]
            offset += 1
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
    def computeNTT(f:list[int], q:int, n:int, zetas:list[int]) -> list[int]:
        '''
        Compute NTT of a polynomial

        Args:
            f (list[int]): The polynomial to transform.
            q (int): The modulus.
            n (int): The size of the polynomial.
            zetas (list[int]): The precomputed zeta values for NTT.

        Returns:
            list[int]: The polynomial in NTT domain.
        '''
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
    def computeNTT_inverse(f_hat:list[int], q:int, n:int, n_inv:int, zetas:list[int]) -> list[int]:
        """
        Compute inverse NTT of a polynomial.

        Args:
            f_hat (list[int]): The polynomial in NTT domain.
            q (int): The modulus.
            n (int): The size of the polynomial.
            n_inv (int): The modular multiplicative inverse of n modulo q.
            zetas (list[int]): The precomputed zeta values for inverse NTT.

        Returns:
            list[int]: The polynomial in standard domain.
        """
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
    def compute_vector_NTT(a:list[list[int]], q:int, k:int, n:int, zetas:list[int]) -> list[list[int]]:
        '''
        Compute NTT of k-length vector a

        Args:
            a (list[list[int]]): The vector of polynomials to transform.
            q (int): The modulus.
            k (int): The length of the vector.
            n (int): The size of the polynomials.
            zetas (list[int]): The precomputed zeta values for NTT.
        
        Returns:
            list[list[int]]: The vector of polynomials in NTT domain.
        '''
        a_hat = [[] for _ in range(k)]
        for i in range(k):
            polynomial_hat = NTT.computeNTT(a[i], q, n, zetas)
            a_hat[i] = polynomial_hat
        return a_hat

    @staticmethod
    def compute_vector_NTT_inverse(a_hat:list[list[int]], q:int, k:int, n:int, n_inv:int, zetas:list[int]) -> list[list[int]]:
        '''
        Compute inverse NTT of k-length vector a_hat

        Args:
            a_hat (list[list[int]]): The vector of polynomials in NTT domain.
            q (int): The modulus.
            k (int): The length of the vector.
            n (int): The size of the polynomials.
            n_inv (int): The modular multiplicative inverse of n modulo q.
            zetas (list[int]): The precomputed zeta values for inverse NTT.

        Returns:
            list[list[int]]: The vector of polynomials in standard domain.
        '''
        a = [0]*k
        for i in range(k):
            polynomial = NTT.computeNTT_inverse(a_hat[i], q, n, n_inv, zetas)
            a[i] = polynomial
        return a

    @staticmethod
    def base_case_multiply(a0:int, a1:int, b0:int, b1:int, q:int, z:int) -> tuple[int, int]:
        """
        Multiply two degree-one polynomials with respect to a quadratic modulus

        Args:
            a0 (int): Coefficient of x^0 in the first polynomial.
            a1 (int): Coefficient of x^1 in the first polynomial.
            b0 (int): Coefficient of x^0 in the second polynomial.
            b1 (int): Coefficient of x^1 in the second polynomial.
            q (int): The modulus.
            z (int): The quadratic modulus.
        """
        c0 = (a0*b0 + a1*b1*z) % q
        c1 = (a0*b1 + a1*b0) % q
        return c0, c1

    @staticmethod
    def multiplyNTT(f_hat:list[int], g_hat:list[int], q:int, n:int, zetas:list[int]) -> list[int]:
        '''
        Multiply two polynomials in NTT domain

        Args:
            f_hat (list[int]): The first polynomial in NTT domain.
            g_hat (list[int]): The second polynomial in NTT domain.
            q (int): The modulus.
            n (int): The size of the polynomials.
            zetas (list[int]): The precomputed zeta values for multiplication in NTT domain.
        '''
        h = [0] * n
        for i in range(n//2):
            a0 = f_hat[2*i]
            a1 = f_hat[2*i + 1]
            b0 = g_hat[2*i]
            b1 = g_hat[2*i + 1]
            h[2*i], h[2*i + 1] = NTT.base_case_multiply(a0, a1, b0, b1, q, zetas[i])

        return h

    @staticmethod
    def multiply_vectors_NTT(a_hat:list[list[int]], b_hat:list[list[int]], q:int, k:int, n:int, zetas:list[int]) -> list[int]:
        '''
        Multiply two k-length vectors in NTT domain

        (1 x k) * (k x 1) = (1 x 1)

        Args:
            a_hat (list[list[int]]): The first vector of polynomials in NTT domain.
            b_hat (list[list[int]]): The second vector of polynomials in NTT domain.
            q (int): The modulus.
            k (int): The length of the vectors.
            n (int): The size of the polynomials.
            zetas (list[int]): The precomputed zeta values for multiplication in NTT domain.

        Returns:
            list[int]: The resulting polynomial in NTT domain.
        '''
        result = []
        for i in range(k):
            multiplied = NTT.multiplyNTT(a_hat[i], b_hat[i], q, n, zetas)
            result = MathOperations.add_polynomials(result, multiplied, q)
        return result

    @staticmethod
    def multiply_square_matrix_by_vector_NTT(A_hat:list[list[list[int]]], b_hat:list[list[int]], q:int, k:int, n:int, zetas:list[int]) -> list[list[int]]:
        '''
        Multiply a k x k matrix by a k-length vector in NTT domain

        (k x k) * (k x 1) = (k x 1)

        Args:
            A_hat (list[list[list[int]]]): The k x k matrix of polynomials in NTT domain.
            b_hat (list[list[int]]): The k-length vector of polynomials in NTT domain.
            q (int): The modulus.
            k (int): The size of the square matrix and the length of the vector.
            n (int): The size of the polynomials.
            zetas (list[int]): The precomputed zeta values for multiplication in NTT domain.

        Returns:
            list[list[int]]: The resulting k-length vector of polynomials in NTT domain.
        '''
        result = [[] for _ in range(k)]

        for row_A in range(len(A_hat)):
            result[row_A] = NTT.multiply_vectors_NTT(A_hat[row_A], b_hat, q, k, n, zetas)

        return result

    @staticmethod
    def generate_square_matrix_NTT_from_ro(ro:list[int], q:int, k:int, n:int) -> list[list[list[int]]]:
        """
        Generate a k x k matrix of polynomials in NTT domain from a given seed.

        Args:
            ro (list[int]): The seed for the random number generator.
            q (int): The modulus.
            k (int): The size of the square matrix.
            n (int): The size of the polynomials.

        Returns:
            list[list[list[int]]]: The resulting k x k matrix of polynomials in NTT domain.
        """
        A_hat = []
        for i in range(k):
            row = []
            for j in range(k):
                seed = bytes(ro+[j]+[i])
                polynomial = NTT.sampleNTT(seed, n, q)
                row.append(polynomial)
            A_hat.append(row)
        return A_hat