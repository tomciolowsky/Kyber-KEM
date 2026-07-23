from hashlib import shake_256
from random import randint
from .conversion import Conversion

class Randomness:
    ''' Random and Pseudo-random functions used in Kyber '''

    @staticmethod
    def PRF(eta:int, s:list[int], b:int) -> list[int]:
        """
        Generate a list of pseudo-random integers.

        Args:
            eta (int): The parameter for the centered binomial distribution.
            s (list[int]): The seed for the pseudo-random function.
            b (int): The counter for the pseudo-random function.

        Returns:
            list[int]: The resulting list of pseudo-random integers.
        """
        seed = bytes(s + [b])
        shake = shake_256(seed)
        hash_bytes = shake.digest(64*eta)
        hash_ints = [int(byte) for byte in hash_bytes]
        return hash_ints
    
    @staticmethod
    def samplePolyCBD(q:int, n:int, eta:int, ints:list[int]) -> list[int]:
        """
        Sample a polynomial from the centered binomial distribution.

        Args:
            q (int): The modulus.
            n (int): The size of the polynomial.
            eta (int): The parameter for the centered binomial distribution.
            ints (list[int]): The input integers to sample from.

        Returns:
            list[int]: The resulting pseudo-random polynomial.
        """
        b = Conversion.ints_to_bits(ints)

        f = [0] * n
        for i in range(n):
            x = 0
            y = 0
            for j in range(eta):
                x += b[2*i*eta + j]
                y += b[2*i*eta + eta + j]
            f[i] = (x - y) % q
        return f
    
    @staticmethod
    def generate_vector(q:int, k:int, n:int, eta:int, randomness:list[int], n_counter:int) -> list[list[int]]:
        """
        Generate a k-length vector of pseudo-random polynomials.

        Args:
            q (int): The modulus.
            k (int): The length of the vector.
            n (int): The size of the polynomials.
            eta (int): The parameter for the centered binomial distribution.
            randomness (list[int]): The randomness seed.
            n_counter (int): The counter for the randomness seed.

        Returns:
            list[list[int]]: The resulting vector of polynomials.
        """
        y = []
        for i in range(k):
            polynomial = Randomness.generate_polynomial(q, n, eta, randomness, n_counter)
            y.append(polynomial)
            n_counter += 1
        return y

    @staticmethod
    def generate_polynomial(q:int, n:int, eta:int, randomness:list[int], n_counter:int) -> list[int]:
        """
        Generate a pseudo-random polynomial.

        Args:
            q (int): The modulus.
            n (int): The size of the polynomial.
            eta (int): The parameter for the centered binomial distribution.
            randomness (list[int]): The randomness seed.
            n_counter (int): The counter for the randomness seed.

        Returns:
            list[int]: The resulting polynomial.
        """
        ints = Randomness.PRF(eta, randomness, n_counter)
        polynomial = Randomness.samplePolyCBD(q, n, eta, ints)
        return polynomial
    
    @staticmethod
    def random_bytes(n:int) -> bytes:
        """
        Generate n / bit_len(n)-1 random bytes
        """
        num_of_bytes = n // (n.bit_length()-1)
        ints = [randint(0, n-1) for _ in range(num_of_bytes)]
        return bytes(ints)

    @staticmethod
    def random_ints(n:int) -> list[int]:
        """
        Generate n / bit_len(n)-1 random integers
        """
        num_of_ints = n // (n.bit_length()-1)
        ints = [randint(0, n-1) for _ in range(num_of_ints)]
        return ints