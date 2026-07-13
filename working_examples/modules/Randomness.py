from hashlib import shake_256
from random import randint
from modules.Conversion import Conversion

class Randomness:
    ''' Random and Pseudo-random functions used in Kyber '''

    @staticmethod
    def PRF(eta, s, b):
        seed = bytes(s + [b])
        shake = shake_256(seed)
        hash_bytes = shake.digest(64*eta)
        hash_ints = [int(byte) for byte in hash_bytes]
        return hash_ints
    
    @staticmethod
    def samplePolyCBD(q, n, eta, ints):
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
    def generate_vector(q, k, n, eta, randomness, n_counter):
        y = []
        for i in range(k):
            polynomial = Randomness.generate_polynomial(q, n, eta, randomness, n_counter)
            y.append(polynomial)
            n_counter += 1
        return y

    @staticmethod
    def generate_polynomial(q, n, eta, randomness, n_counter):
        ints = Randomness.PRF(eta, randomness, n_counter)
        polynomial = Randomness.samplePolyCBD(q, n, eta, ints)
        return polynomial
    
    @staticmethod
    def random_bytes(n):
        num_of_bytes = n // (n.bit_length()-1)
        ints = [randint(0, n-1) for _ in range(num_of_bytes)]
        return bytes(ints)
    
    @staticmethod
    def random_ints(n):
        num_of_bytes = n // (n.bit_length()-1)
        ints = [randint(0, n-1) for _ in range(num_of_bytes)]
        return ints
