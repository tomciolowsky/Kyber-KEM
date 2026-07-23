from hashlib import sha3_256, sha3_512, shake_256 

class Hash:
    ''' Hash functions used in Kyber '''

    @staticmethod
    def H(s):
        sha = sha3_256(s)
        hash_bytes = sha.digest()
        hash_ints = [int(byte) for byte in hash_bytes]
        return hash_ints
        
    @staticmethod
    def J(s):
        shake = shake_256(s)
        hash_bytes = shake.digest(32)
        hash_ints = [int(byte) for byte in hash_bytes]
        return hash_ints

    @staticmethod
    def G(c):
        sha = sha3_512(c)
        hash_bytes = sha.digest()
        hash_ints = [int(byte) for byte in hash_bytes]
        a = hash_ints[:32]
        b = hash_ints[32:]
        return (a, b)