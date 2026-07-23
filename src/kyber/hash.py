from hashlib import sha3_256, sha3_512, shake_256 

class Hash:
    ''' Hash functions used in Kyber '''

    @staticmethod
    def H(s:bytes) -> list[int]:
        """
        Hash function H: SHA3-256

        Args:
            s (bytes): Seed bytes to hash.

        Returns:
            list[int]: List of integers representing the hash.
        """
        sha = sha3_256(s)
        hash_bytes = sha.digest()
        hash_ints = [int(byte) for byte in hash_bytes]
        return hash_ints
        
    @staticmethod
    def J(s:bytes) -> list[int]:
        """
        Hash function J: SHAKEd-256
        
        Args:
            s (bytes): Seed bytes to hash.

        Returns:
            list[int]: List of integers representing the hash.
        """
        shake = shake_256(s)
        hash_bytes = shake.digest(32)
        hash_ints = [int(byte) for byte in hash_bytes]
        return hash_ints

    @staticmethod
    def G(c:bytes) -> tuple[list[int], list[int]]:
        """
        Hash function G: SHA3-512
        
        Args:
            c (bytes): Seed bytes to hash.

        Returns:
            tuple[list[int], list[int]]: A tuple containing two lists of integers representing the hash.
        """
        sha = sha3_512(c)
        hash_bytes = sha.digest()
        hash_ints = [int(byte) for byte in hash_bytes]
        a = hash_ints[:32]
        b = hash_ints[32:]
        return (a, b)