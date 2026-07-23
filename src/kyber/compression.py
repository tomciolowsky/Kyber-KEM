class Compression:
    ''' Functions used for compression / decompression '''

    @staticmethod
    def compress_integer(x:int, q:int, d:int) -> int:
        """
        Args:
            x (int): The integer to compress.
            q (int): The modulus.
            d (int): The bit width.
        """
        y = (((2**d) * x) + (q//2)) // q
        return y%(2**d)

    @staticmethod
    def decompress_integer(y:int, q:int, d:int) -> int:
        """
        Args:
            y (int): The integer to decompress.
            q (int): The modulus.
            d (int): The bit width.
        """
        x = ((q * y) + (2**d // 2)) // (2**d)
        return x%q

    @staticmethod
    def compress_polynomial(f:list[int], q:int, d:int) -> list[int]:
        """
        Args:
            f (list[int]): The polynomial to compress.
            q (int): The modulus.
            d (int): The bit width.
        """
        return [Compression.compress_integer(coefficient, q, d) for coefficient in f]

    @staticmethod
    def decompress_polynomial(f:list[int], q:int, d:int) -> list[int]:
        """
        Args:
            f (list[int]): The polynomial to decompress.
            q (int): The modulus.
            d (int): The bit width.
        """
        return [Compression.decompress_integer(coefficient, q, d) for coefficient in f]

    @staticmethod
    def compress_vector(a:list[list[int]], q:int, d:int) -> list[list[int]]:
        """
        Args:
            a (list[list[int]]): The vector to compress.
            q (int): The modulus.
            d (int): The bit width.
        """
        return [Compression.compress_polynomial(polynomial, q, d) for polynomial in a]

    @staticmethod
    def decompress_vector(a:list[list[int]], q:int, d:int) -> list[list[int]]:
        """
        Args:
            a (list[list[int]]): The vector to decompress.
            q (int): The modulus.
            d (int): The bit width.
        """
        return [Compression.decompress_polynomial(polynomial, q, d) for polynomial in a]