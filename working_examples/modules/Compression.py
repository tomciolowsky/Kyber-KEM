class Compression:
    ''' Functions used for compression / decompression '''

    @staticmethod
    def compress_integer(x, q, d):
        y = (((2**d) * x) + (q//2)) // q
        return y%(2**d)

    @staticmethod
    def decompress_integer(y, q, d):
        x = ((q * y) + (2**d // 2)) // (2**d)
        return x%q

    @staticmethod
    def compress_polynomial(f, q, d):
        return [Compression.compress_integer(coefficient, q, d) for coefficient in f]

    @staticmethod
    def decompress_polynomial(f, q, d):
        return [Compression.decompress_integer(coefficient, q, d) for coefficient in f]

    @staticmethod
    def compress_vector(a, q, d):
        return [Compression.compress_polynomial(polynomial, q, d) for polynomial in a]

    @staticmethod
    def decompress_vector(a, q, d):
        return [Compression.decompress_polynomial(polynomial, q, d) for polynomial in a]