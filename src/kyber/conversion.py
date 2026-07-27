class Conversion:
    ''' Functions for converting between bitstrings, polynomials, and bytes representations. '''
    
    @staticmethod
    def bitstring_to_polynomial(m:str, n:int) -> list[int]:
        """
        Args:
            m (str): The bitstring to convert.
            n (int): The size of the polynomial.
        """
        f = [0] * n
        for i in range(n):
            if m[i] == "1":
                f[i] = 1
        return f

    @staticmethod
    def polynomial_to_bitstring(f:list[int], n:int) -> str:
        """
        Args:
            f (list[int]): The polynomial to convert.
            n (int): The size of the polynomial.
        """
        m = ""
        for i in range(n):
            if f[i] == 1:
                m += "1"
            else:
                m += "0"
        return m
    
    @staticmethod
    def text_in_bytes_to_bitstring(text_in_bytes:bytes, n:int) -> str:
        """
        Args:
            text_in_bytes (bytes): The bytes to convert.
            n (int): The length of the bitstring.
        """
        bitstring = ""
        
        for byte in text_in_bytes:
            binary_string = format(byte, '08b')
            bitstring += binary_string

        if len(bitstring) < n:
            bitstring += '0' * (n - len(bitstring))

        return bitstring
    
    @staticmethod
    def bitstring_to_text_in_bytes(bitstring:str, n:int) -> bytes:
        """
        Args:
            bitstring (str): The bitstring to convert.
            n (int): The length of the bitstring.
        """
        chunks_8bits = [bitstring[i:i+8] for i in range(0, n, 8)]
        bytes_list = bytes(int(byte, 2) for byte in chunks_8bits)
    
        return bytes_list
    
    @staticmethod
    def ints_to_bits(ints:list[int]) -> list[int]:
        """
        Args:
            ints (list[int]): The list of integers to convert.
        """
        bit_list = [0]*(len(ints)*8)
        for i in range(len(ints)):
            for j in range(8):
                bit_list[i*8 + j] = ints[i] % 2
                ints[i] = ints[i] // 2
        return bit_list

    @staticmethod
    def bits_to_bytes(bits:list[int]) -> bytes:
        """
        Args:
            bits (list[int]): The list of bits to convert.
        """
        b_bytes = bytearray()
        for i in range(0, len(bits), 8):
            byte_val = sum(bits[i + j] << j for j in range(8))
            b_bytes.append(byte_val)
        return bytes(b_bytes)

    @staticmethod
    def bytes_to_bits(b_bytes:bytes) -> list[int]:
        """
        Args:
            b_bytes (bytes): The bytes to convert.
        """
        bits = []
        for byte in b_bytes:
            for j in range(8):
                bits.append((byte >> j) & 1)
        return bits

    @staticmethod
    def byte_encode(ints:list[int], d:int) -> bytes:
        """
        Encode a list of integers into a byte array.

        Args:
            ints (list[int]): The list of integers to encode.
            d (int): The number of bits to represent each coefficient.
        """
        bits = []
        for x in ints:
            a = x % (1 << d)
            for j in range(d):
                bits.append((a >> j) & 1)
        return Conversion.bits_to_bytes(bits)

    @staticmethod
    def vector_byte_encode(vec:list[list[int]], d:int) -> bytes:
        """
        Encode a vector of polynomials into a bytes.

        Args:
            vec (list[list[int]]): The vector of polynomials to encode.
            d (int): The number of bits to represent each coefficient.
        """
        byte_array = bytearray()
        for polynomial in vec:
            byte_array.extend(Conversion.byte_encode(polynomial, d))
        return bytes(byte_array)

    @staticmethod
    def byte_decode(b_bytes:bytes, d:int) -> list[int]:
        """
        Decode a byte array into a list of integers.

        Args:
            b_bytes (bytes): The byte array to decode.
            d (int): The number of bits to represent each coefficient.
        """
        bits = Conversion.bytes_to_bits(b_bytes)
        n = len(bits) // d
        ints = []
        for i in range(n):
            val = sum(bits[i * d + j] << j for j in range(d))
            ints.append(val)
        return ints

    @staticmethod
    def vector_byte_decode(b_bytes:bytes, k:int, d:int) -> list[list[int]]:
        """
        Decode a byte array into a k-length vector of polynomials.

        Args:
            b_bytes (bytes): The byte array to decode.
            n (int): The size of each polynomial.
            k (int): The length of the vector.
            d (int): The number of bits to represent each coefficient.
        """
        poly_byte_len = (256 * d) // 8
        vec = []
        for i in range(k):
            chunk = b_bytes[i * poly_byte_len : (i + 1) * poly_byte_len]
            vec.append(Conversion.byte_decode(chunk, d))
        return vec