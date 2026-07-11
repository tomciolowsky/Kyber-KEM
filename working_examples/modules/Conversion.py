class Conversion:
    ''' Functions for converting between bitstrings, polynomials, and bytes representations. '''
    
    @staticmethod
    def bitstring_to_polynomial(m, n):
        f = [0] * n
        for i in range(n):
            if m[i] == "1":
                f[i] = 1
        return f

    @staticmethod
    def polynomial_to_bitstring(f, n):
        m = ""
        for i in range(n):
            if f[i] == 1:
                m += "1"
            else:
                m += "0"
        return m
    
    @staticmethod
    def text_in_bytes_to_bitstring(text_in_bytes, n):
        bitstring = ""
        
        for byte in text_in_bytes:
            binary_string = format(byte, '08b')
            bitstring += binary_string

        if len(bitstring) < n:
            bitstring += '0' * (n - len(bitstring))

        return bitstring
    
    @staticmethod
    def bitstring_to_text_in_bytes(bitstring, n):
        chunks_8bits = [bitstring[i:i+8] for i in range(0, n, 8)]
        bytes_list = bytes(int(byte, 2) for byte in chunks_8bits)
    
        return bytes_list