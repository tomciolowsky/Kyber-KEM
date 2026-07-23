class MathOperations:
    ''' General mathematical functions for polynomials, vectors, and matrices. '''

    @staticmethod
    def add_polynomials(f, g, modulus):
        result_length = max(len(f), len(g))
        result = [0] * result_length
        for i in range(result_length):
            coefficient_f = f[i] if i < len(f) else 0
            coefficient_g = g[i] if i < len(g) else 0
            result[i] = (coefficient_f + coefficient_g) % modulus
        return result

    @staticmethod
    def subtract_polynomials(f, g, modulus):
        result_length = max(len(f), len(g))
        result = [0] * result_length
        for i in range(result_length):
            coefficient_f = f[i] if i < len(f) else 0
            coefficient_g = g[i] if i < len(g) else 0
            result[i] = (coefficient_f - coefficient_g) % modulus
        return result
    
    @staticmethod
    def multiply_polynomials(f, g, modulus):
        result_length = len(f) + len(g) - 1
        result = [0] * result_length
        for i in range(len(f)):
            for j in range(len(g)):
                result[i+j] = (result[i+j] + f[i] * g[j]) % modulus
        return result
    
    @staticmethod
    def ring_multiply_polynomials(f, g, modulus, n):
        result = MathOperations.multiply_polynomials(f, g, modulus)
        if len(result) > n:
            for i in range(n, len(result)):
                result[i%n] = (result[i%n] - result[i]) % modulus
            result = result[:n]
        return result
    
    @staticmethod
    def add_vectors(a, b, modulus, k):
        result = []
        for i in range(k):
            result.append(MathOperations.add_polynomials(a[i], b[i], modulus))
        return result
    
    @staticmethod
    def multiply_vectors(a, b, modulus, k, n):
        result = []
        for i in range(k):
            multiplied = MathOperations.ring_multiply_polynomials(a[i], b[i], modulus, n)
            result = MathOperations.add_polynomials(result, multiplied, modulus)
        return result

    @staticmethod
    def mod_s(r, q):
        r = r % q
        if q % 2 == 0:
            if r <= q // 2:
                result = r
            else:
                result = r - q
        else:
            if r <= (q - 1) // 2:
                result = r
            else:
                result = r - q
        return result

    @staticmethod
    def round_q(x, q):
        x_prime = MathOperations.mod_s(x, q)
        if -int(q/4) <= x_prime <= int(q/4):
            return 0
        else:
            return 1
        
    @staticmethod
    def round_polynomial(f, q):
        return [MathOperations.round_q(coefficient, q) for coefficient in f]

    @staticmethod
    def multiply_polynomial_by_scalar(f, scalar, modulus):
        return [(coefficient * scalar) % modulus for coefficient in f]

    @staticmethod
    def multiply_square_matrix_by_vector(A, b, modulus, k, n):
        result = [[] for _ in range(k)]

        for row_A in range(k):
            result[row_A] = MathOperations.multiply_vectors(A[row_A], b, modulus, k, n)

        return result

    @staticmethod
    def matrix_transpose(A, k, n):
        result = [[0] * k for _ in range(n)]
        for i in range(k):
            for j in range(n):
                result[j][i] = A[i][j]
        return result
    
    @staticmethod
    def integer_inverse_mod(n, q):
        return pow(n, -1, q)