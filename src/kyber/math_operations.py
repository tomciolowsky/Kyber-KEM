class MathOperations:
    ''' General mathematical functions for polynomials, vectors, and matrices. '''

    @staticmethod
    def add_polynomials(f:list[int], g:list[int], modulus:int) -> list[int]:
        """
        Add two polynomials f and g under a given modulus.

        Args:
            f (list[int]): Coefficients of the first polynomial.
            g (list[int]): Coefficients of the second polynomial.
            modulus (int): The modulus to apply to the coefficients.

        Returns:
            list[int]: Coefficients of the resulting polynomial after addition.
        """
        result_length = max(len(f), len(g))
        result = [0] * result_length
        for i in range(result_length):
            coefficient_f = f[i] if i < len(f) else 0
            coefficient_g = g[i] if i < len(g) else 0
            result[i] = (coefficient_f + coefficient_g) % modulus
        return result

    @staticmethod
    def subtract_polynomials(f:list[int], g:list[int], modulus:int) -> list[int]:
        """
        Subtract two polynomials f and g under a given modulus.

        Args:
            f (list[int]): Coefficients of the first polynomial.
            g (list[int]): Coefficients of the second polynomial.
            modulus (int): The modulus to apply to the coefficients.

        Returns:
            list[int]: Coefficients of the resulting polynomial after subtraction.
        """
        result_length = max(len(f), len(g))
        result = [0] * result_length
        for i in range(result_length):
            coefficient_f = f[i] if i < len(f) else 0
            coefficient_g = g[i] if i < len(g) else 0
            result[i] = (coefficient_f - coefficient_g) % modulus
        return result
    
    @staticmethod
    def multiply_polynomials(f:list[int], g:list[int], modulus:int) -> list[int]:
        """
        Multiply two polynomials f and g under a given modulus.

        Args:
            f (list[int]): Coefficients of the first polynomial.
            g (list[int]): Coefficients of the second polynomial.
            modulus (int): The modulus to apply to the coefficients.
        
        Returns:
            list[int]: Coefficients of the resulting polynomial after multiplication.
        """
        result_length = len(f) + len(g) - 1
        result = [0] * result_length
        for i in range(len(f)):
            for j in range(len(g)):
                result[i+j] = (result[i+j] + f[i] * g[j]) % modulus
        return result
    
    @staticmethod
    def ring_multiply_polynomials(f:list[int], g:list[int], modulus:int, n:int) -> list[int]:
        """
        Multiply two polynomials f and g under a given modulus in the ring of "polynomials modulo (X^n + 1)".

        Args:
            f (list[int]): Coefficients of the first polynomial.
            g (list[int]): Coefficients of the second polynomial.
            modulus (int): The modulus to apply to the coefficients.
            n (int): The degree of the ring.
        
        Returns:
            list[int]: Coefficients of the resulting polynomial after multiplication in the ring.
        """
        result = MathOperations.multiply_polynomials(f, g, modulus)
        if len(result) > n:
            for i in range(n, len(result)):
                result[i%n] = (result[i%n] - result[i]) % modulus
            result = result[:n]
        return result
    
    @staticmethod
    def add_vectors(a:list[list[int]], b:list[list[int]], modulus:int, k:int) -> list[list[int]]:
        """
        Add two vectors of polynomials a and b under a given modulus.

        Args:
            a (list[list[int]]): The first vector of polynomials.
            b (list[list[int]]): The second vector of polynomials.
            modulus (int): The modulus to apply to the coefficients.
            k (int): Length of each vector.
        
        Returns:
            list[list[int]]: The resulting vector of polynomials after addition.
        """
        result = []
        for i in range(k):
            result.append(MathOperations.add_polynomials(a[i], b[i], modulus))
        return result
    
    @staticmethod
    def multiply_vectors(a:list[list[int]], b:list[list[int]], modulus:int, k:int, n:int) -> list[int]:
        """
        Multiply two vectors of polynomials a and b under a given modulus in the ring of "polynomials modulo (X^n + 1)".
        
        (1 x k) * (k x 1) = (1 x 1) 

        Args:
            a (list[list[int]]): The first vector of polynomials.
            b (list[list[int]]): The second vector of polynomials.
            modulus (int): The modulus to apply to the coefficients.
            k (int): Length of each vector.
            n (int): The degree of the ring.

        Returns:
            list[int]: Coefficients of the resulting polynomial after multiplication.
        """
        result = []
        for i in range(k):
            multiplied = MathOperations.ring_multiply_polynomials(a[i], b[i], modulus, n)
            result = MathOperations.add_polynomials(result, multiplied, modulus)
        return result

    @staticmethod
    def mod_s(r:int, q:int) -> int:
        """
        Compute the symmetric modulo of r with respect to q.

        Args:
            r (int): The integer to be reduced.
            q (int): The modulus.
        """
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
    def round_q(x:int, q:int) -> int:
        """
        Round an integer x in the ring of integers modulo q to 0 or 1.

        Args:
            x (int): The integer to be rounded.
            q (int): The modulus.

        Returns:
            int: 0 or 1.
        """
        x_prime = MathOperations.mod_s(x, q)
        if -int(q/4) <= x_prime <= int(q/4):
            return 0
        else:
            return 1
        
    @staticmethod
    def round_polynomial(f:list[int], q:int) -> list[int]:
        """
        Round the coefficients of a polynomial f in the ring of integers modulo q to 0 or 1.

        Args:
            f (list[int]): Coefficients of the polynomial.
            q (int): The modulus.
        
        Returns:
            list[int]: Polynomial of 0s and 1s.
        """
        return [MathOperations.round_q(coefficient, q) for coefficient in f]

    @staticmethod
    def multiply_polynomial_by_scalar(f:list[int], scalar:int, modulus:int) -> list[int]:
        """
        Multiply a polynomial f by a scalar under a given modulus.

        Args:
            f (list[int]): Coefficients of the polynomial.
            scalar (int): The scalar to multiply by.
            modulus (int): The modulus to apply to the coefficients.

        Returns:
            list[int]: Coefficients of the scaled polynomial.
        """
        return [(coefficient * scalar) % modulus for coefficient in f]

    @staticmethod
    def multiply_square_matrix_by_vector(A:list[list[list[int]]], b:list[list[int]], modulus:int, k:int, n:int) -> list[list[int]]:
        """
        Multiply a square matrix A by a vector b under a given modulus in the ring of "polynomials modulo (X^n + 1)".

        (k x k) * (k x 1) = (k x 1)

        Args:
            A (list[list[list[int]]]): The square matrix of polynomials.
            b (list[list[int]]): The vector of polynomials.
            modulus (int): The modulus to apply to the coefficients.
            k (int): Size of the square matrix and length of the vector.
            n (int): The degree of the ring.

        Returns:
            list[list[int]]: The resulting vector of polynomials.
        """
        result = [[] for _ in range(k)]

        for row_A in range(k):
            result[row_A] = MathOperations.multiply_vectors(A[row_A], b, modulus, k, n)

        return result

    @staticmethod
    def matrix_transpose(A:list[list[list[int]]], k:int) -> list[list[list[int]]]:
        """
        Transpose a square matrix A of vectors of polynomials.

        Args:
            A (list[list[list[int]]]): The square matrix of polynomials.
            k (int): Size of the square matrix.

        Returns:
            list[list[list[int]]]: The transposed matrix of polynomials.
        """
        result = [[0] * k for _ in range(k)]
        for i in range(k):
            for j in range(k):
                result[j][i] = A[i][j]
        return result
    
    @staticmethod
    def integer_inverse_mod(n:int, q:int) -> int:
        """
        Compute the modular multiplicative inverse of n modulo q.

        Args:
            n (int): The integer to find the inverse of.
            q (int): The modulus.
        """
        return pow(n, -1, q)