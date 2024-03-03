import random
from time import perf_counter
from typing import Tuple


class RSA:
    def _generate_primes(self, size: int):
        def is_prime(n):
            if n == 2:
                return True

            if n % 2 == 0:
                return False

            r, s = 0, n - 1
            while s % 2 == 0:
                r += 1
                s //= 2
            for _ in range(5):
                a = random.randrange(2, n - 1)
                x = pow(a, s, n)
                if x == 1 or x == n - 1:
                    continue
                for _ in range(r - 1):
                    x = pow(x, 2, n)
                    if x == n - 1:
                        break
                else:
                    return False
            return True

        primes = []

        for _ in range(2):
            while True:
                n = random.getrandbits(size)
                if is_prime(n):
                    break

            primes.append(n)

        return primes

    def generate_keys(self, size: int) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        """
        Tato metoda vrací nejdříve privátní klíč (n, d), poté veřejný (n, s)
        """

        def gcd(a: int, b: int) -> int:
            while b:
                a, b = b, a % b
            return a

        if size % 2 != 0:
            raise "Neplatná délka klíče, musí být násobkem 2"

        p, q = self._generate_primes(size // 2)

        n = p * q

        phi_n = (p - 1)*(q - 1)

        s = random.randint(2, phi_n - 1)
        while n % s == 0 or gcd(s, phi_n) != 1:
            s = random.randint(2, phi_n - 1)

        d = pow(s, -1, phi_n)

        return ((n, d), (n, s))

    def encrypt(self, public_key: Tuple[int, int], plaintext: str) -> str:
        n, s = public_key

        encrypted = ''
        for i, letter in enumerate(plaintext, 1):
            encrypted += str(pow(ord(letter), s, n))
            if i != len(plaintext):
                encrypted += "\n"

        return encrypted

    def decrypt(self, private_key: Tuple[int, int], ciphertext: str) -> str:
        n, d = private_key

        decrypted = ''
        for letter in ciphertext.split("\n"):
            decrypted += chr(pow(int(letter), d, n))

        return decrypted


if __name__ == "__main__":
    rsa = RSA()

    start = perf_counter()

    for i in [1024, 2048, 3072]:
        print(f"\nDélka klíče: {i}\n")
        prkey, pukey = rsa.generate_keys(i)
        print(f"Generování klíčů: {(perf_counter() - start):.2f}s")

        start = perf_counter()
        enc = rsa.encrypt(pukey, "Testovací text")
        print(f"Šifrování: {(perf_counter() - start):.2f}s")

        start = perf_counter()
        dec = rsa.decrypt(prkey, enc)
        print(f"Dešifrování: {(perf_counter() - start):.2f}s")
        print(dec)
