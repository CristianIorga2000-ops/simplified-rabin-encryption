import binascii
import random

from Crypto.Util import number


def egcd(a, b):
    """
    Extended Euclidian Algorithm for gcd
    """
    if a == 0:
        return b, 0, 1
    else:
        gcd, y, x = egcd(b % a, a)
        return gcd, x - (b // a) * y, y


def is_prime(n):
    """
    Primality test
    """
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(n ** 0.5), 2):
        if n % i == 0:
            return False
    return True


def generate_keys(num_of_bits):
    """
    Generate as large as num_of_bits prime numbers for keys
    """
    p, q = 0, 0

    while p % 4 != 3:
        p = number.getPrime(num_of_bits)

    while q % 4 != 3:
        q = number.getPrime(num_of_bits)

    n = p * q

    return n, p, q


def encryption(plaintext, n):
    """
    c = m^2 mod n
    :param n: public key n = p * q
    """
    plaintext = padding(plaintext)
    return plaintext ** 2 % n


def padding(plaintext):
    # convert to a bit string
    binary_str = ''.join(format(ord(i), '08b') for i in plaintext)

    # convert back to integer
    decimal_msg = int(binary_str, 2)

    return decimal_msg


def decrypt(message: int, p: int, q: int):
    # Step 1: find a b so that a*p + b*q = 1
    _, a, b = egcd(p, q)

    # Step 2: calculate r and s
    r = pow(message, (p + 1) // 4, p)
    s = pow(message, (q + 1) // 4, q)

    # Step 3: calculate X and Y
    X = (a * p * r + b * q * s) % p
    Y = (a * p * r - b * q * s) % q

    return [X, -X, Y, -Y]


# decide which answer to choose
def choose(lst: list[int]):
    def byteToString(n):
        try:
            return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode()
        except:
            return "."

    return list(filter(lambda n: n != ".", map(lambda n: byteToString(n), lst)))


if __name__ == '__main__':
    mess = "Bu n"
    lst = []
    encrypted_m = 0
    decrypted_ops = ""
    pk, sk1, sk2 = 0, 0, 0
    while (lst.__len__() != 1):
        pk, sk1, sk2 = generate_keys(64)

        encrypted_m = encryption(mess, pk)

        decrypted_ops = decrypt(encrypted_m, sk1, sk2)

        lst = choose(decrypt(encrypted_m, sk1, sk2))

    print("Key generation succesfull.\np = " + str(sk1) + "\nq = " + str(sk2))
    print("N = " + str(pk))

    print("\n\n Message is : " + mess)

    print("Decimal form of encrypted message: " + str(encrypted_m))

    print(str(lst))
    # print("Decrypted message variants:\n" + str(x) + "\n" + str(mx) + "\n" + str(y) + "\n" + str(my) + "\n")
