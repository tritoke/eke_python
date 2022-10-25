import random
import math
from collections import namedtuple
from Crypto.Util.number import getPrime, long_to_bytes as l2b, bytes_to_long as b2l
from base64 import b64encode, b64decode as b64d


KEYSIZE_BITS = 2048

def randbits(bits: int) -> int:
    return random.SystemRandom().getrandbits(bits)

def randbytes(n: int) -> bytes:
    return l2b(random.SystemRandom().getrandbits(8 * n))

def flip_a_coin() -> bool:
    return bool(random.SystemRandom().getrandbits(1))

def b64e(x):
    return b64encode(x).decode()

class RSA:
    def __init__(self, p: int, q: int):
        self.p = p
        self.q = q
        self.n = p * q
        eulers_totient = (self.p - 1) * (self.q - 1)
        while True:
            e = randbits(KEYSIZE_BITS)
            if math.gcd(e, eulers_totient) == 1:
                # e is coprime so we're gucci
                self.e = e
                self.d = pow(self.e, -1, eulers_totient)
                break

    def gen():
        """
        create a new public/private RSA keypair
        """

        p = getPrime(KEYSIZE_BITS // 2)
        q = getPrime(KEYSIZE_BITS // 2)

        return RSA(p, q)

    def from_pub_key(e: int, n: int):
        # ugly hack
        rsa = RSA.gen()
        rsa.p = None
        rsa.q = None
        rsa.d = None

        rsa.e = e
        rsa.n = n

        return rsa

    def encrypt(self, message: int) -> int:
        return pow(message, self.e, self.n)

    def decrypt(self, message: int) -> int:
        return pow(message, self.d, self.n)

    def encode_public_key(self) -> (bytes, bytes):
        # add 1 to e 50% of the time
        e = self.e + 1 * flip_a_coin()
        return l2b(e)

