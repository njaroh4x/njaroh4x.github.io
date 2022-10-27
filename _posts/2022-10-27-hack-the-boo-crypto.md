---
layout: post
title: "Hack The Boo 2022 - crypto"
categories: ["ctf", "HackTheBoo2022"]
---

## Gonna-Lift-Em-All

> Quick, there's a new custom Pokemon in the bush called "The Custom Pokemon". Can you find out what its weakness is and capture it?

Competition started with a python code showing us how data of the Pokemon was encrypted, and data.txt file that provided encrypted flag.

```
from Crypto.Util.number import bytes_to_long, getPrime
import random

FLAG = b'HTB{??????????????????????????????????????????????????????????????????????}'

def gen_params():
  p = getPrime(1024)
  g = random.randint(2, p-2)
  x = random.randint(2, p-2)
  h = pow(g, x, p)
  return (p, g, h), x

def encrypt(pubkey):
  p, g, h = pubkey
  m = bytes_to_long(FLAG)
  y = random.randint(2, p-2)
  s = pow(h, y, p)
  return (g * y % p, m * s % p)

def main():
  pubkey, privkey = gen_params()
  c1, c2 = encrypt(pubkey)

  with open('data.txt', 'w') as f:
    f.write(f'p = {pubkey[0]}\ng = {pubkey[1]}\nh = {pubkey[2]}\n(c1, c2) = ({c1}, {c2})\n')


if __name__ == "__main__":
  main()
```

Challenge was scary at first, because initially I thought that it is El Gamal and tried to check the key generation security, however after longer looking at the code i saw that in the encryption schema there is multiplication, and not exponentation.

### Encryption schema

Encryption schema can be translated from the code as follows:

p <- random 1024 bit length prime
g <- random generator of multiplicative group modulo p

For convienience, lets assume that "\*" character means multiplication modulo p, and "\*\*" exponentation modulo p

x <- "private key" of encryption
h <- part of public key, equals g\*\*x

### Encryption:

y <- random number (sometimes called ephemeral key)

s <- h\*\*y

c1 <- g\*y  (notice: in tratitional El Gamal this is g\*\*y: (check [El Gamal](https://en.wikipedia.org/wiki/ElGamal_encryption)))

c2 <- m\*s

### Decrption
This cryptographic schema is weak, because you do not need to hold the secret key for decryption.

Decryption (and the method to obtain flag) is as follows (try yourself before moving further):

y <- (g\*\*-1)\*c1 (where \*\*-1 means inversion in multiplicative group modulo p)

s <- h\*\*y

m <- c2\*(s\*\*-1)


Python PoC code:
```
inv_g = pow(g,-1,p)
y = inv_g * c1 % p
s = pow(h, y, p)
inv_s = pow(s, -1, p)

from Crypto.Util import number
print(number.long_to_bytes(c2*inv_s % p))
```

## Fast Carmichael

> You are walking with your friends in search of sweets and discover a mansion in the distance. All your friends are too scared to approach the building, so you go on alone. As you walk down the street, you see expensive cars and math papers all over the yard. Finally, you reach the door. The doorbell says "Michael Fastcar". You recognize the name immediately because it was on the news the day before. Apparently, Fastcar is a famous math professor who wants to get everything done as quickly as possible. He has even developed his own method to quickly check if a number is a prime. The only way to get candy from him is to pass his challenge.

The challenge was given as a server source code:

```
def _isPrime(p):
    if p < 1:
        return False
    if (p.bit_length() <= 600) and (p.bit_length() > 1500):
        return False
    if not millerRabin(p, 300):
        return False

    return True
```

where millerRabin(p, 300) was implementation of Miller-Rabin primality test to all prime bases lesser than 300 ([definition here](https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test))

The task was to find p (with bit length between 600 and 1500) that is passing the Miller-Rabin primality test and is not a prime number. Such numbers are called pseudoprimes (composite numbers that pass principality tests). After little bit of googling and surfing Wikipedia, I found that there are Carmichael numbers, which are composite numbers that pass Miller-Rabin test. [Wikipedia article](https://en.wikipedia.org/wiki/Carmichael_number) provided the number that actually is with the valid length:

```
p = 29674495668685510550154174642905332730771991799853043350995075531276838753171770199594238596428121188033664754218345562493168782883
N = p*(313*(p-1)+1)*(353*(p-1)+1)
```


## Spooky RSA

> It was a Sunday evening when, after years, you managed to understand how RSA works. Unfortunately, that changed when the worst villain ever decided to dress up like RSA and scare people who wanted to learn more about cryptography. But his custom uniform has a hole in it. Can you find it?

With day 3 we got the encryption algorithm schema "disguised" as RSA (but wasn't close to it)

```
from random import randint

FLAG = b'HTB{????????????????????????????????????????????}'


def key_gen(bits):
    p, q = getStrongPrime(bits), getStrongPrime(bits)
    N = p * q
    return N, (p, q)


def encrypt(m, N, f):
    e1, e2 = randint(2, N - 2), randint(2, N - 2)
    c1 = (pow(f, e1, N) + m) % N
    c2 = (pow(f, e2, N) + m) % N
    return (e1, c1), (e2, c2)


def main():
    N, priv = key_gen(1024)

    m = bytes_to_long(FLAG)

    (e1, c1), (e2, c2) = encrypt(m, N, priv[0])

    with open('out.txt', 'w') as f:
        f.write(f'N = {N}\n(e1, c1) = ({e1}, {c1})\n(e2, c2) = ({e2}, {c2})\n')


if __name__ == "__main__":
    main()
```

The encryption schema is as follows (let's assume that all additions, multiplications and exponentations are modulo N):
p, q <- strong prime numbers
N <- p\*q
e1, e2 <- random number
c1 <- p\*\*e1 + m
c2 <- p\*\*e2 + m
encryption returns e1, e2, c1, c2

### How to decrypt

Since the only comparison between traditional RSA and "Spooky RSA" was the generation of N, i will not try to compare between those 2. The main weakness in this schema is that it gived 2 ciphertexts and the base of exponentiation is p (a divisor of N)

We can compute new c:

c <- c1 - c2 = p\*\*e1 - p\*\*e2 (the m reduces itself)

Because p and q are primes, and c is divisible by p, we know that GCD(c, N) = p

Knowing p, we can compute, e.g.:

m <- c1 - p\*\*e1

Python PoC:
```
from Crypto.Util import number

diff = (c1 - c2) % N

p = number.GCD(diff, N)
q = N // p

print(N == p*q)

d1 = (c1 - pow(p, e1, N))%N

print(number.long_to_bytes(d1))
```

## Whole Lotta Candy

> In a parallel universe, "trick-or-treat" is played by different rules. As technologies became more advanced and the demand for security researchers increased, the government decided to incorporate security concepts into every game and tradition. Instead of candy, kids have the choice of selecting a AES mode and encrypting their plaintext. If they somehow manage to find the FLAG, they get candy. Can you solve this basic problem for the toddlers of this universe?


This challenge touched my heart, because i played simillar game as I was a "toddler" in the world of IT (a.k.a. student) :--) .

You could choose mode of AES encryption, one of: ECB, CBC, CFB, OFB and CTR. Then you were given the flag ciphertext and an Oracle that encrypts any given plaintext. After inspecting the given source code, i found a vulnerability in CTR mode (the rest looked non-crackable since the IV was not given as output).

The CTR encryption mode is as follows:

![CTR-encryption](/assets/img/CTR_encryption.svg.png)

Security on this mode depends on the counter generator, which should be unique each time a message is encrypted, however the challenges implementation of CTR had fixed counter generator (which could be observed by asking Oracle twice for ciphertext and receiving the same result).

Braking of this unsecure mode can be done under Chosen Plaintext Attack, as follows:

- receive flag ciphertext
- encode plaintext "HTB{        }", and increase spaces until end of the ciphertexts match each other
- for each byte inside, compute byte of the FLAG cipher XOR byte of Plaintext cipher XOR ' '

This works, since each byte of cipher is calculater by XOR'ing the output of AES cipher with plaintext, and xoring 2 ciphertext from the same stream and xoring it with the known plaintext byte, gives the original message (output from AES stream cipher is reduced)

Unfortunately, my code is too messy to share, but I encourage anyone to explore this path on its own.

## AHS512

> The most famous candy maker in town has developed a secret formula to make sensational and unique candies by just giving the name of the candy. He even added a pinch of randomness to his algorithm to make it even more interesting. As his trusted friend and security enthousiast he has asked you to test it for him. Can you find a bug?

This challenge was good PoC of why using a non-colision resistant function or operation on data before hashing makes whole hashing function non-collision resistant.

The "updated hashing function" from the challenge was given as follows:

```
class ahs512():

    def __init__(self, message):
        self.message = message
        self.key = self.generateKey()

    def generateKey(self):
        while True:
            key = randint(2, len(self.message) - 1)
            if len(self.message) % key == 0:
                break

        return key

    def transpose(self, message):
        transposed = [0 for _ in message]

        columns = len(message) // self.key

        for i, char in enumerate(message):
            row = i // columns
            col = i % columns
            transposed[col * self.key + row] = char
        return bytes(transposed)

    def rotate(self, message):
        return [((b >> 4) | (b << 3)) & 0xff for b in message]

    def hexdigest(self):
        transposed = self.transpose(self.message)
        rotated = self.rotate(transposed)
        return sha512(bytes(rotated)).hexdigest()
```

And the main function:

```
def main(s):
    sendMessage(s, WELCOME)

    original_message = b"pumpkin_spice_latte!"
    original_digest = ahs512(original_message).hexdigest()
    sendMessage(
        s,
        f"\nFind a message that generate the same hash as this one: {original_digest}\n"
    )

    while True:
        try:
            message = receiveMessage(s, "\nEnter your message: ")
            message = bytes.fromhex(message)
            print(message)
            digest = ahs512(message).hexdigest()
            print(digest)
            if ((original_digest == digest) and (message != original_message)):
                sendMessage(s, f"\n{FLAG}\n")
            else:
                sendMessage(s, "\nConditions not satisfied!\n")
```

There are 3 main observations:

- Each encryption generates new "random key", however the key space is small enough for smashing the same payload and waiting until matching key generates again.
- The transpose method is vulnerable to collisions by permutating the original message, but scripting permutation algorithm is more time consuming than the second vulnerable method.
- The rotate function is vulnerable to colisions by swapping the highest bit with the lowest one.

Quick draft on proof:

Let "b7b6b5b4b3b2b1b0" be the representation of byte b. Then the method rotate(b) produces:

```
rotate(b) == 0000b7b6b5b4 | b4b3b2b1(b0)000 = b4b3b2b1(b7 | b0)b6b5b4
```

If we swap either b7 or b0 in a way that (b7 \| b0) holds the original value, then the rotate function produces the same output.

Simple python PoC script (you can also swap only one vulnerable letter not all of them):
```
import binascii
original_message = b"pumpkin_spice_latte!"
spoofed_message = b""

for c in original_message:
    if (c & 1) | (c >> 7) and not (c & 1) & (c >> 7):
        print("vulnerable letter: " + chr(c))
        spoofed_message += bytes([c ^ 0x81])
    else:
        spoofed_message += bytes([c])

print("spoofed message: " + binascii.hexlify(spoofed_message).decode())
```
