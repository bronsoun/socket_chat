import random

def isPrime(n):
    if n % 2 == 0:
        return n == 2
    d = 3
    while d * d <= n and n % d != 0:
        d += 2
    return d * d > n

def random_st(a, b):
    rand = random.randrange(a, b)
    while isPrime(rand) == False:
        rand = random.randrange(a, b)
    print(rand)
