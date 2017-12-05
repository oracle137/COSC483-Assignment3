import random
import hashlib


def powv1 (m, e, n):
   s = 1
   while e != 0:
      if e & 1:
         s = (s * m) % n
      e >>= 1
      m = (m * m) % n
   return s


def miller_rabin(n, k): #primetest

    # Implementation uses the Miller-Rabin Primality Test
    # The optimal number of rounds for this test is 40
    # See http://stackoverflow.com/questions/6325576/how-many-iterations-of-rabin-miller-should-i-use-for-cryptographic-safe-primes
    # for justification

    # If number is even, it's a composite number

    if n == 2:
        return True

    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
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


def readFile(funName, fileName):
    try:
        with open(fileName, 'r') as f:
            return f.read()
            
    except FileNotFoundError:
        print("{0}: key file: {1} not found".format(funName, fileName))
        exit()
    
def enc(keyFile, inputFile, outputFile):
    
    key = readFile('rsa-sign', keyFile).split('\n')
    if len(key) != 3:
        print("rsa-sign: invalide key file")
        exit()
    
    else: # Pull info from public key
        nBits = int(key[0])
        n = int(key[1])
        e = int(key[2])
    
    plainText = readFile('rsa-sign', inputFile)
    m = hashlib.sha256(plainText.encode()).hexdigest()


    # Add the padding to the plain text
    r = random.getrandbits(nBits // 2)
    r = r << (nBits - (nBits // 2) - 2)
    m = r + int(m,16)

    # Calculate the cypher text
    cipherText = powv1(m, e, n)
    # cipherText = pow(m,e,n)

    with open(outputFile, 'w+') as o:
        o.write(str(cipherText))

def dec(keyFile, messageFile, sigFile):
    
    key = readFile('rsa-validate', keyFile).split('\n')
    if len(key) != 3:
        print("rsa-validate: invalide key file")
        exit()
    
    else: # Pull the info from the private key
        nBits = int(key[0])
        n = int(key[1])
        d = int(key[2])
    
    cipherText = readFile('rsa-validate', sigFile)


    # Calculate the plain text with the padding
    m = powv1(int(cipherText), d, n)

    # Pull off the padding
    plainText = m & ((1 << nBits - (nBits // 2) - 2) - 1)

    originalText = readFile('rsa-validate', messageFile)
    m = int(hashlib.sha256(originalText.encode()).hexdigest(),16)

    if plainText == m:
        print('True')
    else:
        print('False')
    
def isPrime(n):
    if n < 2:
        return False
        
    d = n - 1
    t = 0
    while d % 2 == 0:
        d = d // 2 #Apparently the // operator explicitly does integer division. Cool.
        t += 1
        
    for k in range(5):
        a = random.randint(2, n - 2)
        v = pow(a, d, n)
        if v != 1:
            i = 0
            while v != (n - 1):
                if i == t - 1:
                    return False
                    
                else:
                    i += 1
                    v = pow(v, 2) % n
                    
    return True
    
def getRandPrime(n):
    prime = 1
    while not isPrime(prime):
        random.randint(2, n)
        
    return prime
    
def isCoprime(x, y):
    for z in range(2, min(x, y) + 1):
        if (x % z) == (y % z) == 0:
            return False
            
    return True
    
def getCoprime(order):
    for e in range(3, order):
        if isCoprime(e, order):
            return e
        
    print("didn't find coprime with {0}".format(order))
    exit()


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

# def keygen(pubKeyFile, privKeyFile, numBits):# COmment boxed in stuff if nothing works
#     p = number.getPrime(int(numBits))
#     q = number.getPrime(int(numBits))
#     #############################################
#     # numBits = int(numBits)
#     # p = random.getrandbits(numBits)
#     # q = random.getrandbits(numBits)
#     # while not miller_rabin(p,100) and not miller_rabin(q,100):
#     #     p = random.getrandbits(numBits)
#     #     q = random.getrandbits(numBits)
#     #############################################
#     n = p * q
#     order = (p - 1) * (q - 1)
#     e = getCoprime(order)
#     d = modinv(e, order)
#
#     with open(pubKeyFile, 'w+') as pub:
#         pub.write(str(numBits) + '\n' + str(n) + '\n' + str(e))
#
#     with open(privKeyFile, 'w+') as priv:
#         priv.write(str(numBits) + '\n' + str(n) + '\n' + str(d))
    