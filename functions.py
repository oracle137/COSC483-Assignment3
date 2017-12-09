import random
import hashlib
from Crypto.Util import number
from multiprocessing import Process
import operator
import os
from Crypto.Cipher import AES
import sys
from multiprocessing import Process,Manager, Pool
import multiprocessing as mp
import binascii

# Credit to Chris Coe for this code
# Requires pycrypto, which does indeed work for python3
blocksize = 128
keysize = 256


def encrypt(key, raw):
    '''
    Takes in a string of clear text and encrypts it.
    @param raw: a string of clear text
    @return: a string of encrypted ciphertext
    '''
    if (raw is None) or (len(raw) == 0):
        raise ValueError('input text cannot be null or empty set')
    cipher = AES.new(key[:32], AES.MODE_ECB)
    ciphertext = cipher.encrypt(raw)
    return ciphertext


def decrypt(key, enc):
    if (enc is None) or (len(enc) == 0):
        raise ValueError('input text cannot be null or empty set')
    cipher = AES.new(key, AES.MODE_ECB)
    enc = cipher.decrypt(enc)
    return enc


def padding(raw):

    lraw = len(raw[-1])*8
    modraw = lraw % blocksize
    remainder = blocksize - modraw
    # print("modraw:",modraw)
    if modraw == 0:
        remainder = 128
        paddingstr = (int(remainder/8)).to_bytes(int(remainder/8),byteorder="big",signed=False)* int(remainder/8)
        # print("Padding str",paddingstr)
        # raw.append(bytes("\0", encoding='utf-8') * int(((remainder)/(len(bytes("\0", encoding='utf-8')) * 8))))
        raw.append(paddingstr)
    else:
        # paddingstr = bytes(str(remainder),encoding='utf-8') * int(((remainder)/(len(bytes(str(remainder), encoding='utf-8')) * 8)))
        paddingstr = (int(remainder / 8)).to_bytes(1, byteorder="big", signed=False) * int(remainder/8)
        # print(paddingstr)
        # print("Padding str", int(remainder / 8))
        raw[-1] = raw[-1] + paddingstr

    return raw


def remove_padding(raw):
    #needs some love
    i = int.from_bytes(raw[-1][-1:],byteorder="big",signed=False)
    raw[-1] = raw[-1][:16 - i]
    return raw


def XOR(a, b):# https://stackoverflow.com/questions/29408173/byte-operations-xor-in-python
    return bytes(map(operator.xor, a, b))


# Create a function called "chunks" with two arguments, l and n:
def chunks(l, n): # https://chrisalbon.com/python/break_list_into_chunks_of_e
    # For item i in a range that is a length of l,
    for i in range(0, len(l), n):
        # Create an index range for l of n items:
        yield l[i:i+n]


def IV_Gen():
    return os.urandom(int(blocksize/8))

def cbc_sign(key,raw,iv):
    ct_split = []
    ct_split.append(1)
    ct_split.append(len(raw))
    split_raw = list(chunks(raw,int(blocksize/8)))
    padded_split_raw = padding(split_raw)
    for item in padded_split_raw:
        block = XOR(iv,item)
        iv = encrypt(key,block)
        ct_split.append(iv)
    #ct = b''.join(ct_split)
    return ct_split[-1]


def cbc_enc(key,raw,iv):
    ct_split = []
    ct_split.append(iv)
    split_raw = list(chunks(raw,int(blocksize/8)))
    padded_split_raw = padding(split_raw)
    # print(padded_split_raw)
    for item in padded_split_raw:
        block = XOR(iv,item)
        iv = encrypt(key,block)
        ct_split.append(iv)

    ct = b''.join(ct_split)
    return ct


def cbc_dec(key,ct):
    IV = ct[:16]
    dt_split = []
    split_raw = list(chunks(ct[16:],int(blocksize/8)))
    for i in range(0,len(split_raw)):
        block = decrypt(key,split_raw[i])
        if (i == 0):
            dt_split.append(XOR(block,IV))
        else:
            dt_split.append(XOR(block, split_raw[i - 1]))
    dt_split = remove_padding(dt_split)
    return b''.join(dt_split)


def powv1 (m, e, n):
   s = 1
   while e != 0:
      if e & 1:
         s = (s * m) % n
      e >>= 1
      m = (m * m) % n
   return s


def IV_Gen():
    return os.urandom(int(blocksize/8))


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
        return True, plainText
    else:
        print('False')
        return False


def dec2(keyFile, messageFile):
    key = readFile('rsa-validate', keyFile).split('\n')
    if len(key) != 3:
        print("rsa-validate: invalide key file")
        exit()

    else:  # Pull the info from the private key
        nBits = int(key[0])
        n = int(key[1])
        d = int(key[2])

    cipherText = readFile('rsa-validate', messageFile)

    # Calculate the plain text with the padding
    m = powv1(int(cipherText), d, n)

    # Pull off the padding
    plainText = m & ((1 << nBits - (nBits // 2) - 2) - 1)

    return plainText


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

def keygen(pubKeyFile, privKeyFile, numBits,CA = None):# COmment boxed in stuff if nothing works
    p = number.getPrime(int(numBits))
    q = number.getPrime(int(numBits))

    n = p * q
    order = (p - 1) * (q - 1)
    e = getCoprime(order)
    d = modinv(e, order)

    with open(pubKeyFile, 'w+') as pub:
        pub.write(str(numBits) + '\n' + str(n) + '\n' + str(e))

    with open(privKeyFile, 'w+') as priv:
        priv.write(str(numBits) + '\n' + str(n) + '\n' + str(d))

    if CA == None:
        enc(privKeyFile,pubKeyFile,pubKeyFile + "-casig")
    else:
        enc(CA, pubKeyFile, pubKeyFile + "-casig")