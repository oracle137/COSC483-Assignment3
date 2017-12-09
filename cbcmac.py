import sys, operator, binascii
from Crypto.Cipher import AES
import hashlib
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

def padding(raw):
    lraw = len(raw[-1])*8
    modraw = lraw % blocksize
    remainder = blocksize - modraw
    if modraw == 0:
        remainder = 128
        paddingstr = (int(remainder/8)).to_bytes(int(remainder/8),byteorder="big",signed=False)* int(remainder/8)
        raw.append(paddingstr)
    else:
        paddingstr = (int(remainder / 8)).to_bytes(1, byteorder="big", signed=False) * int(remainder/8)
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

def cbc_enc(key,raw,iv):
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


if __name__ == "__main__":
# Check for appropriate number of args
    if len(sys.argv) != 8:
        print("Invalid amount of arguments")
        exit(1)
    tag = key = msg = ''
# Input files
    for i in range(1, len(sys.argv),2):
        if sys.argv[i] == '-k':
            key = sys.argv[i+1]
        elif sys.argv[i] == '-m':
            msg = sys.argv[i+1]
        elif sys.argv[i] == '-t':
            tag = sys.argv[i+1]
    keyFile = open(key, 'rb')
    key = bytes('', encoding='utf-8')
    for line in keyFile:
        key += line
    msgFile = open(msg, 'rb')
    msg = bytes('', encoding='utf-8')
    for line in msgFile:
        msg += line

# Generate "1" IV
    iv = '0000000000000001'
    iv = bytes(iv, encoding='utf-8')
# Either validate or generate a tag
    if sys.argv[7] == 'cbcmac-validate':
        tagFile = open(tag, 'rb')
        tag = bytes('', encoding='utf-8')
        for line in tagFile:
            tag += line
        checkTag = cbc_enc(key, msg, iv)
        if tag == checkTag:
            print("True")
        else:
            print("False")
        print("Correct Tag: ", checkTag)
        print("Your Tag:    ", tag)
    else:
        tagFile = open(tag,'wb')
        newTag = cbc_enc(key,msg,iv)
        tagFile.write(cbc_enc(key, msg, iv))
        print(newTag)