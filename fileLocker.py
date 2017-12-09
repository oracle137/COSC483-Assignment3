import sys
import os
import functions as f
import binascii

d = r = p = vk = ''

for i in range(2, len(sys.argv)-1,2):
    if sys.argv[i] == "-d":
        d = sys.argv[i+1]
    elif sys.argv[i] == "-p":
        p = sys.argv[i+1]
    elif sys.argv[i] == "-r":
        r = sys.argv[i+1]
    elif sys.argv[i] == "-vk":
        vk = sys.argv[i+1]
    else:
        print("Invalid flag: ", sys.argv[i])

files = os.listdir(d)



if sys.argv[1] == "lock":
    if not f.dec(vk,p,p+"-casig"):
        exit()
    print("hey it validated")
    # Check that public key verifies
    AES = os.urandom(128)
    with open("AESkey", 'w+') as o:
        o.write(str(AES))
    # Sign the manifest with the private key

    for filename in files:
        with open(d + r"\\" + filename, 'rb') as o:
            tmp = o.read()
        # tmp = f.readFile("Lock",d + r"\\" + filename)

        ciphertext = f.cbc_enc(AES,tmp,f.IV_Gen())
        os.remove(d + r"\\" + filename)
        with open(d + r"\\" + filename, 'wb') as o:
            o.write(ciphertext)
    # Encrypt all the files in the directory using CBC mode, delete all plaintext after
    for filename in files:
        with open(d + r"\\" + filename, 'rb') as o:
            tmp = o.read()
        f.cbc_sign(AES,tmp,bytes('0000000000000001',encoding='utf-8'))
    # Create tags for all the cipher text files
    f.enc(p, "AESkey", d + r"\\" + "manifest")
    #os.remove("AESkey")
    # Then, generate random AES key, encrypt it with locking party's public key, and write it to a file (manifest)
    f.enc(r, d + r"\\" + "manifest", d + r"\\" + "manifest-casig")
elif sys.argv[1] == "unlock":
#     # Check that public key verifies
    if not f.dec(vk, p, p + "-casig"):
        exit()
    if not f.dec(p,d + r"\\" + "manifest",d + r"\\" + "manifest-casig"):
        exit()
#     # Check that manifest verifies from public key
#     # Verify tags match (remove tags after)
    #manifest = None
    # with open("AESkey", 'rb') as filw:
    #    key = filw.read()
    # print(int.from_bytes(key,byteorder='little'))
    # print(f.dec2(p, d + r"\\" + "manifest"))
    _, plaintext = f.dec(p,d + r"\\" + "manifest",d + r"\\" + "manifest-casig")
    for filename in files:
        if filename == "manifest" or filename == "manifest-casig":
            continue # TODO: remove file
        else:
            tmp = None
            with open(d + r"\\" + filename, 'rb') as o:
                tmp = o.read()
            print(tmp)
            with open(d + r"\\" + filename, 'wb') as o:
                o.write(f.cbc_dec(bytes(str(plaintext), encoding='utf-8'), tmp))

    # get key from manifest
   # for file in files:
   #     with open(d + r"\\" + file, 'rb') as o:


    #     # Decrypt files
else:
     print("Invalid usage, use shell script to run appropriate behavior.")