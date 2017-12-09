import sys
import os
import functions as f

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
    AES = f.AES_Creation(d, "enc")

    for filename in files:
        with open(d + r"\\" + filename, 'rb') as o:
            tmp = o.read()

        ciphertext = f.cbc_enc(AES,tmp,f.IV_Gen())
        os.remove(d + r"\\" + filename)
        with open(d + r"\\" + filename, 'wb') as o:
            o.write(ciphertext)
    # Encrypt all the files in the directory using CBC mode, delete all plaintext after
    for filename in files:
        with open(d + r"\\" + filename, 'rb') as o:
            tmp = o.read()
        with open(d +r"\\" + filename + ".tag", 'wb') as o:
            o.write(f.cbc_sign(AES,tmp,bytes('0000000000000001',encoding='utf-8')))
    f.enc(r, d + r"\\" + "manifest", d + r"\\" + "manifest-casig")
elif sys.argv[1] == "unlock":
    # Check that public key verifies
    if not f.dec(vk, p, p + "-casig"):
        exit()
    if not f.dec(p,d + r"\\" + "manifest",d + r"\\" + "manifest-casig"):
        exit()

    os.remove(d + r"\\" + "manifest-casig")
    AES = f.AES_Creation(d, "dec")
    for filename in files:
        if filename == "manifest" or filename == "manifest-casig" or filename.endswith(".tag"):
            continue # TODO: remove file
        else:

            tagContents = None
            with open(d + r"\\" + filename + ".tag", 'rb') as tagFile:
                tagContents = tagFile.read()
            fileContents = None
            with open(d + r"\\" + filename, 'rb') as currentFile:
                fileContents = currentFile.read()
            fileTag = f.cbc_sign(AES,fileContents,bytes('0000000000000001',encoding='utf-8'))
            if tagContents != fileTag:
                print("Incorrect tag")
                exit(1)
            os.remove(d + r"\\" + filename + ".tag")

            tmp = None
            with open(d + r"\\" + filename, 'rb') as o:
                tmp = o.read()

            with open(d + r"\\" + filename, 'wb') as o:
                o.write(f.cbc_dec(AES, tmp))
    os.remove(d + r"\\" + "manifest")
else:
     print("Invalid usage, use shell script to run appropriate behavior.")