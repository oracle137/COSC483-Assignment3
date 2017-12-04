import sys

import functions

def printUsage():
    print("Usage: ./[rsa-enc/rsa-dec]")
    print("          -k <key file> : required, specifies a file storing a valid RSA key in the example format")
    print("          -i <input file> : required, specifies the path of the file containing an integer in Z∗n in String form (base 10) that is being operated on")
    print("          -o <output file> : required, specifies the path of the file where the resulting output is stored in String form (base 10)")
    print("       ./[rsa-keygen]")
    print("          -p <public key file> : required, specifies the file to store the public key")
    print("          -s <private key file> :  required, specifies the file to store the private key")
    print("          -n <number of bits> : required, specifies the number of bits in your N")
    exit()

if __name__ == "__main__":
    
    if not (len(sys.argv) == 8):
        printUsage()
        
    elif sys.argv[1] == 'rsa-enc' or sys.argv[1] == 'rsa-dec':
    
        keyFile = ""
        inputFile = ""
        outputFile = ""
        
        if sys.argv[2] == '-k':
            keyFile = sys.argv[3]
                
        else:
            printUsage()
            
        if sys.argv[4] == '-i':
            inputFile = sys.argv[5]
            
        else:
            printUsage()
            
        if sys.argv[6] == '-o':
            outputFile = sys.argv[7]
            
        else:
            printUsage()
            
        if sys.argv[1] == 'rsa-enc':
            functions.enc(keyFile, inputFile, outputFile)
            
        else: #This has already been checked
            functions.dec(keyFile, inputFile, outputFile)
        
    elif sys.argv[1] == 'rsa-keygen':
        
        pubKeyFile = ""
        privKeyFile = ""
        numBits = 0
        
        if sys.argv[2] == '-p':
            pubKeyFile = sys.argv[3]
                
        else:
            printUsage()
            
        if sys.argv[4] == '-s':
            privKeyFile = sys.argv[5]
            
        else:
            printUsage()
            
        if sys.argv[6] == '-n':
            numBits = sys.argv[7]
            
        else:
            printUsage()
            
        functions.keygen(pubKeyFile, privKeyFile, numBits)