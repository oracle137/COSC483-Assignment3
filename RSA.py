import sys

import functions

def printUsage():
    print("Usage: ./[rsa-sign/rsa-validate]")
    print("          -k <key file> : required, specifies a file storing a valid RSA key in the example format")
    print("          -m <message file> : required, specifies the path of the file containing an integer in Z∗n in String form (base 10) that is being operated on")
    print("          -c <sig file> : required, specifies the path of the file where the resulting output is stored in String form (base 10)")
    exit()

if __name__ == "__main__":
    
    if not (len(sys.argv) == 8):
        printUsage()
        
    elif sys.argv[1] == 'rsa-sign' or sys.argv[1] == 'rsa-validate':
    
        keyFile = ""
        messageFile = ""
        sigFile = ""
        
        if sys.argv[2] == '-k':
            keyFile = sys.argv[3]
                
        else:
            printUsage()
            
        if sys.argv[4] == '-m':
            messageFile = sys.argv[5]
            
        else:
            printUsage()
            
        if sys.argv[6] == '-c':
            sigFile = sys.argv[7]
            
        else:
            printUsage()
            
        if sys.argv[1] == 'rsa-sign':
            functions.enc(keyFile, messageFile, sigFile)
            
        else: #This has already been checked
            functions.dec(keyFile, messageFile, sigFile)
        
    # elif sys.argv[1] == 'rsa-keygen':
    #
    #     pubKeyFile = ""
    #     privKeyFile = ""
    #     numBits = 0
    #
    #     if sys.argv[2] == '-p':
    #         pubKeyFile = sys.argv[3]
    #
    #     else:
    #         printUsage()
    #
    #     if sys.argv[4] == '-s':
    #         privKeyFile = sys.argv[5]
    #
    #     else:
    #         printUsage()
    #
    #     if sys.argv[6] == '-n':
    #         numBits = sys.argv[7]
    #
    #     else:
    #         printUsage()
    #
    #     functions.keygen(pubKeyFile, privKeyFile, numBits)