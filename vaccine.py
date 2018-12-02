from fileEncryptMAC import MyencryptMAC, MydecryptMAC, MyFileEncryptMAC, MyFileDecryptMAC
from fileEncryptRSA import generateKeyPair, MyRSAencrypt, MyRSAdecrypt

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
Making a VACCINE for Ransomeware that decrypt all the encrypted raw data
'''

priv_key = "/Users/Phuc Nguyen/Desktop/FinalTesting/SHREKISLOVESHREKISLIFE555/privateKey.pem"
dir_path = "/Users/Phuc Nguyen/Desktop/Testing"
print("RSAEncrypt and RSADecrypt")
# This is the file where the virus will infect
# Making this path(tester folder) the current working directory 
os.chdir(dir_path)
cwd = os.getcwd()

# Testing

jason={}

for root, dirs, files in os.walk(cwd):
    for filename in files:
        if filename.endswith(".json"):
            print("Decrypting ", filename)
            # change directory to root in order to start from root and acess every folder inside the path
            os.chdir(root)
            # Reading the .JSON file 
            with open(filename, 'r') as f:
                json_data = f.read()
            # load the data (RSACipher, ...) from the file    
            json_object = json.loads(json_data)
            # Decoding each object with base 64 and then encode with ascii ( opposite with virus)
            RSACipher   = base64.b64decode(json_obj["RSACipher"].encode('ascii'))       
            C = base64.b64decode(json_obj["C"].encode('ascii')) 
            tag = base64.b64decode(json_obj["tag"].encode('ascii')) 
            IV  = base64.b64decode(json_obj["IV"].encode('ascii')) 
            ext = json_obj["ext"]

            # Then, decrypt it using the data that returned from encrypted (virus)
            plaintext = MyRSAdecrypt(RSACipher, C, IV, ext, priv_key, tag)
            #print(plaintext)
            # Write the original message into the original file with original extension 
            with open(file + ext, 'w') as outfile: #Writes to json
                #file_out = open(file_path, "wb")
                outfile.write(plaintext)
                outfile.close()


