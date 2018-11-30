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

print("RSAEncrypt and RSADecrypt")
priv_key = "/Users/Phuc Nguyen/Desktop/FinalTesting/SHREKISLOVESHREKISLIFE555/privateKey.pem"
dir_path = "/Users/Phuc Nguyen/Desktop/Testing"

os.chdir(dir_path)
cwd = os.getcwd()
print("Current directory:" + cwd)
# Testing
pub_key = "/Users/Phuc Nguyen/Desktop/FinalTesting/SHREKISLOVESHREKISLIFE555/publicKey.pem"
'''
file = "/Users/Phuc Nguyen/Desktop/Testing/message.txt"
RSA, C, IV, ext, tag= MyRSAencrypt(file, pub_key)
plainText = MyRSAdecrypt(RSA, C, IV, ext, priv_key, tag)
print(plainText)
'''
jason={}

for root, dirs, files in os.walk(cwd):
    for file in files:
        if file.endswith(".json"):
            print("Decrypt all file:", file)
            
            with open(file, 'r') as f:
                json_data = f.read()
                
            #print("Decrypt json data:",json_data)    
            json_obj = json.loads(json_data)
            #print(json_obj["RSACipher"])
            print("\n\n\n")
            rsa   = base64.b64decode(json_obj["RSA"].encode('ascii')) 
            #print("decrypt rsa =",rsa)
            C = base64.b64decode(json_obj["C"].encode('ascii')) 
            #print("decrypt C =",C)
            
            tag = base64.b64decode(json_obj["Tag"].encode('ascii')) 
            #print("decrypt tag =",tag)
            IV  = base64.b64decode(json_obj["IV"].encode('ascii')) 
            #print("decrypt IV =",IV)
            ext = json_obj["Ext"]
            #print("ext =",ext)
            plaintext = MyRSAdecrypt(file,rsa, C, IV, ext, priv_key, tag)
            #def my_RSA_decrypt(filepath, rsa_cipher, C, IV, hmac_tag, ext, rsa_privatekey_filepath):
            #print(plaintext)
            
            #file_path = "FILE_" + str(file_count) + ext
            #file_count += 1
            with open(file + ext, 'w') as outfile: #Writes to json
                #file_out = open(file_path, "wb")
                outfile.write(plaintext)
                outfile.close()

            #os.remove(file)
        
