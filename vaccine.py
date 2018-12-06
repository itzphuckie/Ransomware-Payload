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

# Testing

jason={}

for root, dirs, files in os.walk(dir_path):
    for filename in files:
        # Combine the file path with the root to loop through every fodler 
        path=os.path.join(root,filename)
        # check for ".json" file and only decrypt those 
        if path.endswith(".json") and not filename.startswith('.'):
            print("Decrypting ", filename)
            # Reading the .JSON file 
            with open(path, 'r') as file:
                json_data = file.read()
            # load the data (RSACipher, ...) from the file    
            json_obj = json.loads(json_data)
            # Decoding each object with base 64 and then encode with ascii ( opposite with virus)
            RSACipher   = base64.b64decode(json_obj["RSACipher"].encode('ascii'))       
            C = base64.b64decode(json_obj["C"].encode('ascii')) 
            tag = base64.b64decode(json_obj["tag"].encode('ascii')) 
            IV  = base64.b64decode(json_obj["IV"].encode('ascii')) 
            ext = json_obj["ext"]

            # Get rid of".json" file so we can add the original extension later 
            new_path =path.replace('.json','')
            # Add the original extension 
            name = new_path + ext
            # decrypting the file 
            plain_text = MyRSAdecrypt (new_path,RSACipher, C, IV, ext, priv_key, tag)
            
            # Write the original message into the original file with original extension 
            with open(name, 'wb') as outfile: #Writes to json
                outfile.write(plain_text)
                outfile.close()
    
#Testing
                
                
