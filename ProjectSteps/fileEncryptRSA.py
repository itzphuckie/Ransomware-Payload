# File Encryption Lab
# CECS 378
# Alexander Fielding
# Phuc Nguyen

from fileEncryptMAC import MyencryptMAC, MydecryptMAC, MyFileEncryptMAC, MyFileDecryptMAC
import os
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.asymmetric.padding import MGF1 as uno
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from pathlib import Path #used to get file ext
#Global variables
encFileName = " "
decFileName = " "
filename =" "
keysize = 32

# 0. Key Generation - generate public key and private key
def generateKeyPair():  
    privateKey = rsa.generate_private_key( #generate a private key
         public_exponent=65537, # indicate what one mathematical property of the key generation will be
         # Not using e != 65537 - reduce the compatibility w/ existing hardware/software, and break conformance to some standards of security authorities
         # Higher e - make public RSA operation slower
         # Lower e - (ex, e = 3,..) make operation faster, However, using higher e is safer for padding
    
         # e = 65.. generates a prime P suitable as RSA modulus, implying gcd(P-1,e) = 1, which means  p != 1 (mod e)
         # Every private/ public pair consists of an exponent and modulus 
         key_size=2048, # number of bits long the key should be, larger = more security
         backend=default_backend()
    )
    publicKey = privateKey.public_key()   # generate public key
    return publicKey, privateKey
def keyValidation():
    # If ther ear NO key.PEM created yet, we will go ahead and create a new set of keys and store it in the directory "keys"
    if(os.path.exists('./SHREKISLOVESHREKISLIFE555/publicKey.pem') == False):
        # generate a public and private key using the generate function but not .PEM file yet
        publicKey, privateKey = generateKeyPair()

    #Creating the privateKey.PEM file format - base64 format w/ delimiters
    # Using private_bytes() to serialize the key that we've loaded / generated
    # with out having to encrypt ( we used no encryption) 
        privatePem = privateKey.private_bytes( 
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        #Creating the publicKey.PEM file, serialize tje public key using public_bytes
        publicPem = publicKey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # Making a folder/directory called "keys" to store both private/public keys
        os.makedirs('./SHREKISLOVESHREKISLIFE555')
        privateFile = open ("SHREKISLOVESHREKISLIFE555/privateKey.pem", "wb") # Write private keys to file as binary 
        privateFile.write(privatePem)
        privateFile.close()
            
        publicFile = open ("SHREKISLOVESHREKISLIFE555/publicKey.pem", "wb") #Writes public keys to file as binary
        publicFile.write(publicPem)
        publicFile.close()
        print("Private Key & Public Key are created.")

# 1. Encrypt using RSA
def MyRSAencrypt(filepath, RSA_Publickey_filepath):
    backend=default_backend()
    #encrypts the data of where the filepath is 
    C, IV, EncKey, tag, HMACKey, ext  = MyFileEncryptMAC(filepath)
    #load public key from file
    # Initilize RSA public key encryption object and load pem publickey from RSA file path
    with open(RSA_Publickey_filepath, "rb") as key_file:
        public_key = serialization.load_pem_public_key( 
            key_file.read(),
            backend = default_backend()
	)

    # encrypt the public key
    # we use OAEP instead of PKCS1v15 b/c it's the recommended choice for any new protocal/application. PK just support legacy protocal
    # mgf - mask generation function object.
    RSACipher = public_key.encrypt(         
	EncKey+HMACKey, # concatenated 
	padding.OAEP(
	    mgf=MGF1(algorithm=hashes.SHA256()),
	    algorithm=hashes.SHA256(),
	    label=None
	    )       
	)
    return RSACipher, C, IV, ext, tag

# 2. Decrypt using RSA
def MyRSAdecrypt (filepath,RSACipher, C, IV, ext, RSA_Privatekey_filepath, tag):
    #Open the the private key .PEM file 
    with open(RSA_Privatekey_filepath, 'rb') as key_file:
        private_key = serialization.load_pem_private_key( 
            key_file.read(),
            password = None,
            backend = default_backend()
	)
    # use the private key to decrypt and obtain concatenated key of EncKey and HMACKey
    key = private_key.decrypt(      
    RSACipher,
    padding.OAEP(
        mgf= MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
	label=None
	)
    )
    # first 32 bytes are encryption key 
    EncKey=key[:32]
    #last 32 byets are hmac key
    HMACKey= key[-32:]
    # Decrypt and obtain the m(plaintext) 
    m = MydecryptMAC(C, EncKey, IV, tag, HMACKey) #decrypt the message using decrypted key
    return m
