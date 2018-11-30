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
from cryptography.hazmat.primitives.asymmetric import rsa
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


# 1. Encrypt using RSA
def MyRSAencrypt(filepath, RSA_Publickey_filepath):
    backend=default_backend()
    C, IV, EncKey, tag, HMACKey, ext  = MyFileEncryptMAC(filepath)    #encrypts file using the mac file 

    #load public key from file
    # Initilize RSA public key encryption object and load pem publickey from RSA file path
    with open(RSA_Publickey_filepath, "rb") as key_file:
        public_key = serialization.load_pem_public_key( 
            key_file.read(),
            backend = default_backend()
	)

    #use RSA encrypt to encrypt the public key
    # we use OAEP instead of PKCS1v15 b/c it's the recommended choice for any new protocal/application. PK just support legacy protocal
    # mgf - mask generation function object.
    RSACipher = public_key.encrypt(         
	EncKey+HMACKey, # concatenated 
	OAEP(
	    mgf=MGF1(algorithm=hashes.SHA256()),
	    algorithm=hashes.SHA256(),
	    label=None
	    )       
	)
    return RSACipher, C, IV, ext, tag

# 2. Decrypt using RSA
def MyRSAdecrypt (filepath,RSACipher, C, IV, ext, RSA_Privatekey_filepath, tag):
    #uses private key to decrypt key used for message
    with open(RSA_Privatekey_filepath, 'rb') as key_file:
        private_key = serialization.load_pem_private_key( 
            key_file.read(),
            password = None,
            backend = default_backend()
	)
    key = private_key.decrypt(      
    RSACipher,
    OAEP(
        mgf=MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
	label=None
	)
    )
    EncKey = key[0:32]
    HMACKey = key[len(EncKey):]
    m = MyFileDecryptMAC(IV, EncKey, ext, HMACKey, tag) #decrypt the message using decrypted key
    return m

