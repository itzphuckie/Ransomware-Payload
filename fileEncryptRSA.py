# File Encryption Lab
# CECS 378
# Alexander Fielding
# Phuc Nguyen

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
rsaKeySize = 2048
keysize = 32
magicNum = 65537
blockSize = 16

# 0. Key Generation - generate public key and private key
def generateKeyPair():
    privateKey = rsa.generate_private_key( #generate a private key
         public_exponent = magicNum, # indicate what one mathematical property of the key generation will be
         # Not using e != 65537 - reduce the compatibility w/ existing hardware/software, and break conformance to some standards of security authorities
         # Higher e - make public RSA operation slower
         # Lower e - (ex, e = 3,..) make operation faster, However, using higher e is safer for padding

         # e = 65.. generates a prime P suitable as RSA modulus, implying gcd(P-1,e) = 1, which means  p != 1 (mod e)
         # Every private/ public pair consists of an exponent and modulus
         key_size = rsaKeySize, # number of bits long the key should be, larger = more security
         backend=default_backend()
    )
    publicKey = privateKey.public_key()   # generate public key
    return publicKey, privateKey


# 1. Encryption Method with HMAC
def MyencryptMAC(message,key, HMACKey):
        # Encoding the String message to b-8bytes binary
        # messageB = message
        # Catching exception when the key length < 32 and print out
    if(len(key) < keysize):
        raise ValueError("Invalid key, length must be 32 bytes (256bits)")
        return
        # Padding using PKCS37, symmetric padding
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plainText = padder.update(message) # update the plain text to padded message
    padded_plainText += padder.finalize()
        # Now, move to encrypting the padded_plainText
    iv = os.urandom(blockSize); # create the iv
        # encrypting using AES algorithms and CBC modes
    cipherEncrypt = Cipher(algorithms.AES(key), modes.CBC(iv), backend = default_backend())
    encryptor = cipherEncrypt.encryptor()
        #Then update the encrypt method with the padded plain text message and finalize it
    cipherText = encryptor.update(padded_plainText) + encryptor.finalize()

        # Generate tag with HMAC
    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend = default_backend())
    h.update(cipherText)
    tag = h.finalize() # Finalize the current context and return the message digest as bytes.
    return(cipherText, iv, tag)



# 2. Decryption Method - Inverse of Encryption
def MydecryptMAC(cipherText, key,iv, tag, HMACKey):
    # Catching exception when the key length < 32 and print out
    if(len(key) < keysize):
        raise ValueError("Invalid key, length must be 32 bytes (256bits)")
        return
    # 1. Vertify Tag - use HMAC to vertify integrity & authenticity of a message

    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend = default_backend()) # hashes algorithms
    h.update(cipherText) # hashes and authenticates bytes
    h.verify(tag) # compares bytes to current digest ( crytographic hash function contianing a string of digits )
    # Finalize the current context and securely compare digest to signature

    # 2. Decrypt the cipher Text to padded plainText
    cipherDecrypt = (Cipher(algorithms.AES(key), modes.CBC(iv), backend = default_backend())).decryptor()
    padded_plainText = cipherDecrypt.update(cipherText) + cipherDecrypt.finalize()

    # 3. Then, unpad the padded plainText into actual message that is the same as before we encrypted
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    message = unpadder.update(padded_plainText)
    message += unpadder.finalize()
    #plainText = message
    return message

# 3. Encrypting to a file path ( I set it to .txt so we don't have to open with every time)
def MyFileEncryptMAC(filepath):
    # generate a random key for enc and mac
    encKey = os.urandom(keysize)
    macKey = os.urandom(keysize)
    # Reading file in and encrypt it
    plainTextFile = open(filepath, 'rb');
    message = plainTextFile.read()
    (cipherText, iv,tag) = MyencryptMAC(message,encKey, macKey)
    # write back to an .ecnrypted file
    #encFileName = input("Enter the filename for the encrypted file" + "\n")
    #messageEncrypted = open(filepath + encFileName, 'wb')
    #messageEncrypted.write(cipherText)
    extension = Path(filepath).suffix # grabs extension of file
    return cipherText, iv, encKey,tag,macKey, extension

# 4. Inverse of encrypting to file, this method lets us decrypt the cipher text from the encrypted file
def MyFileDecryptMAC(filepath, encKey, iv,tag, macKey):
    # Open the .encrypted file and read it
    messageEncrypted = open(filepath, 'rb')
    cipherText = messageEncrypted.read()
    # decrypt it then write to a .decrypted file
    plainText = MydecryptMAC(cipherText, encKey, iv,tag,macKey)
    decFileName = input("Enter the filename for the decrypted file" + "\n")
    cipherTextDecrypted = open(filepath + decFileName, 'wb')
    #print('Decypted message from file:' + '\n')
    cipherTextDecrypted.write(plainText)

# 5. Encrypt using RSA and Optimal asymmetric encryption padding
# Inputs: filepath, public key
# Outputs: Encrypted file
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

# 6. Decrypt using RSA and Optimal asymmetric encryption padding
# Inputs: RSA Cipher, cyphertext, IV, ext loaction, private key, Tag
# Outputs: Decypted file
def MyRSAdecrypt (RSACipher, C, IV, ext, RSA_Privatekey_filepath, tag):
    #uses private key to decrypt key used for message
    key = private_key.decrypt(
    RSACipher,
    OAEP(
        mgf=MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
	label=None
	)
    )
    EncKey = key[0:keysize]
    HMACKey = key[len(EncKey):]
    MyFileDecryptMAC(IV, EncKey, ext, HMACKey, tag) #decrypt the message using decrypted key
