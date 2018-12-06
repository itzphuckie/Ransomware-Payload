# File Encryption Lab
# CECS 378
# Alexander Fielding
# Phuc Nguyen

import os
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from pathlib import Path #used to get file ext

#Global variables
encFileName = " "
decFileName = " "
filename =" "
keysize = 32


# 1. Encryption Method using MAC
def MyencryptMAC(message,key, HMACKey):
    # Catching exception when the key length < 32 and print out
    if(len(key) < 32): 
        raise ValueError("Invalid key, length must be 32 bytes (256bits)")
        return
    # Padding using PKCS37, symmetric padding
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plainText = padder.update(message) # update the plain text to padded message
    padded_plainText += padder.finalize()
    # Now, move to encrypting the padded_plainText
    blocksize = 16;
    iv = os.urandom(blocksize); # create the iv
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
    if(len(key) < 32): 
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

# 3. Encrypting to a file path 
def MyFileEncryptMAC(filepath):
    # generate a random key for enc and mac 
    encKey = os.urandom(keysize)
    macKey = os.urandom(keysize)
    # Reading file in and encrypt it
    plainTextFile = open(filepath, 'rb');
    message = plainTextFile.read()
    (cipherText, iv,tag) = MyencryptMAC(message,encKey, macKey)
    # write back to an ecnrypted file
    extension = Path(filepath).suffix # grabs extension of file
    out_file = open(filepath , "wb") #make a new file to write in binary
    out_file.write(cipherText) #write to the new file
    out_file.close() #close the file
    return cipherText, iv, encKey,tag,macKey, extension

# 4. Inverse of encrypting to file, this method lets us decrypt the cipher text from the encrypted file
def MyFileDecryptMAC(filepath,encKey, iv,tag, macKey):
    #open a file to decrypt
    file = open(filepath,"rb")
    #read the file
    content=file.read()
    # Decrypt the contents using MAC Decrypt
    m=MydecryptMAC(content, key,iv, tag, HMACKey)
    # Write the content back to the filepath 
    out_file1 = open(filepath, "wb") #make a new file
    out_file1.write(m) #write a new file
    out_file1.close() #close that file
    #return m
    
