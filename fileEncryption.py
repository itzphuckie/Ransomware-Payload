





















# File Encryption Lab
# CECS 378
# Alexander Fielding
# Phuc Nguyen

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
    
# 1. Encryption Method 
def Myencrypt(message,key):
        # Encoding the String message to b-8bytes binary
    messageB = message
        # Catching exception when the key length < 32 and print out
    if(len(key) < 32): 
        print("Invalid key, length must be 32 bytes (256bits)")
        return
        # Padding using PKCS37, symmetric padding 
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plainText = padder.update(messageB) # update the plain text to padded message
    padded_plainText += padder.finalize()
        # Now, move to encrypting the padded_plainText
    iv = os.urandom(16); # create the iv
        # encrypting using AES algorithms and CBC modes
    cipherEncrypt = (Cipher(algorithms.AES(key), modes.CBC(iv), backend = default_backend())).encryptor()
        #Then update the encrypt method with the padded plain text message and finalize it
    cipherText = cipherEncrypt.update(padded_plainText) + cipherEncrypt.finalize()
    return(cipherText, iv)



# 2. Decryption Method - Inverse of Encryption 
def Mydecrypt(cipherText, key,iv):
    # Catching exception when the key length < 32 and print out
    if(len(key) < 32): 
        print("Invalid key, length must be 32 bytes (256bits)")
    # Decrypt the cipher Text to padded plainText
    cipherDecrypt = (Cipher(algorithms.AES(key), modes.CBC(iv), backend = default_backend())).decryptor()
    padded_plainText = cipherDecrypt.update(cipherText) + cipherDecrypt.finalize()

    # Then, unpad the padded plainText into actual message that is the same as before we encrypted 
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    message = unpadder.update(padded_plainText)
    message += unpadder.finalize()
    # decoding to string message
    plainText = message
    return plainText

# 3. Encrypting to a file path ( I set it to .txt so we don't have to open with every time)
def MyFileEncrypt(filepath):
    # generate a random key
    key = os.urandom(32)
    print("32 bytes key: ", key)
    plainTextFile = open(filepath, 'rb');
    message = plainTextFile.read()
    (cipherText, iv) = Myencrypt(message,key)
    messageEncrypted = open(filepath + "Encrypt.txt", 'wb')
    messageEncrypted.write(cipherText)
    return cipherText, iv, key, "Encrypt.txt"
	
# 4. Inverse of encrypting to file, this method lets us decrypt the cipher text from the encrypted file
def MyFileDecrypt(filepath, key, iv):
    messageEncrypted = open(filepath, 'rb')
    cipherText = messageEncrypted.read()
    plainText = Mydecrypt(cipherText, key, iv)
    cipherTextDecrypted = open(filepath + "Decrypt.txt", 'wb')
    cipherTextDecrypted.write(plainText)

# Main

# 1. Testing the Myencrypt and Mydecrypt method by encrypt a message then decrypt and compare if the boolean return true for matching plaintext
mess = b'I like pie'

key1 = os.urandom(32) # creating a key that is 32 bytes
print("Plain Text:", mess)
(CipherText,iv) = Myencrypt(mess, key1)
print("Cipher Text:", CipherText)
print("Key:", iv)
decrypt = Mydecrypt(CipherText,key1, iv)
print("Decrypt Message:", decrypt)
print("Compare if both messages are the same:", mess == decrypt)
# 2. Test the file encryption and decryption
filepath = "/Users/Phuc Nguyen/Desktop/read.txt"
#encrypting the message to a filepath.encrypt
(ciphertext, iv, key, ext) = MyFileEncrypt(filepath)
#decrypting
MyFileDecrypt(filepath + ext, key, iv)

