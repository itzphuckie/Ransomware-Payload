# File Encryption Lab
# CECS 378
# Alexander Fielding
# Phuc Nguyen

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

#Global variables
encFileName = " "
decFileName = " "
filename =" "
keysize = 32
user = input("          Enter user as specified in file manager"+ '\n')
MAIN_MENU = ('         Select operation.' + '\n' +
 '          1. EncyptMAC a message from user input ' + '\n' +
 '          2. Encrypt a file/picture with MAC' + '\n' +
 '          3. Quit' + '\n')

user_input = None

# 1. Encryption Method
def MyencryptMAC(message,key, HMACKey):
        # Encoding the String message to b-8bytes binary
    #messageB = message
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
    encFileName = input("Enter the filename for the encrypted file" + "\n")
    messageEncrypted = open(filepath + encFileName, 'wb')
    messageEncrypted.write(cipherText)
    return cipherText, iv, encKey,tag,macKey, encFileName

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

# Main

# 1. Testing the Myencrypt and Mydecrypt method by encrypt a message then decrypt and compare if the boolean return true for matching plaintext
while(user_input != 5):

    print(MAIN_MENU)

    user_input = int(input("Enter a number to execute an operation from above" + '\n'))

    if(user_input == 1):
        encKey = os.urandom(keysize) # creating an encrypt key that is 32 bytes
        macKey = os.urandom(keysize) # creating mac key that is also 32 bytes
        
        msg = input("Enter the message you want to encrypt" + '\n')
        bytemsg = str.encode(msg)
        print("Plain Text:", msg)
        # encryption 
        (CipherText,iv,tag) = MyencryptMAC(bytemsg, encKey, macKey)
        print("Cipher Text:", CipherText)
        print("IV:", iv)
        print("Tag:", tag)
        # Decryption
        print("Decrypting ....")
        pt = MydecryptMAC(CipherText,encKey, iv,tag,macKey)
        #bytept = decode(pt)
        print("Decrypted Message:", pt)
        print('\n')

    elif(user_input == 2):
        
        filename = input("Enter the filename from the desktop you want to encrypt" + "\n")
        filepath = "/Users/" + user + "/Desktop/" + filename
        #filepath = "/Users/" + user + "/Desktop/apple.jpg"
        #encrypting the message to a filepath.encrypt
        (ciphertext, iv, encKey, tag, macKey, ext) = MyFileEncryptMAC(filepath)
        #decrypting
        filepath = filepath + ext
        MyFileDecryptMAC(filepath, encKey, iv,tag,macKey)

    elif(user_input == 3):
        break;

    else:
        print("         Invalid input")
