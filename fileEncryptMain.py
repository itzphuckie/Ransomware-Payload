# File Encryption Lab
# CECS 378
# Alexander Fielding
# Phuc Nguyen

from fileEncryptMAC import MyencryptMAC, MydecryptMAC, MyFileEncryptMAC, MyFileDecryptMAC
from fileEncryptRSA import generateKeyPair, MyRSAencrypt, MyRSAdecrypt 
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
user = input("          Enter user as specified in file manager"+ '\n')
MAIN_MENU = ('         Select operation.' + '\n' +
 '          1. Encypt a message from user input and then decrypt it using MAC. ' + '\n' +
 '          2. Encrypt a file/picture and decrupt with MAC.' + '\n' +
 '          3. Generate Private & Public Key.'  + '\n' +
 '          4. Encrypt using RSA then Decrypt it( every file in the directory ) '  + '\n' +
 '          5. Quit' + '\n')


user_input = None
# Main Program 
while(user_input != 6):

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
    elif(user_input == 4):
        print("RSAEncrypt and RSADecrypt")
        pub_key = "/Users/Phuc Nguyen/Desktop/FinalTesting/SHREKISLOVESHREKISLIFE555/publicKey.pem"
        dir_path = "/Users/Phuc Nguyen/Desktop/Testing"
        os.chdir(dir_path)
        cwd = os.getcwd()
        print("Current directory:" + cwd)

        jason={}
        for root, dirs, files in os.walk(cwd):
            for filename in files:
                print("Encrypting " + filename + "...") 
                RSACipher, C, IV, ext, tag = MyRSAencrypt(filename, pub_key )

                fname = os.path.splitext(str(filename))[0]
                jas = {}
                jas[fname] = []
                jas[fname].append({

                    "RSACipher": RSACipher.decode('latin-1'),
                    "C": C.decode('latin-1'),
                    "IV": IV.decode('latin-1'),
                    "ext": ext,
                    "tag": tag.decode('latin-1')
                })
                jason.update(jas)
	
                with open(filename + '.json', 'w') as outfile: #Writes to json 
                    json.dump(jason, outfile, indent=4)
                    outfile.close()
                #os.remove(filename)
    elif(user_input == 5):
        break;
    else:
        print("         Invalid input")
    
