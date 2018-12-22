import os,sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import asymmetric


#0. Key Generation - generate public key and private key
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

