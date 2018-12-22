# CECS378_Ransomware

This is a group project for CECS 378.
We made ransomware project that involves working with servers in Linux Ubuntu, AWS instance, RSA Encryption and Decryption.

PART 1 : Setting up an HTTPs Server with Node, Amazon EC2, NGINX and Let's Encrypt.
  - Follow this tutorial (https://blog.cloudboost.io/setting-up-an-https-sever-with-node-amazon-ec2-nginx-and-lets-encrypt-46f869159469), and set up a NGINX server with Node.js and AWS EC2 instance.
  - You can get a free working domain by registering with name cheap, and make sure to point your DNS to server. I would recommend using Route 53 on AWS website.
  - Now, you need to make sure to set up a certificate for "Let's Encrypt". You can find all the instruction on https://letsencrypt.org/.
  - Next step is SSL Configuration, you have 2 options:
    1. SSL config for Nginx as Reverse Proxy
    2. SSL config for Node
  Check my folder called "SSLConfig" for codes to put in server.js
  - Lastly, you need to check your SSL Labs Performance, https://www.ssllabs.com/ssltest/ . If you get an A+, that means you have passed all the test, however, there are 2 common errors that might happen.
  - Errors :
    1. TLS 1.2 instead of 1.3
    2. Invalid : Server provided more than one HSTS headers
  Check out my "ServerSetupErrorSolution" for solutions to fix it.

PART 2: File Encryption
  - These steps are Python Cryptogrpahy based (hazmat ONLY).
  Step 1:
    - Build simple Encrypt and Decrypt modules that will generate a 16 Bytes IV, and encrypt the message using the jey and IV in CBC mode ( AES). Catch an error if the len(key) < 32.
      (C, IV)= Myencrypt(message, key):
    - Then, you will generate a 32 Byte keys and open a file, read it and ecnrypt then decrypt it.
      (C, IV, key, ext)= MyfileEncrypt (filepath):
  Step 2:
    - Modify the File Encryption with HMAC for authentication matters. I would recommend to use SHA256 in your HMAC.
      (C, IV, tag)= MyencryptMAC(message, EncKey, HMACKey)
      (C, IV, tag, Enckey, HMACKey, ext)= MyfileEncryptMAC (filepath)
  - You can find the codes to these methods insider "ProjectSteps"

PART 3: RSA File with OS package and JSON package
  Step 1:
    - You will a script that looks for a pair of RSA Public and private key (using a CONSTANT file path; PEM format). If the files do not exist (use OS package) then generate the RSA public and private key (2048 bits length) using the same constant file path.
  Step 2:
    - Modify your HMAC file encryption with RSA.
    - In this method, you first call MyfileEncryptMAC (filepath) which will return (C, IV, tag, Enckey, HMACKey, ext).
    - You then will initialize an RSA public key encryption object and load pem publickey from the RSA_publickey_filepath.
    - Lastly, you encrypt the key variable ("key"= EncKey+ HMACKey (concatenated)) using the RSA publickey in OAEP padding mode. The result will be RSACipher. You then return (RSACipher, C, IV, ext).
    (RSACipher, C, IV, tag, ext)= MyRSAEncrypt(filepath, RSA_Publickey_filepath)
  Step 3:
    - Use OS package to retrieve the current working directory. Then do a Depth first search from root down and encrypt every folder in that current directory.
    - For every file that is encrypted, store the encrypted file as a JSON file. The attributes you have for each file are 'RSACipher', 'C', 'IV', 'tag' and 'ext'. The values are from MyRSAEncrypt method. Once the JSON fire is written (use json.dump() with file.write() methods) into a JSON file then you can remove the plaintext file (use os.remove() method). Note that you need to encode/decode your data before writing them into a JSON file.
  Step 4:
    - Use Pyinstaller or Py2exe to create an executable file from your step 3
WARNING: DO NOT run the executable file on important folders. Only test on a designated python working directory. You are responsible if you lose any important file.

PART 4: Awesomeware
  Step 1:
    - Set up a Restful Server using this tutorial, https://www.codementor.io/olatundegaruba/nodejs-restful-apis-in-10-minutes-q0sgsfhbd .
    - You want to make sure that your server has a simple DB with at least two API's. One is to POST a public/private key pair (stored in your MongoDB). The other is a GET request which contains a Public key in the hearder and it returns the corresponding private key in response.
  Step 2:
    - After you deploy your RESTful server to your AWS, you modify your Python payload's keyGen method to POST the public/private keys to the server.
    - Then, make sure to write a Python script that makes a GET request to retrieve the private key for the public key stored on the disk.
    - I recommend including an "App Key" in your requests. This is to authenticate the application to the server so your server does not respond to any connection coming from anywhere other than your own Python payload.

Useful Links:
  Part 1 :
    - https://blog.cloudboost.io/setting-up-an-https-sever-with-node-amazon-ec2-nginx-and-lets-encrypt-46f869159469
    - https://letsencrypt.org/
    - https://www.ssllabs.com/ssltest/
    - https://www.linuxbabe.com/ubuntu/enable-tls1-3-nginx-ubuntu-18-04-16-04
  Part 4:
    - https://www.codementor.io/olatundegaruba/nodejs-restful-apis-in-10-minutes-q0sgsfhbd
