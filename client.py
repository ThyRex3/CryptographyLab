import socket
import rsa
import Crypto
import base64
import os
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto import Random
import ast
from random import getrandbits
import sys
import time
from socket import error as socket_error

def RSAEnc(plainText, publicKey):
   holder = rsa.PublicKey.load_pkcs1(publicKey, 'PEM')
   cipherText = rsa.encrypt(plainText, holder)
   return cipherText

def RSADec(cipherText, privateKey):
   holder = rsa.PrivateKey.load_pkcs1(privateKey, 'PEM')
   plaintext = rsa.decrypt(cipherText, holder)
   return plainText

def DHCalc(g, p, x):
   return ((int(g)**int(x)) % int(p))

# Hashing Strings: http://pythoncentral.io/hashing-strings-with-python/
def HashPlaintext(plainText):
    salt = uuid.uuid4().hex
    return hashlib.sha256(salt.encode() + plainText.encode()).hexdigest() + ':' + salt

# Hashing Message with Key? : https://gist.github.com/theY4Kman/3893296
def HMAC(key, plainText):
    hash_obj = HMAC.new(key=key, msg=plainText, digestmod=SHA256)
    return hash_obj.hexdigest()

bobPublicKey = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkr8IivGI753PxologDYiEG18V
DRlCeNBJ9TCxlHRkVVfNTyBwAlUqFNkLodLoNwQFKQrAQvS4d0uhMGfY7chS++qN
EWa2+55yI6dYKDwkOXbyRfetaDiRJqvxBIUCpl9tTc0BafSfp8XDnFNtLIbVZoei
G1BX5485bHGRqhXL7QIDAQAB
-----END PUBLIC KEY-----"""

alicePublicKey = """-----BEGIN PUBLIC KEY----- 
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgH1LaxDblUH8MtKCq4HuqLHqcfFo 
67939uV3Svfby3zfqDuWNJmWw7lNS0iRTQ8eQ4px6pDHGaN5oYrUU/TArYx1nTOd 
M40nCEwDh+jf612jCAOykrgN+4RKjXqsctrPpHc8CfEEIBEVIUXBomd8iEzn/S62 
TJCV9FmE9a+HiwDhAgMBAAE=
 -----END PUBLIC KEY-----"""

alicePrivateKey = RSA.generate(1024, Random.new().read)

DH_A = 29

BLOCK_SIZE = 32
PADDING = '{'
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

h = SHA256.new('AliceSecret').hexdigest()
HOST = '127.0.0.1'    # The remote host
PORT = 50007              # The same port as used by the server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.sendall('Requesting RSA information')
#data = s.recv(1024)
s.sendall(RSAEnc(h, bobPublicKey))

AESSharedSecret = RSAEnc(h, bobPublicKey)

g = int(s.recv(2))
p = int(s.recv(2))

print(DHCalc(g, p, DH_A))
print(h)
print("g = ", g)
print("p = ", p)

exponB = s.recv(10)
s.sendall(str(DHCalc(g, p, DH_A)))
print("rec'd bob number", exponB)

sharedSecret = DHCalc(exponB, p, DH_A)
print "Shared secret = ", int(sharedSecret)

secretMessage = ('a'*2000)
# secret is used to encrypt
secret = os.urandom(BLOCK_SIZE)

print "Secret = ", secretMessage
s.sendall(RSAEnc(secretMessage, alicePublicKey))

# create an AES cipher
cipher = AES.new(secret)

#cipherText
encoded = EncodeAES(cipher, secretMessage)
print "Encoded: ", encoded, "\n encoded len = ", len(encoded), "\n"
#Hash the cipherText
hash = SHA256.new(encoded).digest()
#Sign the hashed cipherText
signature = alicePrivateKey.sign(hash, '')

s.sendall(encoded)
print "sent encoded"
s.sendall(str(signature))
print "sent signature"

time.sleep(0.01)

s.close()
#print 'Received', repr(data)

# Sources
# https://gist.github.com/theY4Kman/3893296
