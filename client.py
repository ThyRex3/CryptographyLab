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
   holder = rsa.PublicKey.load_pkcs1_openssl_pem(publicKey)
   cipherText = rsa.encrypt(plainText, holder)
   return cipherText

def RSADec(cipherText, privateKey):
   holder = rsa.PrivateKey.load_pkcs1(privateKey, "PEM")
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

# Enc/Dec with AES : http://docs.python-guide.org/en/latest/scenarios/crypto/
# key and IV are byte strings
def AESEnc(key, plainText, iv):
	encryption_suite = AES.new(key=key, mode=AES.MODE_CBC, IV=iv)
	cipherText = encryption_suite.encrypt(plainText)

def AESDec(key, cipherText, iv):
	decryption_suite = AES.new(key=key, mode=AES.MODE_CBC, IV=iv)
	plainText = decryption_suite.decrypt(cipherText)

bobPrivateKey =  """-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDkr8IivGI753PxologDYiEG18VDRlCeNBJ9TCxlHRkVVfNTyBw
AlUqFNkLodLoNwQFKQrAQvS4d0uhMGfY7chS++qNEWa2+55yI6dYKDwkOXbyRfet
aDiRJqvxBIUCpl9tTc0BafSfp8XDnFNtLIbVZoeiG1BX5485bHGRqhXL7QIDAQAB
AoGAV52zHoXYiST7Oge+yesFc7/c5P7Yv6vz+XH0TwUWtt4vvpxjTCbIpE/KfHdq
i8eQRb3cvZ6pjgc+taoLD4TCq7cpBxz476Vno9q7Wu+zyyMbWBSv+YFWm77HlBwS
Z0Bl0G7rwdhsjhwsgHHiZOCs7E6OSvTj1A3VOm3AYsMoJK0CQQD0TjyRGpbNV/n+
ireTtc2nz9MzbG4Du473mW+hEBJoBRX2DKaBhS/mubWEYKoiyfZOF3hZX8eW0TX2
ec/04fnnAkEA76IfhZFl7M6GuIbwixOEfZ+1EaqjQ9IUTr8d/uSTjtDDoeQ3GW5X
FWi0tIsYkVnNL+wtMQ2PeP3LUGtjqzOZCwJBANerRX6XaW9HbhNOZDdKtI2jQwBP
hWNYLSLZWhlmdclMTBHVIxyN9jaJ1PtS1n81qXFQ+NZ1Xl3+vNOkv3egEhsCQQC+
84KIzc7Zf80Mt8JwIJJgBGal+EJ3Ja02/sYpOf13PVXW6GMbqbhNAA2XHIvsLxH5
UQrF3tdoA10C7UATyV73AkEAsyGXpS6EMmKwCe0b5YtfZ7AU+6EmZMgoTbG2YONJ
g3EvCnfEowdQ9P9KyCUT7Fk5cvGLpLNJ+CTDTCfJYRe1Lg==
-----END RSA PRIVATE KEY----- """

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
s.sendall(RSAEnc(h, alicePublicKey))

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

# generate some key
# random_generator = Random.new().read
# key = RSA.generate(1024, random_generator)

# create an AES cipher
cipher = AES.new(secret)

#cipherText
encoded = EncodeAES(cipher, secretMessage)
print "Encoded: ", encoded
#Hash the cipherText
hash = SHA256.new(encoded).digest()
#Sign the hashed cipherText
signature = alicePrivateKey.sign(hash, '')

decoded = DecodeAES(cipher, encoded)
print "Decoded: ", decoded

s.close()
#print 'Received', repr(data)

# Sources
# https://gist.github.com/theY4Kman/3893296