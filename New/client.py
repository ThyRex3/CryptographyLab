import sys, string, random, pickle, os

from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS

# Import socket library
from socket import *

# Global Variables - Empty strings
encryptKey = ""		# Alice's encrypt = Bob's decrypt key
decryptKey = ""
signKey = ""		
verifySigKey = ""

# Set hostname or IP address from command line
serverName = '127.0.0.1'
# Set port number by converting argument string to integer
serverPort = 5711
#Choose SOCK_STREAM, which is TCP
clientSocket = socket(AF_INET, SOCK_STREAM)
#Connect oserver using hostname/IP and port
clientSocket.connect((serverName, serverPort))

alicePrivateKey = """-----BEGIN RSA PRIVATE KEY-----
MIIEoQIBAAKCAQBtZg6fW8hDisvVgj1BS7c1tyIvTYMq3ztvD1uYOF3sJz+WXwi1
YhMLYtEUg9566x0EPVNLFMkIuWJBZHy19fxvxnp4gQXA5SJqqLkbEQluM2n7c2UA
HeMvP4clcQi/P0ItGqytZx8A8amP2pRMKDjORcvuvYD6bfLNnAORDOVNICRLc1PM
HNCtKpy6RGOePmS/u+qvSr8cgWZTHEDJbHZCxFPG1hGsiqpjkSDanAfMAJI5i5IX
ekyFUT4N+8OY+KeLTopVvJ0i0B5LAJBZpRK/PftLXKupVEvB5okO3qSDPn+6sUek
ute3amcTBzwI6uBtQgKmBxsdQss+JbvcfOnhAgMBAAECggEARDnp1KjA9J6TEMzw
ttApqm5T+3wz2YDu6AyD6yL8MFMp7PXH0JchmXA/RLQZBD+tEP/N+n00AyTaij3J
KRIIJQ17Q7vzgqFkHXCsQJ0XbIrUBeWpj7EUBltwRYGBGwSwmMCSAHLXexc70GNZ
KUXMZ5hP3syAq632RxSNhOCuALLCH4MNJapoS3lZtaEivGczVEOjAuzpqnc5w4OZ
Ct6PHSezanLwFN/qOr+wHriac0LO//TOulL2cOt61KgtV5pshjmzB9EhSodwqCqp
+UCTQbU/JQbLA40dlSTreJ13n7PVWAoI8rAnfgXSNSUYvrswfxc8t8ajWGF8e2qA
IoCAAQKBgQCr7J4JWfOtsMh6fJ48IvHoxSuqiVZmoFqrdGORrEC2PZ3cLzrLHC4a
+a25DDlyJVJjBEtNAM346C4hxy6PA4V0/RVVKuN21TVv2wNo3Z9QnDHdl4C0Uttj
bDYbt38kX66qbZlOcxrerc0YTRb7Zxc6q77YmyuyInPceh0AKPfvYQKBgQCi5cpw
OP2bG3CVGAzsOD4a5gacAS0J64j27pJsYVHenNVjr55Q/MtnaTmSm6vvUdCxxW/h
YTkGLFUx0m7KQbi4luc5REbg4ZFKk0tCN6jhcJxe4N5r0snf2jVPCqcArsoTqTIF
8RRPIkjGT70n57PIqqo5boALVaxgx7LGvmOKgQKBgDipOAB++9dvnvL3ZTMOlUmQ
ye5favFRwfAl4Lbe3Ujyj7dEfYz5EZzkUsPc6oXbFQb7IFIVhMyWwLVzLr4FfBNt
YX17MBI2/HCL7ti9ycbIY4rTZqCHejSPMln6JNX5DtiuXEtFlkJzZ1et+HgMptQ4
TCKZKVKBFkxAlpQ57FShAoGAC9vUr/TGKZuGx6PXlP7HLqgeRQ8k2zsFXoyhpjgz
gJRESJyJVvYATMfxRAYHL0Xyfm6UJYExaIyjqxvZqum769w4ewfIbSieriIo8Woh
5j+PcqzGJG1U+vHkvZtV6wvOdD32AU66nsQtLhqx94y7ntklyUaNFcYn5WfEUQmd
L4ECgYB6vX1ox9Ba7MVnfq10OjOIZH6dqm8m7J0FbZQlXbAsSotHSuGTUhzUsxQ9
bhe38s8GaNih8NNB/jf0fj7DMojy1t0/9e4fiBvfp7AVHCbel8QMyaFXC82geVZv
zspK3wkls4sR0XqdnvL87wn1Sd5/aXnRZs/nA6pT7oWKTqs6LQ==
-----END RSA PRIVATE KEY-----"""

alicePublicKey = """-----BEGIN PUBLIC KEY-----
MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBtZg6fW8hDisvVgj1BS7c1
tyIvTYMq3ztvD1uYOF3sJz+WXwi1YhMLYtEUg9566x0EPVNLFMkIuWJBZHy19fxv
xnp4gQXA5SJqqLkbEQluM2n7c2UAHeMvP4clcQi/P0ItGqytZx8A8amP2pRMKDjO
RcvuvYD6bfLNnAORDOVNICRLc1PMHNCtKpy6RGOePmS/u+qvSr8cgWZTHEDJbHZC
xFPG1hGsiqpjkSDanAfMAJI5i5IXekyFUT4N+8OY+KeLTopVvJ0i0B5LAJBZpRK/
PftLXKupVEvB5okO3qSDPn+6sUekute3amcTBzwI6uBtQgKmBxsdQss+JbvcfOnh
AgMBAAE=
-----END PUBLIC KEY-----"""

bobPublicKey = """-----BEGIN PUBLIC KEY-----
MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQB0bzAxHFzZb3XvSfqo7tUI
iCHFXsgDdP3niTXe9QW0wNvhIgMGFd4k05N/ZgHkvwG+2xpoPkZoK1dRLJ9C+oUR
l1jMseUJ2WnA22smM6QO6CAd6qw+FxzrALl6ZxibwaokgpDY2QorZesKRNys/vKM
qgNDh5yX65jUXI+fCofThvP9TDO7H1W5jMZHfyG+X4m7P8/9kCyCknLavb94CLiw
tlM9Iq1+yB9cA0oW9sZwZ2aWK8pu0229slBq898mqOqlLhS4lNVluuQdlGmbYmk/
++e1yOdS3M0EuDE6mHcSx3QTR1Qnv5eLkgi/8wg2s2X1DYdxW4ShjnLp/nmNBPuD
AgMBAAE=
-----END PUBLIC KEY-----"""

# Start assignment
# Step 1: Set up shared secret keys for encryption
encryptKey = str(os.urandom(16))

message = 'a'*2000

def RSAEnc(plainText):
	key = RSA.importKey(bobPublicKey)
	cipher = PKCS1_OAEP.new(key, SHA256)
	return cipher.encrypt(plainText)

def DHCalc(a, g, p):
	return pow(g, a, p)

def DHSecretKey(value, b, p):
	return pow(value, b, p)

def DH(bobvalue, g, p):
	a = random.SystemRandom().randint(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, p-2)
	aliceValue = DHCalc(a, g, p)
	tempSecretKey = DHSecretKey(bobvalue, a, p)
	hash = SHA256.new()
	hash.update(str(tempSecretKey))
	longSecretKey = hash.hexdigest()
	returnKey = longSecretKey[0:16]
	clientSocket.send(str(aliceValue))
	return returnKey

cipherText = RSAEnc(encryptKey)
clientSocket.send(cipherText)
pickleString = clientSocket.recv(4096)
# (bobvalue, g, p)
data = pickle.loads(pickleString)
decryptKey = DH(data[0], data[1], data[2])
print 'Encrypt Key" ', encryptKey
print 'Decrypt Key: ', decryptKey

signKey = str(os.urandom(16))
signCipherText = RSAEnc(signKey)
clientSocket.send(signCipherText)
pickleString = clientSocket.recv(4096)
# (bobvalue, g, p)
data = pickle.loads(pickleString)
verifySigKey = DH(data[0], data[1], data[2])
print 'verifySigKey: ', verifySigKey
print 'signature key: ', signKey

# End assignment
clientSocket.close()

