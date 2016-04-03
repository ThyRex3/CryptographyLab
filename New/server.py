import sys, string, random, pickle

from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from socket import *

# Global Variables
encryptKey = ""	
decryptKey = ""
signKey = ""
verifySigKey = ""
# g = shared base
g = 2	
# p = shared prime
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF

# Set port number by converting argument string to integer
serverPort = 5711
# Choose SOCK_STREAM, which is TCP
serverSocket = socket(AF_INET, SOCK_STREAM)
# Start listening on specified port
serverSocket.bind(('', serverPort))
#Listener begins listening
serverSocket.listen(1)

# Wait for connection and create a new socket
# It blocks here waiting for connection
connectionSocket, addr =serverSocket.accept()

bobPrivateKey = """-----BEGIN RSA PRIVATE KEY-----
MIIEoQIBAAKCAQB0bzAxHFzZb3XvSfqo7tUIiCHFXsgDdP3niTXe9QW0wNvhIgMG
Fd4k05N/ZgHkvwG+2xpoPkZoK1dRLJ9C+oURl1jMseUJ2WnA22smM6QO6CAd6qw+
FxzrALl6ZxibwaokgpDY2QorZesKRNys/vKMqgNDh5yX65jUXI+fCofThvP9TDO7
H1W5jMZHfyG+X4m7P8/9kCyCknLavb94CLiwtlM9Iq1+yB9cA0oW9sZwZ2aWK8pu
0229slBq898mqOqlLhS4lNVluuQdlGmbYmk/++e1yOdS3M0EuDE6mHcSx3QTR1Qn
v5eLkgi/8wg2s2X1DYdxW4ShjnLp/nmNBPuDAgMBAAECggEAHJg97qG3j9LW1NiH
Tbux5/F+0bkQSAEQZi+FYmcsapK+rVCsC2+Nad/oJm6H4oSiShwHJTi+E9EpFY9u
4YUi7woLTeIWjM+vMCTy8KPYE60gThiXCnykpnY8FvqAyafLQEIsjoTnAXd7PL9i
rr3CFZefS5NfetPqaaT9xKJSbzktFjLeGZj8swEVTUwihaVKvxcNWGjlxieaf093
VsDvbR8X4nzU9G+LJwYuiVNNAysvc6Kh8cwhM62R+JRKmA5JRHK0onLElut6w8Ve
+R1lKCUW6VDaGOpTXm4sPgA9CijRISOUb5AbTXOhYZs9j/qha6HbOXtjKxZajs6U
mfJE2QKBgQDBMoFRsqQWNUid395H3d+qAwnXXc6XSztx/pVLZaCR6YitqITvYmm8
z4rvu52AVKdipMkk9FdR1lCYKuKSnQOQ2MW26JWDEVntal3VSkUhFIunc2vkHxO1
w1GVfdznRx1/P3m+6KBjk/xC9+/lezJQthnjV+sGU5jSSdU+E6eWDwKBgQCaSJ9D
4HIdFM20ScRCfcbShx0ScoRT4BNxK6eTg4HFwNLfqIzkP4MV7C855sN4TINr10Re
b/hU2UsDHYhNN1IUfHuQKsOUaAFQCaA+e5ONJL0CpopSJTGBnq2l1aIUkaB0xbsz
8zIuM0++OO6NGvdh18iqnYJsrHI0l65jHkaXTQKBgACduZ3aFP3hI58lRJ80DO+M
3O4r5WnEGqdtaWp5I37zoLT1EZ91z+KDQu0qywDKxFHjNqUAhnrDVTR3BovzJjzD
BDZmHXvyhTflm/D/MKM/XoalLpXmp3hv7AWvBhJSvrxWJnw+X6yRnz9TbRdtQibR
vdlkwWIeyCD7jUuKYoFvAoGAT4tTuc41Z3L7X5GMw29Pm+mXfpRWT1w/CeElA/QQ
a2GwFyoygdeRATOFYcftTc+9DlOtZzc5hJ2HhDKsvIriIbfQiRLTRWeeDaL44F4c
Q/AGFyDAPfv5G0gxZUfQyeQPI0Vy8CTZ4WIJIhz+OPgHRYXYasbMoLUEKMNvYKES
ah0CgYAV20SblnVjGHj1ExxxLqbzX+usO6HNZrLVqIsCH8rr3vOYOzoDT48EfJ5+
gd+FxCN/TGfALW49ViyGXTLTub5H587OqAIR1GdOPpk+DTEWFz5q+p280uVKXBzb
3/qaClaSrFMsOPq/vOhaimW8EoLQWCTL0Hu3RdBfWbO6h7JCew==
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

# RSA Decryption of message from Alice to Bob
def RSADec(cipherText):
	key = RSA.importKey(bobPrivateKey)
	cipher = PKCS1_OAEP.new(key, SHA256)
	return cipher.decrypt(cipherText)

# g ^ b % p
def DHCalc(b):
	return pow(g, b, p)

# Add padding for AES Encryption
# 1 followed by 0's
def addPadding(plainText):
	padding = 16 - len(plainText) % 16
	pad = "1"
	while padding > 0:
		plainText += pad
		padding -= 1
		pad = "0"
	return plainText

# Remove padding (1 followed by 0's) for AES Decryption
def remPadding(padPlainText):
	position = len(padPlainText) - 1
	count = 0
	while position >= 0:
		if padPlainText[position] != '1':
			position -= 1
			count += 1
		else:
			count += 1
			return padPlainText[:-count]
	return padPlainText

# Add necessary padding before AES encryption
def AESEnc(plainText):
	paddedMessage = addPadding(plainText)
	cipher = AES.new(encryptKey)
	return cipher.encrypt(paddedMessage)

# Decrypt cipherText before removal of padding
def AESDec(cipherText):
	cipher = AES.new(decryptKey)
	message = cipher.decrypt(cipherText)
	return remPadding(message)

# value ^ b % p
def DHSecretKey(value, b):
	return pow(value, b, p)

# Because Alice signed her message via RSA,
# this verify Signature method is specific for RSA signature
def verifySignature(signature, plainText):
	key = RSA.importKey(alicePublicKey)
	hash = SHA256.new()
	hash.update(plainText)
	verifier = PKCS1_PSS.new(key)
	if verifier.verify(hash, signature):
		return True
	else:
		return False

# Diffie-Hellman Protocol
def DH():
	b = random.SystemRandom().randint(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, p-2)
	bobValue = DHCalc(b)
	data = (bobValue, g, p)
	pickleString = pickle.dumps(data, -1)
	# Send Bob's value, shared prime, and shared base to Alice.
	connectionSocket.send(pickleString)
	aliceValueStr = connectionSocket.recv(4096)
	# Chance what is received from string to integer
	aliceValue = int(aliceValueStr)
	tempSecretKey = DHSecretKey(aliceValue, b)
	hash = SHA256.new()
	hash.update(str(tempSecretKey))
	longSecretKey = hash.hexdigest()
	returnKey = longSecretKey[0:16]
	return returnKey

# Hash plainText with signature key via SHA-256
# Returns a HMAC signature
def HMACSign(plainText):
	hash = HMAC.new(signKey, plainText, SHA256)
	return hash.hexdigest()

# Send plainText message by generating an HMAC signature,
# encrpyt plainText via AES
# send cipherText from Bob to Alice
def sendMessage(plainText):
	signature = HMACSign(plainText)
	cipherText = AESEnc(plainText)
	data = (cipherText, signature)
	pickleString = pickle.dumps(data, -1)
	print "Bob's AES Encrypted Message CipherText: "
	print cipherText
	print
	print "Bob's HMAC SHA-256 Hashed Message Signature: "
	print signature
	print
	print "Bob's Encrypt Key: "
	print encryptKey
	print 
	print "Bob's RSA Private Key: "
	print bobPrivateKey
	print
	connectionSocket.send(pickleString)

# Receive cipherText from Bob to be decrypted and then verifies signature
def recvMessage(message):
	# Data = (0) cipherText (1) signature
	data = pickle.loads(message)
	print "Received Alice's AES Encrypted Message (CipherText): "
	print data[0]
	print
	print "Alice's RSA SHA-256 Hashed Signature: "
	print data[1]
	plainText = AESDec(data[0])
	if(verifySignature(data[1], plainText)):
		print
		print "Authenticated Signature."
		print "Printing plaintext message from Alice to Bob: "
		print plainText
		print
		print "Bob's Decrypt Key: "
		print decryptKey
		print
		print "Bob's Verification Signature Key: "
		print verifySigKey
		print
	else:
		print "Unauthenticated Signature"
		print 

# Receive a message that is supposedly Alice's RSA Encrypted Key
cipherText = connectionSocket.recv(4096)
decryptKey = RSADec(cipherText)
encryptKey = DH()

aliceEncSignKey = connectionSocket.recv(4096)
verifySigKey = RSADec(aliceEncSignKey)
signKey = DH();
print 'Signature key: ', signKey
print

lastMessage = connectionSocket.recv(4096)
message = 'b' * 1000

# Decrypt and print 2000 byte message from Alice to Bob
recvMessage(lastMessage)
# Encrypt and print 1000 byte message from Bob to Alice
sendMessage(message)
connectionSocket.close()