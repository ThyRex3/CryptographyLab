import socket
from random import getrandbits

HOST = '127.0.0.1'    # The remote host
PORT = 50007              # The same port as used by the server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
sharedPrime = 23	#p
sharedBase = 5		#g

aliceSecret = 6		#a
bobSecret = 15		#b

# Alice sends Bob: A = g^a mod p
A = (sharedBase**aliceSecret) % sharedPrime

# Bob sends Alice: B = g^b mod p
B = (sharedBase**bobSecret) & sharedPrime

#Alice computes shared Secret Key: s = B^a mod p
aliceSharedSecret = (B ** aliceSecret) % sharedPrime

#Bob computes shared Secret Key: s = A^b mod p
bobSharedSecret = (A ** bobSecret) % sharedPrime

#Send shared Secret Key from Bob to Alice
s.sendall('%d' %bobSharedSecret)
data = s.recv(1024)
s.close()
print 'Received', repr(data)

# https://github.com/lowazo/pyDHE/blob/master/DiffieHellman.py
# https://github.com/lowazo/pyDHE/blob/master/simpleDH.py