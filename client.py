import socket

HOST = '127.0.0.1'    # The remote host
PORT = 50007              # The same port as used by the server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
# Variables Used
sharedPrime = 23    # p
sharedBase = 5      # g
 
aliceSecret = 6     # a
bobSecret = 15      # b
 
# Begin
 
# Alice Sends Bob A = g^a mod p
A = (sharedBase**aliceSecret) % sharedPrime
 
# Bob Sends Alice B = g^b mod p
B = (sharedBase ** bobSecret) % sharedPrime
 
# Alice Computes Shared Secret: s = B^a mod p
aliceSharedSecret = (B**aliceSecret) % sharedPrime
 
# Bob Computes Shared Secret: s = A^b mod p
bobSharedSecret = (A**bobSecret) % sharedPrime
s.sendall('Hello, world')
data = s.recv(1024)
s.close()
print 'Received', repr(data)