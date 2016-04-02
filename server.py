import socket
import rsa
import Crypto
from Crypto.PublicKey import RSA
import ast
from random import getrandbits
import sys
import time
from socket import error as socket_error

def RSAEnc(plaintext, publicKey):
   holder = rsa.PublicKey.load_pkcs1_openssl_pem(publicKey)
   cipherText = rsa.encrypt(plaintext, holder)
   return cipherText

def RSADec(cipherText, privateKey):
   holder = rsa.PrivateKey.load_pkcs1(privateKey, "PEM")
   plaintext = rsa.decrypt(cipherText, holder)
   return plaintext

def DHCalc(g, p, x):
   return ((int(g)**int(x)) % int(p))

def AESEnc(key, plainText, iv):
        encryption_suite = AES.new(key=key, mode=AES.MODE_CBC, IV=iv)
        cipherText = encryption_suite.encrypt(plainText)

def AESDec(key, cipherText, iv):
        decryption_suite = AES.new(key=key, mode=AES.MODE_CBC, IV=iv)
        plainText = decryption_suite.decrypt(cipherText)

#def VerifyAndDecrypt(pubKey, hash, ciphertext):
	


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

bobPublicKey =  """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkr8IivGI753PxologDYiEG18V
DRlCeNBJ9TCxlHRkVVfNTyBwAlUqFNkLodLoNwQFKQrAQvS4d0uhMGfY7chS++qN
EWa2+55yI6dYKDwkOXbyRfetaDiRJqvxBIUCpl9tTc0BafSfp8XDnFNtLIbVZoei
G1BX5485bHGRqhXL7QIDAQAB
-----END PUBLIC KEY-----"""

alicePrivateKey =  """-----BEGIN RSA PRIVATE KEY-----
MIICWgIBAAKBgH1LaxDblUH8MtKCq4HuqLHqcfFo67939uV3Svfby3zfqDuWNJmW
w7lNS0iRTQ8eQ4px6pDHGaN5oYrUU/TArYx1nTOdM40nCEwDh+jf612jCAOykrgN
+4RKjXqsctrPpHc8CfEEIBEVIUXBomd8iEzn/S62TJCV9FmE9a+HiwDhAgMBAAEC
gYB2RMhtgzhirtKyTtHhtgva1Th07dsKQwz1ESPczsZHuz6r8F76U4uw0Dst5qnc
iW6rslf+DVIwM1G/ICmXsICf4H4b8RNYOzyQtlyAXpLiofNxLGywoNrNwC/4h2nC
ppPDQocWv//ncnHRbBVHt/JrDY3DEd8rLgUImBip/YnbIQJBAPSiCT02T4lvVn7U
cKqYDZrz4j63U0DAj8AdNeCXYdoeCTMUFC0tyC4pgpsWIKznhMkP6g7zowzkWfMZ
sKmf9dUCQQCDHdNeHQiV9HsMH8oIkby3BLcXjMeCSf/XpIxfuUxyXa1VFglOAD/f
AkYkl4AWaHKkMQI2KloLIobefHOSoKjdAkB4CaJ69NFmYMmShm+aZe4XIKDdoVsq
pNJktHCheea7/o0JEUstOA/IBvpdWyhBb4FKn5J8L7TMOKiijvKO6TzZAkBO6mOu
kID7aGOq/3MlRzozWaYtiXEHTSysiQBoGOoXJ6TMwm+lP+cxfXfkTD8uvXzKsCip
m0II06YjQPp6tTINAkAJHfsmZeSYIV13BXE2heZF2AY1w7kWimwP29OPQCAP30H8
VADrZltqk9Uz0HJI6OKurPQXTP8W4mJmbauslg3Z
-----END RSA PRIVATE KEY-----"""

alicePublicKey = """-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgH1LaxDblUH8MtKCq4HuqLHqcfFo
67939uV3Svfby3zfqDuWNJmWw7lNS0iRTQ8eQ4px6pDHGaN5oYrUU/TArYx1nTOd
M40nCEwDh+jf612jCAOykrgN+4RKjXqsctrPpHc8CfEEIBEVIUXBomd8iEzn/S62
TJCV9FmE9a+HiwDhAgMBAAE=
-----END PUBLIC KEY-----"""


DH_B = 47
g = "13"
p = "31"
HOST = ''                 # Symbolic name meaning all available interfaces
PORT = 50007              # Arbitrary non-privileged port
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(1)

connected = False

while not connected:
    conn, addr = s.accept()
    data = conn.recv(1024)
    hash = conn.recv(10000)
    print(hash)
    print(RSADec(hash, bobPrivateKey))
  
    AESSecret = RSADec(hash, bobPrivateKey)

    conn.sendall(g)
    conn.sendall(p)
    conn.sendall(str(DHCalc(int(g), int(p), DH_B)))
    exponA = conn.recv(10)
    print("bob num = ", DHCalc(int(g), int(p), DH_B))
    print("received alice number, ", exponA)

    sharedSecret = DHCalc(exponA, p, DH_B)
    print "Shared secret", sharedSecret
	
    #receive encoded Message
    codedMessage = conn.recv(2688)
    print "codedMessage = ", codedMessage
    print "\n message length = ", len(codedMessage), "\n"
    #receive signature
    signature = conn.recv(2048)

    print "message = ", codedMessage
    print "sig = ", signature

#    conn.sendall(data)
conn.close()

