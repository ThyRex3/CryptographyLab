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
aliceSharedSecret = (B ** aliceSecret) % sharedPrime
 
# Bob Computes Shared Secret: s = A^b mod p
bobSharedSecret = (A**bobSecret) % sharedPrime