import socket

HOST = '127.0.0.1'    # The remote host
PORT = 50007              # The same port as used by the server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

class DiffieHellman(object):

	def __init__(self, generator=2, group=17, keyLength=540):
		self.prime = 23    	# p
		self.generator = 5;	# g

		self.prime = self.getPrime(group)

		self.privateKey = self.genPrivateKey(keyLength)
		self.publicKey = self.genPublicKey()

	def genRandom(self, bits):
		"""
		Generate a random number with the specified number of bits
		"""
		_rand = 0
		_bytes = bits // 8 + 8

		while(_rand.bit_length() < bits):
			try:
				# Python 3
				_rand = int.from_bytes(random_function(_bytes), byteorder='big')
			except:
				# Python 2
				_rand = int(OpenSSL.rand.bytes(_bytes).encode('hex'), 16)

		return _rand

	def genPrivateKey(self, bits):
		"""
		Generate a private key using a secure random number generator.
		"""
		return self.genRandom(bits)

	def genPublicKey(self):
		"""
		Generate a public key X with g**x % p.
		"""
		return pow(self.generator, self.privateKey, self.prime)

	def checkPublicKey(self, otherKey):
		"""
		Check the other party's public key to make sure it's valid.
		Since a safe prime is used, verify that the Legendre symbol == 1
		"""
		if(otherKey > 2 and otherKey < self.prime - 1):
			if(pow(otherKey, (self.prime - 1)//2, self.prime) == 1):
				return True
		return False

	def genSecret(self, privateKey, otherKey):
		"""
		Check to make sure the public key is valid, then combine it with the
		private key to generate a shared secret.
		"""
		if(self.checkPublicKey(otherKey) == True):
			sharedSecret = pow(otherKey, privateKey, self.prime)
			return sharedSecret
		else:
			raise Exception("Invalid public key.")

	def genKey(self, otherKey):
		"""
		Derive the shared secret, then hash it to obtain the shared key.
		"""
		self.sharedSecret = self.genSecret(self.privateKey, otherKey)

		# Convert the shared secret (int) to an array of bytes in network order
		# Otherwise hashlib can't hash it.
		try:
			_sharedSecretBytes = self.sharedSecret.to_bytes(
				self.sharedSecret.bit_length() // 8 + 1, byteorder="big")
		except AttributeError:
			_sharedSecretBytes = str(self.sharedSecret)

		s = hashlib.sha256()
		s.update(bytes(_sharedSecretBytes))
		self.key = s.digest()

	def getKey(self):
		"""
		Return the shared secret key
		"""
		return self.key

	def showParams(self):
		"""
		Show the parameters of the Diffie Hellman agreement.
		"""
		print("Parameters:")
		print("Prime[{0}]: {1}".format(self.prime.bit_length(), self.prime))
		print("Generator[{0}]: {1}\n".format(self.generator.bit_length(),
			self.generator))
		print("Private key[{0}]: {1}\n".format(self.privateKey.bit_length(),
			self.privateKey))
		print("Public key[{0}]: {1}".format(self.publicKey.bit_length(),
			self.publicKey))

	def showResults(self):
		"""
		Show the results of a Diffie-Hellman exchange.
		"""
		print("Results:")
		print("Shared secret[{0}]: {1}".format(self.sharedSecret.bit_length(),
			self.sharedSecret))
		print("Shared key[{0}]: {1}".format(len(self.key), hexlify(self.key)))


s.sendall('Hello, world')
data = s.recv(1024)
s.close()
print 'Received', repr(data)

# https://github.com/lowazo/pyDHE/blob/master/DiffieHellman.py