'''
Base class for VerifiableProofOfRetrievability
 
Notes: This class implements an interface for a verifiable proof of retrievability scheme.
A verifiable proof of retrievability scheme consists of four algorithms: (keygen, generateVerifiers, proove, verify).
'''
from charm.core.math.integer import *
from charm.toolbox.pairinggroup import *
from random import randint

class VerifiableProofOfRetrievability():
	"""This class implements an interface for verifiable proof of retrievability scheme"""

	def __init__(self,bit=80):
		"""Initializes the class"""
		self.p =int(integer(randomPrime(bit)))
		self.group = PairingGroup('SS512')
		self.g = self.group.random(G1)
		self.u = self.group.random(G1)
	
	def _getRandomInt(self,maximum):
		"""returns a random integer within 0 and maximum
	
		args:
			range: the range within the number should be
		"""
		return randint(0,maximum)	

	def setP(self,p):
		"""allows to set p to a specific value
	
		args:
			p: must be prime
		raises:
			BaseException: if p is not prime
		"""
		if isPrime(p):
			self.p = p
		else:
			raise BaseException("p is not Prime")

	def keygen(self):
		"""generates a public and private key pair"""
		x = self.group.random(G1) #privateKey
		v = self.g**x #publicKey
		return (x, v)

	def splitMessage(self,M):
		"""splits message M in blocks with the length of p

		args:
			M: the message to be split
		"""
		message = []
		while M!=0:
			 messageBlock = M % self.p
			 message.append(messageBlock)
			 M = M - messageBlock
			 if M!=0:
				  M=M//int(self.p)
		message.reverse()
		return message

	def generateSignature(self,splitMessage,i,x):
		"""generates s signature

		args:
			splitMessage: the list with the message blocks
			i: index of the message block wich should be used
			x: private key
		returns:
			sigma at the index i
		"""
		#return sigma_i
		return (self.group.hash(i,G1)*self.u**splitMessage[i])**x
	
	def compositeMessage(self, splitMessage):
		"""returns one string with the complete message built from the single blocks"""
		message = 0
		i=0
		while i<len(splitMessage)-1: #for m in splitM | geht leider nicht
			 message=(message+splitMessage[i])*self.p
			 i=i+1
		message=(message+splitMessage[len(splitMessage)-1])
		return message

	def genChallenge(self,splitMessage,amount):
		"""generates a challenge
		
			args:
				splitMessage: list with messageblocks
				amount: amount of signatures within the challenge
			returns:
				challenge: a list of index-factor pairs
		"""
		challange = []
		if amount>len(splitMessage):
			raise BaseException("Amount bigger than number of message blocks")
		for counter in range(0,amount):
				i = randint(0,len(splitMessage))
				vi = group.random(G1)
				challenge.append((i,vi))
		return challange
	
	def proove(self, splitMessage, challenge, x):
		"""proove that you can solve the challenge
		
			args:
				splitMessage: list of messageblocks
				challenge: challenge got by the verifier
				x: private key
			returns:
				(sigma, y)
		"""
		#erzeuge sigma
		sigma = 1
		for (i,vi) in challenge:
			sigma_i = self.generateSignature(splitMessage,i,x)
			sigma = sigma * (sigma_i**vi)
		#erzeuge mü
		for (i,vi) in challenge:
			y_i = vi*splitMessage[i]
			y=y+y_i
		return (sigma, y)

	def verify(self, response, challenge, v):
		"""verify that the proove is correct
		
			args:
				response: the response gotten from the server/proover
				challenge: the used challenge
				v: public key of the server
			returns:
				true if the proove was correct
		"""
		a = self.group.pair_prod(response[0], self.g)
		temp=1
		for (i, vi) in challenge:
			temp =temp* ((self.group.hash(i,G1)**vi)*self.u**response[1])
		b = self.groupo.pair_prod(temp, v)
		return a==b
