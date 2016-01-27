'''
Base class for VerifiableProofOfRetrievability
 
Notes: This class implements an interface for a verifiable proof of retrievability scheme.
A verifiable proof of retrievability scheme consists of four algorithms: (keygen, generateVerifiers, proove, verify).
'''
from charm.core.math.integer import *
from charm.toolbox.pairinggroup import *
from random import randint
import sys

class VerifiableProofOfRetrievability():
	"""This class implements an interface for verifiable proof of retrievability scheme"""

	def __init__(self,bit=80):
		"""Initializes the class"""
		
		self.bit = bit
		self.p = int(randomPrime(2*bit))
		self.group = PairingGroup('SS512')
		self.g = self.group.random(G1)
		self.u = self.group.random(G1)
	
	def getRandomInt(self, maximum):
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
		x = int(randomPrime(self.bit)) #privateKey x element Zp
		v = self.g**x #publicKey
		return (x, v)

	def splitMessage(self,M):
		"""splits message M in blocks mi \elem Zp

		args:
			M: the message to be split, MUST BE BYTES
		"""
		message = []
		if not isinstance(M, bytes):
			raise BaseException("M must be Bytes");
		i = 0;
		while i<len(M): #solange es noch weitere bytes gibt
			mi = M[i] #mi ist ein byte
			while mi<self.p and i<len(M)-1: #mi kleiner als p? dann vielleicht noch ein byte dran hängen!
				mi = mi<<8 #shift 1 byte
				i+=1
				mi = mi|M[i] # das nächste byte an mi dran hängen
				if mi>self.p: #wenn mi jetzt doch zu groß geworden ist
					i-=1
					mi = mi>>8
					break #innere schleife verlassen
			message.append(mi)
			i+=1
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
		return (self.group.hash(str(i),G1)*self.u**splitMessage[i])**x

	def generateChallenge(self,splitMessage,amount):
		"""generates a challenge
		
			args:
				splitMessage: list with messageblocks
				amount: amount of signatures within the challenge
			returns:
				challenge: a list of index-factor pairs
		"""
		challenge = []
		if amount>len(splitMessage):
			raise BaseException("Amount bigger than number of message blocks")
		for counter in range(0,amount):
				i = randint(0,len(splitMessage))
				vi = self.getRandomInt(self.p)
				challenge.append((i,vi))
		return challenge
	
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
		y = 0
		for (i,vi) in challenge:
			y_i = vi*splitMessage[i]
			y=y+y_i
		return (sigma, y)

	def verify (self, response, challenge, v):
		"""wrapper for the check function"""
		touple = self.check(response, challenge, v)
		return touple[0]==touple[1]
		
	def check(self, response, challenge, v):
		"""generates e(sigma,g) and e(..., v) to proove that the response is correct
		
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
			temp =temp* ((self.group.hash(str(i),G1)**vi)*self.u**response[1])
		b = self.group.pair_prod(temp, v)
		return (a,b)
