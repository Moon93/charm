'''
Base class for VerifiableProofOfRetrievability
 
Notes: This class implements an interface for a verifiable proof of retrievability scheme.
A verifiable proof of retrievability scheme consists of four algorithms: (keygen, generateVerifiers, proove, verify).
'''
from charm.core.math.integer import *
from random import randint

class VerifiableProofOfRetrievability():
    def __init__(self,bit=80):
        self.p =int(integer(randomPrime(bit)))
		self.group = PairingGroup('SS512')
		self.g = group.random(G1)
		self.u = group.random(G1)
	
	
	
	

    def _getRandomInt(self,range):
        return int(integer(random(range)))    

    def setP(self,p):
        if isPrime(p):
           self.p = p
        else:
            raise BaseException("p is not Prime")

    def keygen(self):
		x = self.group.random(G1) #privateKey
		v = self.g**x #publicKey
        return (x, v)

    def splitMessage(self,M):
        message = []
        while M!=0:
             messageBlock = M % self.p
             message.append(messageBlock)
             M = M - messageBlock
             if M!=0:
                  M=M//int(self.p)
        message.reverse()
        return message

	def generateSignature(self,splitMessage,i,x)
		#return sigma_i
		return (self.group.hash(i,G1)*self.u**splitMessage[i])**x
        
    def generateVerifiers(self,splitMessage):
        return NotImplemented
    
    def compositeMessage(self, splitMessage):
        message = 0
        i=0
        while i<len(splitMessage)-1: #for m in splitM | geht leider nicht
             message=(message+splitMessage[i])*self.p
             i=i+1
        message=(message+splitMessage[len(splitMessage)-1])
        return message

    def genChallenge(self,splitMessage,amount):
        challange = []
       	if amount>len(splitMessage):
       		raise BaseException("Amount bigger than number of message blocks")
       	for counter in range(0,amount):
       		i = randint(0,len(splitMessage))
       		vi = group.random(G1)
       		challenge.append((i,vi))
        return challange
    
    def proove(self, splitMessage, challenge, x):
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
    	a = self.group.pair_prod(response[0], self.g)
		temp=1
    	for (i, vi) in challenge:
	    	temp =temp* (self.group.hash(i,G1)**vi)*self.u**response[1])
    	b = self.groupo.pair_prod(temp, v)
        return a==b
