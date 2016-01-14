'''
Base class for VerifiableProofOfRetrievability
 
Notes: This class implements an interface for a verifiable proof of retrievability scheme.
A verifiable proof of retrievability scheme consists of four algorithms: (keygen, generateVerifiers, proove, verify).
'''
from charm.core.math.integer import *

class VerifiableProofOfRetrievability():
    def __init__(self,bit=80):
        self.p =int(integer(randomPrime(bit)))

    def _getRandomInt(self,range):
        return int(integer(random(range)))    

    def setP(self,p):
        if isPrime(p):
           self.p = p
        else:
            raise BaseException("p is not Prime")

    def keygen(self):
        return NotImplemented

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

    def genChallange(self,amountMessageBlocks,amount):
        challange = []
        # ueberpruefen ob amount > amountMessageBlocks 
        if amount > amountMessageBlocks:
             raise BaseException("The amount of challanges is bigger then the amount of message blocks")
        # waehlen, so dass alle Massage  Block Positionen unterschiedlich
        ableBlockPositions = list(range(amountMessageBlocks))#Liste mit allen Moeglichen Message Block Positionen
        for i in range(amount):
            blockPosition = ableBlockPositions[self._getRandomInt(len(ableBlockPositions))]# Waehlt Zufaellig eine Position in der ableBlockPositions Liste
            ableBlockPositions.remove(blockPosition) # entfernt die ausgewaehlte Message Block Position
            coifficient = self._getRandomInt(self.p) #erzeugt einen zufaelligen Koifizienten
            challange.append((blockPosition,coifficient))
        return challange
    
    def proove(self, splitMessage, verifier, challange):
        return NotImplemented

    def verify(self, response, challange):
        return NotImplemented
