'''
Base class for proof of retrievability

Notes: 4 algorithms: (Kg, St, P, V)
'''

from charm.toolbox.schemebase import *

porSchemeType = "PORScheme"

class POR(SchemeBase):
	def __init__(self):
		SchemeBase.__init__(self)
		SchemeBase._setProperty(self, scheme='POR')

	#keygen
	def Keygen(self):
		raise NotImplementedError

	#store
	def Store(self, sk, M):
		''' return 0 or 1, 1 if the file is stored on the server
		also returns t and the processed m
		'''
		raise NotImplementedError

	#verify
	def Verify(self, pK, sK, t):
		raise NotImplementedError

	#prove
	def Prove(self, pk, t, m):
		raise NotImplementedError
