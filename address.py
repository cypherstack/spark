# Address generation

from dumb25519 import Point, random_scalar

class AddressParameters:
	def __init__(self,F,G):
		if not isinstance(F,Point):
			raise TypeError('Bad type for parameter G!')
		if not isinstance(G,Point):
			raise TypeError('Bad type for parameter F!')
		
		self.F = F
		self.G = G

class SpendKey:
	def __init__(self):
		self.s1 = random_scalar()
		self.s2 = random_scalar()
		self.r = random_scalar()

class FullViewKey:
	def __init__(self,params,spend):
		if not isinstance(params,AddressParameters):
			raise TypeError('Bad type for parameters!')
		if not isinstance(spend,SpendKey):
			raise TypeError('Bad type for spend key!')
		
		self.s1 = spend.s1
		self.s2 = spend.s2
		self.D = spend.r*params.G

class IncomingViewKey:
	def __init__(self,full):
		if not isinstance(full,FullViewKey):
			raise TypeError('Bad type for full view key!')
		
		self.s1 = full.s1

class PublicAddress:
	def __init__(self,params,spend):
		if not isinstance(params,AddressParameters):
			raise TypeError('Bad type for parameters!')
		if not isinstance(spend,SpendKey):
			raise TypeError('Bad type for spend key!')

		self.Q1 = spend.s1*params.F
		self.Q2 = spend.s2*params.F + spend.r*params.G
