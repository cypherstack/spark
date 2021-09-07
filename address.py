# Address generation

from dumb25519 import Point, Scalar, random_scalar

class AddressParameters:
	def __init__(self,G,F):
		if not isinstance(G,Point):
			raise TypeError('Bad type for parameter G!')
		if not isinstance(F,Point):
			raise TypeError('Bad type for parameter F!')
		
		self.G = G
		self.F = F

class SpendKey:
	def __init__(self,s1,s2,r):
		if not isinstance(s1,Scalar):
			raise TypeError('Bad type for spend key s1!')
		if not isinstance(s2,Scalar):
			raise TypeError('Bad type for spend key s2!')
		if not isinstance(r,Scalar):
			raise TypeError('Bad type for spend key r!')
		
		self.s1 = s1
		self.s2 = s2
		self.r = r

class FullViewKey:
	def __init__(self,params,spend):
		if not isinstance(params,AddressParameters):
			raise TypeError('Bad type for parameters!')
		if not isinstance(spend,SpendKey):
			raise TypeError('Bad type for spend key!')
		
		self.s1 = spend.s1
		self.s2 = spend.s2
		self.D = spend.r*params.F

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

		self.Q1 = spend.s1*params.G
		self.Q2 = spend.s2*params.G + spend.r*params.F

def generate(params):
	if not isinstance(params,AddressParameters):
		raise TypeError('Bad type for parameters!')

	s1 = random_scalar()
	s2 = random_scalar()
	r = random_scalar()

	spend = SpendKey(s1,s2,r)
	full = FullViewKey(params,spend)
	incoming = IncomingViewKey(full)
	public = PublicAddress(params,spend)

	return spend,full,incoming,public
