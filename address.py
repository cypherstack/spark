# Address generation

from dumb25519 import Point, Scalar, random_scalar, hash_to_scalar

class AddressParameters:
	def __init__(self,F,G,lookahead=0):
		if not isinstance(F,Point):
			raise TypeError('Bad type for parameter F!')
		if not isinstance(G,Point):
			raise TypeError('Bad type for parameter G!')
		if not isinstance(lookahead,int) or not lookahead >= 0:
			raise ValueError('Bad type or value for diversifier lookahead!')
		
		self.F = F
		self.G = G
		self.lookahead = lookahead

class SpendKey:
	def __init__(self,params):
		if not isinstance(params,AddressParameters):
			raise TypeError('Bad type for parameters!')

		self.params = params
		self.s1 = random_scalar()
		self.s2 = random_scalar()
		self.r = random_scalar()
	
	def full_view_key(self):
		s1 = self.s1
		s2 = self.s2
		D = self.r*self.params.G

		return FullViewKey(self.params,self.base_address(),s1,s2,D)
	
	def incoming_view_key(self):
		s1 = self.s1

		return IncomingViewKey(self.params,self.base_address(),s1)
	
	def base_address(self):
		Q1 = self.s1*self.params.F
		Q2 = self.s2*self.params.F + self.r*self.params.G

		return BaseAddress(Q1,Q2)
	
	def public_address(self,i=0):
		if not isinstance(i,int) or not i >= 0 or not i <= self.params.lookahead:
			raise TypeError('Bad type or value for diversifier!')
		
		Q0 = hash_to_scalar('Q0',self.s1,i)*self.params.F
		Q1 = self.s1*Q0
		Q2 = (hash_to_scalar('Q2',self.s1,i) + self.s2)*self.params.F + self.r*self.params.G

		return PublicAddress(Q0,Q1,Q2)

class FullViewKey:
	def __init__(self,params,base,s1,s2,D):
		if not isinstance(params,AddressParameters):
			raise TypeError('Bad type for parameters!')
		if not isinstance(base,BaseAddress):
			raise TypeError('Bad type for base address!')
		if not isinstance(s1,Scalar):
			raise TypeError('Bad type for full view key!')
		if not isinstance(s2,Scalar):
			raise TypeError('Bad type for full view key!')
		if not isinstance(D,Point):
			raise TypeError('Bad type for full view key!')
		
		self.params = params
		self.base = base
		self.s1 = s1
		self.s2 = s2
		self.D = D
	
class IncomingViewKey:
	def __init__(self,params,base,s1):
		if not isinstance(params,AddressParameters):
			raise TypeError('Bad type for parameters!')
		if not isinstance(base,BaseAddress):
			raise TypeError('Bad type for base address!')
		if not isinstance(s1,Scalar):
			raise TypeError('Bad type for incoming view key!')
		if not isinstance(base,BaseAddress):
			raise TypeError('Bad type for base address!')
		
		self.params = params
		self.base = base
		self.s1 = s1
		self.table = {}
	
		for i in range(self.params.lookahead+1):
			entry = hash_to_scalar('Q2',self.s1,i)*self.params.F + base.Q2
			self.table[repr(entry)] = i

	def get_diversifier(self,Q2):
		if not isinstance(Q2,Point):
			raise TypeError('Bad type for diversifier lookup!')
		
		if repr(Q2) in self.table:
			return self.table[repr(Q2)]
		raise IndexError('Diversifier not found!')

class BaseAddress:
	def __init__(self,Q1,Q2):
		if not isinstance(Q1,Point):
			raise TypeError('Bad type for base address!')
		if not isinstance(Q2,Point):
			raise TypeError('Bad type for base address!')

		self.Q1 = Q1
		self.Q2 = Q2

class PublicAddress:
	def __init__(self,Q0,Q1,Q2):
		if not isinstance(Q0,Point):
			raise TypeError('Bad type for public address!')
		if not isinstance(Q1,Point):
			raise TypeError('Bad type for public address!')
		if not isinstance(Q2,Point):
			raise TypeError('Bad type for public address!')

		self.Q0 = Q0
		self.Q1 = Q1
		self.Q2 = Q2
