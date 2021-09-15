# Coin structure

from dumb25519 import Point, Scalar, PointVector, ScalarVector, random_scalar, hash_to_scalar
import address
import bpplus
import util

class CoinParameters:
	def __init__(self,G,F,H,N):
		if not isinstance(G,Point):
			raise TypeError('Bad type for parameter G!')
		if not isinstance(F,Point):
			raise TypeError('Bad type for parameter F!')
		if not isinstance(H,Point):
			raise TypeError('Bad type for parameter H!')
		if not isinstance(N,int) or N < 1:
			raise ValueError('Bad type or value for parameter N!')
		
		self.G = G
		self.F = F
		self.H = H
		self.N = N

class CoinDelegation:
	def __init__(self,id,s1,S1,c1,C1):
		if not isinstance(s1,Scalar):
			raise TypeError('Bad type for parameter s1!')
		if not isinstance(S1,Point):
			raise TypeError('Bad type for parameter S1!')
		if not isinstance(c1,Scalar):
			raise TypeError('Bad type for parameter c1!')
		if not isinstance(C1,Point):
			raise TypeError('Bad type for parameter C1!')
		
		self.id = id
		self.s1 = s1
		self.S1 = S1
		self.c1 = c1
		self.C1 = C1

class Coin:
	def __repr__(self):
		if self.is_mint:
			return repr(hash_to_scalar(
				self.K,
				self.S,
				self.C,
				self.value,
				self.memo_enc
			))
		else:
			return repr(hash_to_scalar(
				self.K,
				self.S,
				self.C,
				self.range,
				self.value_enc,
				self.memo_enc
			))

	def __init__(self,params,public,value,memo,is_mint,is_output):
		if not isinstance(params,CoinParameters):
			raise TypeError('Bad type for parameters!')
		if not isinstance(public,address.PublicAddress):
			raise TypeError('Bad type for coin address!')
		if not isinstance(value,int) or value < 0 or value >= 2**params.N:
			raise ValueError('Bad type or value for coin value!')
		if not isinstance(memo,str):
			raise TypeError('Bad type for coin memo!')
		if not isinstance(is_mint,bool):
			raise TypeError('Bad type for coin mint flag!')
		if not isinstance(is_output,bool):
			raise TypeError('Bad type for coin output flag!')

		# Recovery key
		k = random_scalar()
		self.K = k*params.G
		K_der = k*public.Q1

		# Serial number commitment
		self.S = hash_to_scalar('ser',K_der,public.Q1,public.Q2)*params.G + public.Q2

		# Value commitment
		self.C = Scalar(value)*params.G + hash_to_scalar('val',K_der)*params.F
		if not is_mint:
			self.range = bpplus.prove(
				bpplus.RangeStatement(bpplus.RangeParameters(params.F,params.G,params.N),PointVector([self.C])),
				bpplus.RangeWitness(ScalarVector([Scalar(value)]),ScalarVector([hash_to_scalar('val',K_der)]))
			)

		# Encrypt value and memo
		if is_mint:
			self.value = Scalar(value)
		else:
			self.value_enc = util.aead_encrypt_utf8(K_der,'Spark coin value',repr(Scalar(value)))
		self.memo_enc = util.aead_encrypt_utf8(K_der,'Spark coin memo',memo)

		# Data used for output only
		self.is_output = False
		if is_output:
			self.is_output = True
			self.k = k
			self.Q1 = public.Q1
			self.value = Scalar(value)

		self.recovered = False
		self.is_mint = is_mint
	
	def identify(self,params,public,incoming):
		if not isinstance(params,CoinParameters):
			raise TypeError('Bad type for parameters!')
		if not isinstance(public,address.PublicAddress):
			raise TypeError('Bad type for public address!')
		if not isinstance(incoming,address.IncomingViewKey):
			raise TypeError('Bad type for incoming view key!')
	
		K_der = incoming.s1*self.K
		
		# Test for ownership
		if not self.S == hash_to_scalar('ser',K_der,public.Q1,public.Q2)*params.G + public.Q2:
			raise ArithmeticError('Coin does not belong to this public address!')
		
		# Decrypt value and memo
		if not self.is_mint:
			self.value = Scalar(util.aead_decrypt_utf8(K_der,'Spark coin value',self.value_enc))
		self.memo = util.aead_decrypt_utf8(K_der,'Spark coin memo',self.memo_enc)
		
		# Test for value commitment
		if not self.C == self.value*params.G + hash_to_scalar('val',K_der)*params.F:
			raise ArithmeticError('Bad coin value commitment!')
		
		# Test range proof
		if not self.is_mint:
			bpplus.verify(
				[bpplus.RangeStatement(bpplus.RangeParameters(params.F,params.G,params.N),PointVector([self.C]))],
				[self.range]
			)
		
	def recover(self,params,public,full):
		if not isinstance(params,CoinParameters):
			raise TypeError('Bad type for coin parameters!')
		if not isinstance(public,address.PublicAddress):
			raise TypeError('Bad type for public address!')
		if not isinstance(full,address.FullViewKey):
			raise TypeError('Bad type for full view key!')
		
		K_der = full.s1*self.K
		
		# Test for ownership
		if not self.S == hash_to_scalar('ser',K_der,public.Q1,public.Q2)*params.G + public.Q2:
			raise ArithmeticError('Coin does not belong to this public address!')
		
		# Decrypt value and memo
		if not self.is_mint:
			self.value = Scalar(util.aead_decrypt_utf8(K_der,'Spark coin value',self.value_enc))
		self.memo = util.aead_decrypt_utf8(K_der,'Spark coin memo',self.memo_enc)
		
		# Test for value commitment
		if not self.C == self.value*params.G + hash_to_scalar('val',K_der)*params.F:
			raise ArithmeticError('Bad coin value commitment!')
		
		# Test range proof
		if not self.is_mint:
			bpplus.verify(
				[bpplus.RangeStatement(bpplus.RangeParameters(params.F,params.G,params.N),PointVector([self.C]))],
				[self.range]
			)
		
		# Recover serial number and generate tag
		self.s = hash_to_scalar('ser',K_der,public.Q1,public.Q2) + full.s2
		self.T = self.s.invert()*params.H

		self.recovered = True
	
	def delegate(self,params,full,id):
		if not isinstance(params,CoinParameters):
			raise TypeError('Bad type for coin parameters!')
		if not isinstance(full,address.FullViewKey):
			raise TypeError('Bad type for full view key!')
		if not self.recovered:
			raise ValueError('Delegation requires coin recovery!')
		
		s1 = hash_to_scalar('ser1',id,self.s,full.s1,full.s2)
		S1 = self.s*params.G - hash_to_scalar('ser1',id,self.s,full.s1,full.s2)*params.F + full.D
		c1 = hash_to_scalar('val',full.s1*self.K) - hash_to_scalar('val1',id,self.s,full.s1,full.s2)
		C1 = self.value*params.G + hash_to_scalar('val1',id,self.s,full.s1,full.s2)*params.F

		self.delegation = CoinDelegation(id,s1,S1,c1,C1)
