# Coin structure

from dumb25519 import Point, Scalar, PointVector, ScalarVector, random_scalar, hash_to_scalar
import address
import bpplus
import schnorr
import util

class CoinParameters:
	def __init__(self,F,G,H,U,value_bytes,memo_bytes):
		if not isinstance(F,Point):
			raise TypeError('Bad type for parameter F!')
		if not isinstance(G,Point):
			raise TypeError('Bad type for parameter G!')
		if not isinstance(H,Point):
			raise TypeError('Bad type for parameter H!')
		if not isinstance(U,Point):
			raise TypeError('Bad type for parameter U!')
		if not isinstance(value_bytes,int) or value_bytes < 1:
			raise ValueError('Bad type or value for parameter value_bytes!')
		if not isinstance(memo_bytes,int) or memo_bytes < 1:
			raise ValueError('Bad type or value for parameter memo_bytes!')
		
		self.F = F
		self.G = G
		self.H = H
		self.U = U
		self.value_bytes = value_bytes
		self.memo_bytes = memo_bytes

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
				self.enc,
				self.janus
			))
		else:
			return repr(hash_to_scalar(
				self.K,
				self.S,
				self.C,
				self.range,
				self.enc,
				self.janus
			))

	def __init__(self,params,public,value,memo,is_mint,is_output):
		if not isinstance(params,CoinParameters):
			raise TypeError('Bad type for parameters!')
		if not isinstance(public,address.PublicAddress):
			raise TypeError('Bad type for coin address!')
		if not isinstance(value,int) or value < 0 or value.bit_length() > 8*params.value_bytes:
			raise ValueError('Bad type or value for coin value!')
		if not isinstance(memo,str) or len(memo.encode('utf-8')) > params.memo_bytes:
			raise ValueError('Bad type or size for coin memo!')
		if not isinstance(is_mint,bool):
			raise TypeError('Bad type for coin mint flag!')
		if not isinstance(is_output,bool):
			raise TypeError('Bad type for coin output flag!')

		# Recovery key
		k = random_scalar()
		self.K = k*public.Q0
		K_der = k*public.Q1

		# Serial number commitment
		self.S = hash_to_scalar('ser',K_der)*params.F + public.Q2

		# Value commitment
		self.C = Scalar(value)*params.G + hash_to_scalar('val',K_der)*params.H
		if not is_mint:
			self.range = bpplus.prove(
				bpplus.RangeStatement(bpplus.RangeParameters(params.G,params.H,8*params.value_bytes),PointVector([self.C])),
				bpplus.RangeWitness(ScalarVector([Scalar(value)]),ScalarVector([hash_to_scalar('val',K_der)]))
			)
		
		# Diversifier assertion
		self.janus = schnorr.prove(
			schnorr.SchnorrStatement(schnorr.SchnorrParameters(params.F),k*params.F),
			schnorr.SchnorrWitness(k)
		)

		# Encrypt recipient data
		padded_memo = memo.encode('utf-8')
		padded_memo += bytearray(params.memo_bytes - len(padded_memo))
		aead_key = hash_to_scalar('aead',K_der)
		if is_mint:
			self.value = value
			self.enc = util.aead_encrypt(aead_key,'Mint recipient data',padded_memo)
		else:
			padded_value = value.to_bytes(params.value_bytes,'little')
			self.enc = util.aead_encrypt(aead_key,'Spend recipient data',padded_value + padded_memo)

		# Data used for output only
		self.is_output = False
		if is_output:
			self.is_output = True
			self.k = k
			self.Q1 = public.Q1
			self.value = value

		self.diversifier = None
		self.identified = False
		self.recovered = False
		self.is_mint = is_mint
	
	def identify(self,params,incoming):
		if not isinstance(params,CoinParameters):
			raise TypeError('Bad type for parameters!')
		if not isinstance(incoming,address.IncomingViewKey):
			raise TypeError('Bad type for incoming view key!')
	
		K_der = incoming.s1*self.K
		
		# Test for diversifier
		Q2 = self.S - hash_to_scalar('ser',K_der)*params.F
		try:
			self.diversifier = incoming.get_diversifier(Q2)
			schnorr.verify(
				schnorr.SchnorrStatement(schnorr.SchnorrParameters(params.F),hash_to_scalar('Q0',incoming.s1,self.diversifier).invert()*self.K),
				self.janus
			)
		except:
			raise ArithmeticError('Coin does not belong to this public address!')
		
		# Decrypt recipient data; check for diversified address consistency
		aead_key = hash_to_scalar('aead',K_der)
		if self.is_mint:
			memo_bytes = util.aead_decrypt(aead_key,'Mint recipient data',self.enc)
			if memo_bytes is not None:
				self.memo = memo_bytes.decode('utf-8').rstrip('\x00')
			else:
				raise ArithmeticError('Bad recipient data!')
		else:
			data_bytes = util.aead_decrypt(aead_key,'Spend recipient data',self.enc)
			if data_bytes is not None:
				self.value = int.from_bytes(data_bytes[:params.value_bytes],'little')
				self.memo = data_bytes[params.value_bytes:].decode('utf-8').rstrip('\x00')
			else:
				raise ArithmeticError('Bad recipient data!')

		# Test for value commitment
		if not self.C == Scalar(self.value)*params.G + hash_to_scalar('val',K_der)*params.H:
			raise ArithmeticError('Bad coin value commitment!')
		
		# Test range proof
		if not self.is_mint:
			bpplus.verify(
				[bpplus.RangeStatement(bpplus.RangeParameters(params.G,params.H,8*params.value_bytes),PointVector([self.C]))],
				[self.range]
			)
		
		self.identified = True
		
	def recover(self,params,full):
		if not isinstance(params,CoinParameters):
			raise TypeError('Bad type for coin parameters!')
		if not isinstance(full,address.FullViewKey):
			raise TypeError('Bad type for full view key!')
		
		# The coin must be identified
		if not self.identified:
			raise ArithmeticError('Coin has not been identified!')
		
		# Recover serial number and generate tag
		K_der = full.s1*self.K
		self.s = hash_to_scalar('ser',K_der) + hash_to_scalar('Q2',full.s1,self.diversifier) + full.s2
		self.T = self.s.invert()*(params.U - full.D)

		self.recovered = True
	
	def delegate(self,params,full,id):
		if not isinstance(params,CoinParameters):
			raise TypeError('Bad type for coin parameters!')
		if not isinstance(full,address.FullViewKey):
			raise TypeError('Bad type for full view key!')
		if not self.recovered:
			raise ValueError('Delegation requires coin recovery!')
		
		s1 = hash_to_scalar('ser1',id,self.s,full.s1,full.s2)
		S1 = self.s*params.F - hash_to_scalar('ser1',id,self.s,full.s1,full.s2)*params.H + full.D
		c1 = hash_to_scalar('val',full.s1*self.K) - hash_to_scalar('val1',id,self.s,full.s1,full.s2)
		C1 = Scalar(self.value)*params.G + hash_to_scalar('val1',id,self.s,full.s1,full.s2)*params.H

		self.delegation = CoinDelegation(id,s1,S1,c1,C1)
