# Spend transaction

import address
import bpplus
import chaum
import coin
import dumb25519
from dumb25519 import Point, Scalar, PointVector, hash_to_scalar
import parallel
import schnorr

class ProtocolParameters:
	def __init__(self,G,F,H,N,n,m):
		if not isinstance(G,Point):
			raise TypeError('Bad type for parameter G!')
		if not isinstance(F,Point):
			raise TypeError('Bad type for parameter F!')
		if not isinstance(H,Point):
			raise TypeError('Bad type for parameter H!')
		if not isinstance(N,int) or N < 1:
			raise ValueError('Bad type or value for parameter N!')
		if not isinstance(n,int) or n < 1:
			raise ValueError('Bad type or value for parameter n!')
		if not isinstance(m,int) or m < 1:
			raise ValueError('Bad type or value for parameter m!')
		
		self.G = G
		self.F = F
		self.H = H
		self.N = N
		self.n = n
		self.m = m

class SpendTransaction:
	def __init__(self,params,full,spend,inputs,indexes,fee,outputs):
		if not isinstance(params,ProtocolParameters):
			raise TypeError('Bad type for parameters!')
		if not isinstance(full,address.FullViewKey):
			raise TypeError('Bad type for full view key!')
		if not isinstance(spend,address.SpendKey):
			raise TypeError('Bad type for spend key!')
		for input in inputs:
			if not isinstance(input,coin.Coin):
				raise TypeError('Bad type for input coin!')
		for l in indexes:
			if not isinstance(l,int) or l < 0 or l >= params.n**params.m:
				raise ValueError('Bad type or value for spend index!')
			if not inputs[l].recovered:
				raise ValueError('Input coin is not recovered!')
		if not isinstance(fee,int) or fee < 0 or fee >= 2**params.N:
			raise ValueError('Bad type or value for fee!')
		for output in outputs:
			if not isinstance(output,coin.Coin):
				raise TypeError('Bad type for output coin!')
			if not output.is_output:
				raise ValueError('Output coin is not flagged as output!')

		w = len(indexes)
		t = len(outputs)

		self.inputs = inputs # input cover set
		self.outputs = outputs # output coins
		self.fee = fee # transaction fee
		self.S1 = PointVector() # serial number commitment offsets
		self.C1 = PointVector() # value commitment offsets
		self.T = PointVector() # tags
		self.parallel = [] # parallel one-of-many proofs
		self.chaum = [] # modified Chaum-Pedersen proofs

		# Spends
		for u in range(w):
			input = inputs[indexes[u]]

			# Serial number commitment offset
			self.S1.append(input.delegation.S1)
			self.C1.append(input.delegation.C1)

			# Tag
			self.T.append(input.T)

			# Parallel one-of-many proof
			self.parallel.append(parallel.prove(
				parallel.ParallelStatement(
					parallel.ParallelParameters(params.F,params.n,params.m),
					PointVector([input.S - self.S1[u] for input in inputs]),
					PointVector([input.C - self.C1[u] for input in inputs])
				),
				parallel.ParallelWitness(
					indexes[u],
					input.delegation.s1,
					input.delegation.c1,
				)
			))

		# Balance statement input value
		b_st = dumb25519.Z
		for u in range(w):
			b_st += self.C1[u]
		for j in range(t):
			b_st -= outputs[j].C
		b_st -= Scalar(fee)*params.G

		# Balance witness
		b_w = Scalar(0)
		for u in range(w):
			input = inputs[indexes[u]]
			b_w += hash_to_scalar('val1',input.delegation.id,input.s,full.s1,full.s2)
		for j in range(t):
			b_w -= hash_to_scalar('val',outputs[j].k*outputs[j].Q1)

		# Balance proof
		self.balance = schnorr.prove(
			schnorr.SchnorrStatement(schnorr.SchnorrParameters(params.F),b_st),
			schnorr.SchnorrWitness(b_w)
		)

		# Modified Chaum-Pedersen proofs
		mu = hash_to_scalar(
			self.inputs,
			self.outputs,
			self.fee,
			self.S1,
			self.C1,
			self.T,
			self.parallel,
			self.balance
		)

		for u in range(w):
			input = inputs[indexes[u]]
			self.chaum.append(chaum.prove(
				chaum.ChaumStatement(chaum.ChaumParameters(params.G,params.F,params.H),mu,self.S1[u],input.T),
				chaum.ChaumWitness(input.s,spend.r - hash_to_scalar('ser1',input.delegation.id,input.s,full.s1,full.s2))
			))
		

	def verify(self,params,tags=None):
		if not isinstance(params,ProtocolParameters):
			raise TypeError('Bad type for parameters!')

		# Check tag uniqueness
		for tag in self.T:
			if tags is not None and tag in tags:
				raise ValueError('Tag has been seen before!')

		# Check fee
		if self.fee < 0 or self.fee >= 2**params.N:
			raise ValueError('Bad value for transaction fee!')
		
		w = len(self.T)
		t = len(self.outputs)

		mu = hash_to_scalar(
			self.inputs,
			self.outputs,
			self.fee,
			self.S1,
			self.C1,
			self.T,
			self.parallel,
			self.balance
		)

		# Check input proofs
		for u in range(w):
			parallel.verify(
				parallel.ParallelStatement(
					parallel.ParallelParameters(params.F,params.n,params.m),
					PointVector([input.S - self.S1[u] for input in self.inputs]),
					PointVector([input.C - self.C1[u] for input in self.inputs])
				),
				self.parallel[u]
			)

			chaum.verify(
				chaum.ChaumStatement(chaum.ChaumParameters(params.G,params.F,params.H),mu,self.S1[u],self.T[u]),
				self.chaum[u]
			)
		
		# Check output proofs
		for j in range(t):
			bpplus.verify(
				[bpplus.RangeStatement(bpplus.RangeParameters(params.F,params.G,params.N),PointVector([self.outputs[j].C]))],
				[self.outputs[j].range]
			)

		# Check balance
		b_st = dumb25519.Z
		for u in range(w):
			b_st += self.C1[u]
		for j in range(t):
			b_st -= self.outputs[j].C
		b_st -= Scalar(self.fee)*params.G

		schnorr.verify(
			schnorr.SchnorrStatement(schnorr.SchnorrParameters(params.F),b_st),
			self.balance
		)