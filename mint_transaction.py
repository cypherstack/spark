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

class MintTransaction:
	def __init__(self,params,public,value,memo):
		if not isinstance(params,ProtocolParameters):
			raise TypeError('Bad type for parameters!')
		if not isinstance(public,address.PublicAddress):
			raise TypeError('Bad type for delegation key!')
		if not isinstance(value,int) or value < 0 or value >= 2**params.N:
			raise ValueError('Bad type or value for coin value!')

		self.output = coin.Coin(
			coin.CoinParameters(params.G,params.F,params.H,params.N),
			public,
			value,
			memo,
			True,
			True
		)
		self.value = value

		self.balance = schnorr.prove(
			schnorr.SchnorrStatement(
				schnorr.SchnorrParameters(params.F),
				self.output.C - Scalar(self.value)*params.G
			),
			schnorr.SchnorrWitness(hash_to_scalar('val',self.output.k*self.output.Q1))
		)

	def verify(self,params):
		if not isinstance(params,ProtocolParameters):
			raise TypeError('Bad type for parameters!')

		# Check value
		if self.value < 0 or self.value >= 2**params.N:
			raise ValueError('Bad value for coin value!')
		
		# Check balance
		schnorr.verify(
			schnorr.SchnorrStatement(
				schnorr.SchnorrParameters(params.F),
				self.output.C - Scalar(self.value)*params.G
			),
			self.balance
		)