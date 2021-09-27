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
	def __init__(self,F,G,H,U,value_bytes,memo_bytes):
		if not isinstance(F,Point):
			raise TypeError('Bad type for parameter F!')
		if not isinstance(G,Point):
			raise TypeError('Bad type for parameter G!')
		if not isinstance(H,Point):
			raise TypeError('Bad type for parameter H!')
		if not isinstance(U,Point):
			raise TypeError('Bad type for parameter H!')
		if not isinstance(value_bytes,int) or value_bytes < 1:
			raise ValueError('Bad type or value for parameter value_bytes!')
		if not isinstance(memo_bytes,int) or memo_bytes < 1:
			raise ValueError('Bad type or value for parameter value_bytes!')
		
		self.F = F
		self.G = G
		self.H = H
		self.U = U
		self.value_bytes = value_bytes
		self.memo_bytes = memo_bytes

class MintTransaction:
	def __init__(self,params,public,value,memo):
		if not isinstance(params,ProtocolParameters):
			raise TypeError('Bad type for parameters!')
		if not isinstance(public,address.PublicAddress):
			raise TypeError('Bad type for delegation key!')
		if not isinstance(value,int) or value < 0 or value.bit_length() > 8*params.value_bytes:
			raise ValueError('Bad type or value for coin value!')
		if not isinstance(memo,str) or len(memo.encode('utf-8')) > params.memo_bytes:
			raise ValueError('Bad type or size for coin memo!')

		self.output = coin.Coin(
			coin.CoinParameters(params.F,params.G,params.H,params.U,params.value_bytes,params.memo_bytes),
			public,
			value,
			memo,
			True,
			True
		)
		self.value = value

		self.balance = schnorr.prove(
			schnorr.SchnorrStatement(
				schnorr.SchnorrParameters(params.H),
				self.output.C - Scalar(self.value)*params.G
			),
			schnorr.SchnorrWitness(hash_to_scalar('val',self.output.k*self.output.Q1))
		)

	def verify(self,params):
		if not isinstance(params,ProtocolParameters):
			raise TypeError('Bad type for parameters!')

		# Check value
		if self.value < 0 or self.value.bit_length() > 8*params.value_bytes:
			raise ValueError('Bad value for coin value!')
		
		# Check balance
		schnorr.verify(
			schnorr.SchnorrStatement(
				schnorr.SchnorrParameters(params.H),
				self.output.C - Scalar(self.value)*params.G
			),
			self.balance
		)