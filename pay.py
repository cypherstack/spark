# Payment proving system
#
# {(F,G,H),S,C,K,K_der,K_div,Q_0,Q_1,Q_2,v' ; k | 
#		K = k*Q_0,
#		K_der = k*Q_1,
#		K_div = k*F,
#		S = H_ser(K_der)F + Q_2,
#		C = SymDec(H_aead_val(K_der,K_div),v')G + H_val(K_der)H
# }
# Also require that memo decryption succeeds under the key H_aead_memo(K_der,K_div)

import address
import coin
from dumb25519 import Point, Scalar, hash_to_scalar, random_scalar
import transcript
import util

class PayParameters:
	def __init__(self,F,G,H,value_bytes):
		if not isinstance(F,Point):
			raise TypeError('Bad type for parameter F!')
		if not isinstance(G,Point):
			raise TypeError('Bad type for parameter G!')
		if not isinstance(H,Point):
			raise TypeError('Bad type for parameter H!')
		if not isinstance(value_bytes,int) or value_bytes < 1:
			raise ValueError('Bad type or value for parameter value_bytes!')
		
		self.F = F
		self.G = G
		self.H = H
		self.value_bytes = value_bytes

class PayStatement:
	def __init__(self,params,context,coin_,K_der,K_div,public):
		if not isinstance(params,PayParameters):
			raise TypeError('Bad type for parameters!')
		if not isinstance(coin_,coin.Coin):
			raise TypeError('Bad type for pay statement coin!')
		if not isinstance(K_der,Point):
			raise TypeError('Bad type for pay statement input K_der!')
		if not isinstance(K_div,Point):
			raise TypeError('Bad type for pay statement input K_div!')
		if not isinstance(public,address.PublicAddress):
			raise TypeError('Bad type for pay statement public address!')
		
		self.F = params.F
		self.G = params.G
		self.H = params.H
		self.value_bytes = params.value_bytes
		self.context = context
		self.coin = coin_
		self.K_der = K_der
		self.K_div = K_div
		self.public = public

class PayWitness:
	def __init__(self,k):
		if not isinstance(k,Scalar):
			raise TypeError('Bad type for pay witness k!')
		
		self.k = k

class PayProof:
	def __init__(self,A1,A2,A3,t):
		if not isinstance(A1,Point):
			raise TypeError('Bad type for pay proof element A1!')
		if not isinstance(A2,Point):
			raise TypeError('Bad type for pay proof element A2!')
		if not isinstance(A3,Point):
			raise TypeError('Bad type for pay proof element A2!')
		if not isinstance(t,Scalar):
			raise TypeError('Bad type for pay proof element t!')

		self.A1 = A1
		self.A2 = A2
		self.A3 = A3
		self.t = t

def challenge(statement,A1,A2,A3):
	if not isinstance(statement,PayStatement):
		raise TypeError('Bad type for pay statement!')
	if not isinstance(A1,Point):
		raise TypeError('Bad type for challenge input A1!')
	if not isinstance(A2,Point):
		raise TypeError('Bad type for challenge input A2!')
	if not isinstance(A3,Point):
		raise TypeError('Bad type for challenge input A3!')

	tr = transcript.Transcript('Pay proof')
	tr.update(statement.F)
	tr.update(statement.G)
	tr.update(statement.H)
	tr.update(statement.value_bytes)
	tr.update(statement.context)
	tr.update(statement.coin.S)
	tr.update(statement.coin.C)
	tr.update(statement.coin.K)
	tr.update(statement.coin.enc)
	tr.update(statement.K_der)
	tr.update(statement.K_div)
	tr.update(statement.public.Q0)
	tr.update(statement.public.Q1)
	tr.update(statement.public.Q2)
	tr.update(A1)
	tr.update(A2)
	tr.update(A3)
	return tr.challenge()

def prove(statement,witness):
	if not isinstance(statement,PayStatement):
		raise TypeError('Bad type for pay statement!')
	if not isinstance(witness,PayWitness):
		raise TypeError('Bad type for pay witness!')
	
	# Check the statement validity
	if not statement.coin.K == witness.k*statement.public.Q0:
		raise ArithmeticError('Invalid pay statement!')
	if not statement.K_der == witness.k*statement.public.Q1:
		raise ArithmeticError('Invalid pay statement!')
	if not statement.K_div == witness.k*statement.F:
		raise ArithmeticError('Invalid pay statement!')
	if not statement.coin.S == hash_to_scalar('ser',statement.K_der)*statement.F + statement.public.Q2:
		raise ArithmeticError('Invalid pay statement!')

	# Decrypt recipient data
	aead_key = hash_to_scalar('aead',statement.K_der,statement.K_div)
	data_bytes = util.aead_decrypt(aead_key,'Spend recipient data',statement.coin.enc)
	if data_bytes is not None:
		value = int.from_bytes(data_bytes[:statement.value_bytes],'little')
	else:
		raise ArithmeticError('Bad recipient data!')
	
	if not statement.coin.C == Scalar(value)*statement.G + hash_to_scalar('val',statement.K_der)*statement.H:
		raise ArithmeticError('Invalid pay statement!')
	
	r = random_scalar()

	A1 = r*statement.public.Q0
	A2 = r*statement.public.Q1
	A3 = r*statement.F

	c = challenge(statement,A1,A2,A3)

	t = r + c*witness.k

	return PayProof(A1,A2,A3,t)

def verify(statement,proof):
	if not isinstance(statement,PayStatement):
		raise TypeError('Bad type for pay statement!')
	if not isinstance(proof,PayProof):
		raise TypeError('Bad type for pay proof!')
	
	c = challenge(statement,proof.A1,proof.A2,proof.A3)

	if not proof.A1 + c*statement.coin.K == proof.t*statement.public.Q0:
		raise ArithmeticError('Failed pay verification!')
	if not proof.A2 + c*statement.K_der == proof.t*statement.public.Q1:
		raise ArithmeticError('Failed pay verification!')
	if not proof.A3 + c*statement.K_div == proof.t*statement.F:
		raise ArithmeticError('Failed pay verification!')
	if not statement.coin.S == hash_to_scalar('ser',statement.K_der)*statement.F + statement.public.Q2:
		raise ArithmeticError('Failed pay verification!')

	# Decrypt recipient data
	aead_key = hash_to_scalar('aead',statement.K_der,statement.K_div)
	data_bytes = util.aead_decrypt(aead_key,'Spend recipient data',statement.coin.enc)
	if data_bytes is not None:
		value = int.from_bytes(data_bytes[:statement.value_bytes],'little')
	else:
		raise ArithmeticError('Bad recipient data!')

	if not statement.coin.C == Scalar(value)*statement.G + hash_to_scalar('val',statement.K_der)*statement.H:
		raise ArithmeticError('Failed pay verification!')

	# Test serial number and value commitments
	if not statement.coin.S == hash_to_scalar('ser',statement.K_der)*statement.F + statement.public.Q2:
		raise ArithmeticError('Failed pay verification!')
	if not statement.coin.C == Scalar(value)*statement.G + hash_to_scalar('val',statement.K_der)*statement.H:
		raise ArithmeticError('Failed pay verification!')
