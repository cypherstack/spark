# Payment proving system
#
# {(G,F),S,C,K_rec,K_der,Q_1,Q_2,v' ; k | 
#		K_rec = kG,
#		k_der = kQ_1,
#		S = H_ser(K_der,Q_1,Q_2)G + Q_2,
#		C = SymDec(K_der,v')G + H_val(K_der)
# }

import address
import coin
from dumb25519 import Point, Scalar, hash_to_scalar, random_scalar
import transcript
import util

class PayParameters:
	def __init__(self,G,F):
		if not isinstance(G,Point):
			raise TypeError('Bad type for parameter G!')
		if not isinstance(F,Point):
			raise TypeError('Bad type for parameter F!')
		
		self.G = G
		self.F = F

class PayStatement:
	def __init__(self,params,context,coin_,K_der,public):
		if not isinstance(params,PayParameters):
			raise TypeError('Bad type for parameters!')
		if not isinstance(coin_,coin.Coin):
			raise TypeError('Bad type for pay statement coin!')
		if not isinstance(K_der,Point):
			raise TypeError('Bad type for pay statement input K_der!')
		if not isinstance(public,address.PublicAddress):
			raise TypeError('Bad type for pay statement public address!')
		
		self.G = params.G
		self.F = params.F
		self.context = context
		self.coin = coin_
		self.K_der = K_der
		self.public = public

class PayWitness:
	def __init__(self,k):
		if not isinstance(k,Scalar):
			raise TypeError('Bad type for pay witness k!')
		
		self.k = k

class PayProof:
	def __init__(self,A1,A2,t):
		if not isinstance(A1,Point):
			raise TypeError('Bad type for pay proof element A1!')
		if not isinstance(A2,Point):
			raise TypeError('Bad type for pay proof element A2!')
		if not isinstance(t,Scalar):
			raise TypeError('Bad type for pay proof element t!')

		self.A1 = A1
		self.A2 = A2
		self.t = t

def challenge(statement,A1,A2):
	if not isinstance(statement,PayStatement):
		raise TypeError('Bad type for pay statement!')
	if not isinstance(A1,Point):
		raise TypeError('Bad type for challenge input A1!')
	if not isinstance(A2,Point):
		raise TypeError('Bad type for challenge input A2!')

	tr = transcript.Transcript('Pay proof')
	tr.update(statement.G)
	tr.update(statement.F)
	tr.update(statement.context)
	tr.update(statement.coin.S)
	tr.update(statement.coin.C)
	tr.update(statement.coin.K)
	tr.update(statement.coin.value_enc)
	tr.update(statement.coin.memo_enc)
	tr.update(statement.K_der)
	tr.update(statement.public.Q1)
	tr.update(statement.public.Q2)
	tr.update(A1)
	tr.update(A2)
	return tr.challenge()

def prove(statement,witness):
	if not isinstance(statement,PayStatement):
		raise TypeError('Bad type for pay statement!')
	if not isinstance(witness,PayWitness):
		raise TypeError('Bad type for pay witness!')
	
	# Check the statement validity
	if not statement.coin.K == witness.k*statement.G:
		raise ArithmeticError('Invalid pay statement!')
	if not statement.K_der == witness.k*statement.public.Q1:
		raise ArithmeticError('Invalid pay statement!')
	if not statement.coin.S == hash_to_scalar('ser',statement.K_der,statement.public.Q1,statement.public.Q2)*statement.G + statement.public.Q2:
		raise ArithmeticError('Invalid pay statement!')

	# Decrypt value and memo
	value = Scalar(util.aead_decrypt_utf8(statement.K_der,'Spark coin value',statement.coin.value_enc))
	util.aead_decrypt_utf8(statement.K_der,'Spark coin memo',statement.coin.memo_enc)

	if not statement.coin.C == value*statement.G + hash_to_scalar('val',statement.K_der)*statement.F:
		raise ArithmeticError('Invalid pay statement!')
	
	r = random_scalar()

	A1 = r*statement.G
	A2 = r*statement.public.Q1

	c = challenge(statement,A1,A2)

	t = r + c*witness.k

	return PayProof(A1,A2,t)

def verify(statement,proof):
	if not isinstance(statement,PayStatement):
		raise TypeError('Bad type for pay statement!')
	if not isinstance(proof,PayProof):
		raise TypeError('Bad type for pay proof!')
	
	c = challenge(statement,proof.A1,proof.A2)

	if not proof.A1 + c*statement.coin.K == proof.t*statement.G:
		raise ArithmeticError('Failed pay verification!')
	if not proof.A2 + c*statement.K_der == proof.t*statement.public.Q1:
		raise ArithmeticError('Failed pay verification!')
	if not statement.coin.S == hash_to_scalar('ser',statement.K_der,statement.public.Q1,statement.public.Q2)*statement.G + statement.public.Q2:
		raise ArithmeticError('Failed pay verification!')

	# Decrypt value and memo
	value = Scalar(util.aead_decrypt_utf8(statement.K_der,'Spark coin value',statement.coin.value_enc))
	util.aead_decrypt_utf8(statement.K_der,'Spark coin memo',statement.coin.memo_enc)

	if not statement.coin.C == value*statement.G + hash_to_scalar('val',statement.K_der)*statement.F:
		raise ArithmeticError('Failed pay verification!')
