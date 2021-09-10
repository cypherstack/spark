# Schnorr discrete logarithm proof
#
# {G,Y ; (y) | Y = yG}

from dumb25519 import Point, Scalar, hash_to_scalar, random_scalar
import transcript

class SchnorrParameters:
	def __init__(self,G):
		if not isinstance(G,Point):
			raise TypeError('Bad type for parameter G!')
		
		self.G = G

class SchnorrStatement:
	def __init__(self,params,Y):
		if not isinstance(params,SchnorrParameters):
			raise TypeError('Bad type for parameters!')
		if not isinstance(Y,Point):
			raise TypeError('Bad type for Schnorr statement input Y!')
		
		self.G = params.G
		self.Y = Y

class SchnorrWitness:
	def __init__(self,y):
		if not isinstance(y,Scalar):
			raise TypeError('Bad type for Schnorr witness y!')
		
		self.y = y

class SchnorrProof:
	def __repr__(self):
		return repr(hash_to_scalar(
			self.A,
			self.t
		))

	def __init__(self,A,t):
		if not isinstance(A,Point):
			raise TypeError('Bad type for Schnorr proof element A!')
		if not isinstance(t,Scalar):
			raise TypeError('Bad type for Schnorr proof element t!')
		
		self.A = A
		self.t = t

def challenge(statement,A):
	if not isinstance(statement,SchnorrStatement):
		raise TypeError('Bad type for Schnorr statement!')
	if not isinstance(A,Point):
		raise TypeError('Bad type for challenge input A!')
	
	tr = transcript.Transcript('Schnorr')
	tr.update(statement.G)
	tr.update(statement.Y)
	tr.update(A)
	return tr.challenge()

def prove(statement,witness):
	if not isinstance(statement,SchnorrStatement):
		raise TypeError('Bad type for Schnorr statement!')
	if not isinstance(witness,SchnorrWitness):
		raise TypeError('Bad type for Schnorr witness!')
	
	# Check the statement validity
	if not statement.Y == witness.y*statement.G:
		raise ArithmeticError('Invalid Schnorr statement!')

	r = random_scalar()

	A = r*statement.G

	c = challenge(statement,A)

	t = r + c*witness.y

	return SchnorrProof(A,t)

def verify(statement,proof):
	if not isinstance(statement,SchnorrStatement):
		raise TypeError('Bad type for Schnorr statement!')
	if not isinstance(proof,SchnorrProof):
		raise TypeError('Bad type for Schnorr proof!')
	
	c = challenge(statement,proof.A)

	if not proof.A + c*statement.Y == proof.t*statement.G:
		raise ArithmeticError('Failed Schnorr verification!')
