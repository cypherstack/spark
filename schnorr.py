# Schnorr discrete logarithm proof (shortened)
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
			self.c,
			self.t
		))

	def __init__(self,c,t):
		if not isinstance(c,Scalar):
			raise TypeError('Bad type for Schnorr proof element c!')
		if not isinstance(t,Scalar):
			raise TypeError('Bad type for Schnorr proof element t!')
		
		self.c = c # In practice, only the first half of the corresponding byte array is stored
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

	# Return a challenge of half length (uses hex representation)
	x = tr.challenge()
	length = len(repr(x))//2
	return Scalar(repr(x)[0:length] + '0'*length)

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

	return SchnorrProof(c,t)

def verify(statement,proof):
	if not isinstance(statement,SchnorrStatement):
		raise TypeError('Bad type for Schnorr statement!')
	if not isinstance(proof,SchnorrProof):
		raise TypeError('Bad type for Schnorr proof!')
	
	c = challenge(statement,proof.t*statement.G - proof.c*statement.Y)

	if not proof.c == c:
		raise ArithmeticError('Failed Schnorr verification!')
