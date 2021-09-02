# Modified Chaum proving system
#
# {(G,F,H),Y,Z ; (x,y) | Y = xG + yF, H = xZ}

from dumb25519 import Point, Scalar, random_scalar
import transcript

class ChaumParameters:
	def __init__(self,G,F,H):
		if not isinstance(G,Point):
			raise TypeError('Bad type for parameter G!')
		if not isinstance(F,Point):
			raise TypeError('Bad type for parameter F!')
		if not isinstance(H,Point):
			raise TypeError('Bad type for parameter F!')
		
		self.G = G
		self.F = F
		self.H = H

class ChaumStatement:
	def __init__(self,params,Y,Z):
		if not isinstance(params,ChaumParameters):
			raise TypeError('Bad type for parameters!')
		if not isinstance(Y,Point):
			raise TypeError('Bad type for Chaum statement input Y!')
		if not isinstance(Z,Point):
			raise TypeError('Bad type for Chaum statement input Z!')
		
		self.G = params.G
		self.F = params.F
		self.H = params.H
		self.Y = Y
		self.Z = Z

class ChaumWitness:
	def __init__(self,x,y):
		if not isinstance(x,Scalar):
			raise TypeError('Bad type for Chaum witness x!')
		if not isinstance(y,Scalar):
			raise TypeError('Bad type for Chaum witness y!')
		
		self.x = x
		self.y = y

class ChaumProof:
	def __init__(self,A1,A2,A3,t1,t2):
		if not isinstance(A1,Point):
			raise TypeError('Bad type for Chaum proof element A1!')
		if not isinstance(A2,Point):
			raise TypeError('Bad type for Chaum proof element A2!')
		if not isinstance(A3,Point):
			raise TypeError('Bad type for Chaum proof element A3!')
		if not isinstance(t1,Scalar):
			raise TypeError('Bad type for Chaum proof element t1!')
		if not isinstance(t2,Scalar):
			raise TypeError('Bad type for Chaum proof element t2!')

		self.A1 = A1
		self.A2 = A2
		self.A3 = A3
		self.t1 = t1
		self.t2 = t2

def challenge(statement,A1,A2,A3):
	if not isinstance(statement,ChaumStatement):
		raise TypeError('Bad type for Chaum statement!')
	if not isinstance(A1,Point):
		raise TypeError('Bad type for challenge input A1!')
	if not isinstance(A2,Point):
		raise TypeError('Bad type for challenge input A2!')
	if not isinstance(A3,Point):
		raise TypeError('Bad type for challenge input A3!')

	tr = transcript.Transcript('Modified Chaum')
	tr.update(statement.G)
	tr.update(statement.F)
	tr.update(statement.H)
	tr.update(statement.Y)
	tr.update(statement.Z)
	tr.update(A1)
	tr.update(A2)
	tr.update(A3)
	return tr.challenge()

def prove(statement,witness):
	if not isinstance(statement,ChaumStatement):
		raise TypeError('Bad type for Chaum statement!')
	if not isinstance(witness,ChaumWitness):
		raise TypeError('Bad type for Chaum witness!')
	
	# Check the statement validity
	if not statement.Y == witness.x*statement.G + witness.y*statement.F:
		raise ArithmeticError('Invalid Chaum statement!')
	if not statement.H == witness.x*statement.Z:
		raise ArithmeticError('Invalid Chaum statement!')
	
	r = random_scalar()
	s = random_scalar()

	A1 = r*statement.G
	A2 = r*statement.Z
	A3 = s*statement.F

	c = challenge(statement,A1,A2,A3)

	t1 = r + c*witness.x
	t2 = s + c*witness.y

	return ChaumProof(A1,A2,A3,t1,t2)

def verify(statement,proof):
	if not isinstance(statement,ChaumStatement):
		raise TypeError('Bad type for Chaum statement!')
	if not isinstance(proof,ChaumProof):
		raise TypeError('Bad type for Chaum proof!')
	
	c = challenge(statement,proof.A1,proof.A2,proof.A3)

	if not proof.A1 + proof.A3 + c*statement.Y == proof.t1*statement.G + proof.t2*statement.F:
		raise ArithmeticError('Failed Chaum verification!')
	if not proof.A2 + c*statement.H == proof.t1*statement.Z:
		raise ArithmeticError('Failed Chaum verification!')
