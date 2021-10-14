# Modified Chaum proving system
#
# {(F,G,H,U),S,T ; (x,y,z) | S = xF + yG + zH, U = xT + yG}

from dumb25519 import Point, Scalar, hash_to_scalar, random_scalar
import transcript

class ChaumParameters:
	def __init__(self,F,G,H,U):
		if not isinstance(F,Point):
			raise TypeError('Bad type for parameter F!')
		if not isinstance(G,Point):
			raise TypeError('Bad type for parameter G!')
		if not isinstance(H,Point):
			raise TypeError('Bad type for parameter H!')
		if not isinstance(U,Point):
			raise TypeError('Bad type for parameter U!')
		
		self.F = F
		self.G = G
		self.H = H
		self.U = U

class ChaumStatement:
	def __init__(self,params,context,S,T):
		if not isinstance(params,ChaumParameters):
			raise TypeError('Bad type for parameters!')
		if not isinstance(S,Point):
			raise TypeError('Bad type for Chaum statement input S!')
		if not isinstance(T,Point):
			raise TypeError('Bad type for Chaum statement input T!')
		
		self.F = params.F
		self.G = params.G
		self.H = params.H
		self.U = params.U
		self.context = context
		self.S = S
		self.T = T

class ChaumWitness:
	def __init__(self,x,y,z):
		if not isinstance(x,Scalar):
			raise TypeError('Bad type for Chaum witness x!')
		if not isinstance(y,Scalar):
			raise TypeError('Bad type for Chaum witness y!')
		if not isinstance(z,Scalar):
			raise TypeError('Bad type for Chaum witness z!')
		
		self.x = x
		self.y = y
		self.z = z

class ChaumProof:
	def __repr__(self):
		return repr(hash_to_scalar(
			self.A1,
			self.A2,
			self.t1,
			self.t2,
			self.t3
		))

	def __init__(self,A1,A2,t1,t2,t3):
		if not isinstance(A1,Point):
			raise TypeError('Bad type for Chaum proof element A1!')
		if not isinstance(A2,Point):
			raise TypeError('Bad type for Chaum proof element A2!')
		if not isinstance(t1,Scalar):
			raise TypeError('Bad type for Chaum proof element t1!')
		if not isinstance(t2,Scalar):
			raise TypeError('Bad type for Chaum proof element t2!')
		if not isinstance(t3,Scalar):
			raise TypeError('Bad type for Chaum proof element t3!')

		self.A1 = A1
		self.A2 = A2
		self.t1 = t1
		self.t2 = t2
		self.t3 = t3

def challenge(statement,A1,A2):
	if not isinstance(statement,ChaumStatement):
		raise TypeError('Bad type for Chaum statement!')
	if not isinstance(A1,Point):
		raise TypeError('Bad type for challenge input A1!')
	if not isinstance(A2,Point):
		raise TypeError('Bad type for challenge input A2!')

	tr = transcript.Transcript('Modified Chaum')
	tr.update(statement.F)
	tr.update(statement.G)
	tr.update(statement.H)
	tr.update(statement.U)
	tr.update(statement.context)
	tr.update(statement.S)
	tr.update(statement.T)
	tr.update(A1)
	tr.update(A2)
	return tr.challenge()

def prove(statement,witness):
	if not isinstance(statement,ChaumStatement):
		raise TypeError('Bad type for Chaum statement!')
	if not isinstance(witness,ChaumWitness):
		raise TypeError('Bad type for Chaum witness!')
	
	# Check the statement validity
	if not statement.S == witness.x*statement.F + witness.y*statement.G + witness.z*statement.H:
		raise ArithmeticError('Invalid Chaum statement!')
	if not statement.U == witness.x*statement.T + witness.y*statement.G:
		raise ArithmeticError('Invalid Chaum statement!')
	
	r = random_scalar()
	s = random_scalar()
	t = random_scalar()

	A1 = r*statement.F + s*statement.G + t*statement.H
	A2 = r*statement.T + s*statement.G

	c = challenge(statement,A1,A2)

	t1 = r + c*witness.x
	t2 = s + c*witness.y
	t3 = t + c*witness.z

	return ChaumProof(A1,A2,t1,t2,t3)

def verify(statement,proof):
	if not isinstance(statement,ChaumStatement):
		raise TypeError('Bad type for Chaum statement!')
	if not isinstance(proof,ChaumProof):
		raise TypeError('Bad type for Chaum proof!')
	
	c = challenge(statement,proof.A1,proof.A2)

	if not proof.A1 + c*statement.S == proof.t1*statement.F + proof.t2*statement.G + proof.t3*statement.H:
		raise ArithmeticError('Failed Chaum verification!')
	if not proof.A2 + c*statement.U == proof.t1*statement.T + proof.t2*statement.G:
		raise ArithmeticError('Failed Chaum verification!')
