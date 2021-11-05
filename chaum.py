# Aggregated modified Chaum proving system

from dumb25519 import Z, Point, PointVector, Scalar, ScalarVector, hash_to_scalar, random_scalar
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
		if not isinstance(S,PointVector):
			raise TypeError('Bad type for Chaum statement input S!')
		if not isinstance(T,PointVector):
			raise TypeError('Bad type for Chaum statement input T!')
		if not len(S) == len(T):
			raise ValueError('Size mismatch for Chaum statement!')
		
		self.F = params.F
		self.G = params.G
		self.H = params.H
		self.U = params.U
		self.context = context
		self.S = S
		self.T = T

class ChaumWitness:
	def __init__(self,x,y,z):
		if not isinstance(x,ScalarVector):
			raise TypeError('Bad type for Chaum witness x!')
		if not isinstance(y,ScalarVector):
			raise TypeError('Bad type for Chaum witness y!')
		if not isinstance(z,ScalarVector):
			raise TypeError('Bad type for Chaum witness z!')
		if not len(x) == len(y) and len(y) == len(z):
			raise ValueError('Size mismatch for Chaum witness!')
		
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
		if not isinstance(A2,PointVector):
			raise TypeError('Bad type for Chaum proof element A2!')
		if not isinstance(t1,ScalarVector):
			raise TypeError('Bad type for Chaum proof element t1!')
		if not isinstance(t2,Scalar):
			raise TypeError('Bad type for Chaum proof element t2!')
		if not isinstance(t3,Scalar):
			raise TypeError('Bad type for Chaum proof element t3!')
		if not len(A2) == len(t1):
			raise ValueError('Size mismatch in Chaum proof!')

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
	if not isinstance(A2,PointVector):
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
	
	n = len(statement.S)
	
	# Check the statement validity
	for i in range(n):
		if not statement.S[i] == witness.x[i]*statement.F + witness.y[i]*statement.G + witness.z[i]*statement.H:
			raise ArithmeticError('Invalid Chaum statement!')
		if not statement.U == witness.x[i]*statement.T[i] + witness.y[i]*statement.G:
			raise ArithmeticError('Invalid Chaum statement!')
	
	r = ScalarVector([random_scalar() for _ in range(n)])
	s = ScalarVector([random_scalar() for _ in range(n)])
	t = random_scalar()

	A1 = t*statement.H
	for i in range(n):
		A1 += r[i]*statement.F + s[i]*statement.G
	A2 = PointVector([r[i]*statement.T[i] + s[i]*statement.G for i in range(n)])

	c = challenge(statement,A1,A2)

	t1 = ScalarVector([r[i] + c**i*witness.x[i] for i in range(n)])
	t2 = Scalar(0)
	t3 = t
	for i in range(n):
		t2 += s[i] + c**i*witness.y[i]
		t3 += c**i*witness.z[i]

	return ChaumProof(A1,A2,t1,t2,t3)

def verify(statement,proof):
	if not isinstance(statement,ChaumStatement):
		raise TypeError('Bad type for Chaum statement!')
	if not isinstance(proof,ChaumProof):
		raise TypeError('Bad type for Chaum proof!')
	if not len(proof.A2) == len(statement.S):
		raise ValueError('Size mismatch in Chaum verification!')
	
	n = len(statement.S)
	
	c = challenge(statement,proof.A1,proof.A2)

	L = proof.A1
	R = proof.t2*statement.G + proof.t3*statement.H
	for i in range(n):
		L += c**i*statement.S[i]
		R += proof.t1[i]*statement.F
	if not L == R:
		raise ArithmeticError('Failed Chaum verification!')
	
	L = Z
	R = proof.t2*statement.G
	for i in range(n):
		L += proof.A2[i] + c**i*statement.U
		R += proof.t1[i]*statement.T[i]
	if not L == R:
		raise ArithmeticError('Failed Chaum verification!')
