# Bulletproof+ range proof
#
# {(G,H,n),C ; (v,r) | 0 <= v < 2^n, C = vH + rG}

import dumb25519
from dumb25519 import Point, Scalar, ScalarVector, PointVector, hash_to_scalar, random_scalar, hash_to_point, multiexp
import transcript

class RangeParameters:
	def __init__(self,G,H,N):
		if not isinstance(G,Point):
			raise TypeError('Bad type for parameter G!')
		if not isinstance(H,Point):
			raise TypeError('Bad type for parameter H!')
		if not isinstance(N,int) or N < 1:
			raise ValueError('Bad type or value for parameter N!')
		
		self.G = G
		self.H = H
		self.N = N

class RangeStatement:
	def __init__(self,params,C):
		if not isinstance(params,RangeParameters):
			raise TypeError('Bad type for parameters!')
		if not isinstance(C,PointVector):
			raise TypeError('Bad type for range statement input C!')
		
		self.G = params.G
		self.H = params.H
		self.N = params.N
		self.C = C
		self.Gi = PointVector([hash_to_point('Gi ' + str(i)) for i in range(len(C)*self.N)])
		self.Hi = PointVector([hash_to_point('Hi ' + str(i)) for i in range(len(C)*self.N)])

class RangeWitness:
	def __init__(self,v,r):
		if not isinstance(v,ScalarVector):
			raise TypeError('Bad type for range witness v!')
		if not isinstance(r,ScalarVector):
			raise TypeError('Bad type for range witness r!')
		if not len(v) == len(r):
			raise IndexError('Range witness data length mismatch!')
		
		self.v = v
		self.r = r

class RangeProof:
	def __repr__(self):
		return repr(hash_to_scalar(
			self.A,
			self.A1,
			self.B,
			self.r1,
			self.s1,
			self.d1,
			self.L,
			self.R
		))

	def __init__(self,A,A1,B,r1,s1,d1,L,R):
		if not isinstance(A,Point):
			raise TypeError('Bad type for range proof element A!')
		if not isinstance(A1,Point):
			raise TypeError('Bad type for range proof element A1!')
		if not isinstance(B,Point):
			raise TypeError('Bad type for range proof element B!')
		if not isinstance(r1,Scalar):
			raise TypeError('Bad type for range proof element r1!')
		if not isinstance(s1,Scalar):
			raise TypeError('Bad type for range proof element s1!')
		if not isinstance(d1,Scalar):
			raise TypeError('Bad type for range proof element d1!')
		if not isinstance(L,PointVector):
			raise TypeError('Bad type for range proof element L!')
		if not isinstance(R,PointVector):
			raise TypeError('Bad type for range proof element R!')
		if not len(L) == len(R):
			raise IndexError('Range proof data length mismatch!')

		self.A = A
		self.A1 = A1
		self.B = B
		self.r1 = r1
		self.s1 = s1
		self.d1 = d1
		self.L = L
		self.R = R

# Data for a round of the inner product argument
class InnerProductRound:
	def __init__(self,Gi,Hi,G,H,a,b,alpha,y,tr):
		# Common data
		self.Gi = Gi
		self.Hi = Hi
		self.G = G
		self.H = H
		self.y = y
		self.done = False

		# Prover data
		self.a = a
		self.b = b
		self.alpha = alpha

		# Verifier data
		self.A = None
		self.B = None
		self.r1 = None
		self.s1 = None
		self.d1 = None
		self.L = PointVector([])
		self.R = PointVector([])

		# Transcript
		self.tr = tr

# Compute a weighted inner product
#
# INPUTS
#   a,b: (ScalarVector)
#   y: weight (Scalar)
# OUTPUTS
#   Scalar
def wip(a,b,y):
	if not len(a) == len(b):
		raise IndexError('Weighted inner product vectors must have identical size!')
	if not isinstance(a,ScalarVector) or not isinstance(b,ScalarVector):
		raise TypeError('Weighted inner product requires ScalarVectors!')
	if not isinstance(y,Scalar):
		raise TypeError('Weighted inner product requires Scalar weight!')

	r = Scalar(0)
	for i in range(len(a)):
		r += a[i]*y**(i+1)*b[i]
	return r

# Turn a scalar into a vector of bit scalars
#
# INPUTS
#   s: (Scalar)
#   N: number of bits (int)
# OUTPUTS
#   ScalarVector
def scalar_to_bits(s,N):
	result = []
	for i in range(N-1,-1,-1):
		if s/Scalar(2**i) == Scalar(0):
			result.append(Scalar(0))
		else:
			result.append(Scalar(1))
			s -= Scalar(2**i)
	return ScalarVector(list(reversed(result)))

# Generate a vector of powers of a scalar, in either direction, indexed at 1
#
# INPUTS
#   s: (Scalar)
#   l: number of powers to include (int)
#   desc: whether to use a descending indexing (bool)
# OUTPUTS
#   ScalarVector
def exp_scalar(s,l,desc=False):
	if desc:
		return ScalarVector([s**(l-i) for i in range(l)])
	else:
		return ScalarVector([s**(i+1) for i in range(l)])

# Perform an inner-product proof round
#
# INPUTS
#   data: round data (InnerProductRound)
def inner_product(data):
	n = len(data.Gi)

	if n == 1:
		data.done = True

		# Random masks
		r = random_scalar()
		s = random_scalar()
		d = random_scalar()
		eta = random_scalar()

		data.A = data.Gi[0]*r + data.Hi[0]*s + data.H*(r*data.y*data.b[0] + s*data.y*data.a[0]) + data.G*d
		data.B = data.H*(r*data.y*s) + data.G*eta

		data.tr.update(data.A)
		data.tr.update(data.B)
		e = data.tr.challenge()

		data.r1 = r + data.a[0]*e
		data.s1 = s + data.b[0]*e
		data.d1 = eta + d*e + data.alpha*e**2

		return

	n //= 2
	a1 = data.a[:n]
	a2 = data.a[n:]
	b1 = data.b[:n]
	b2 = data.b[n:]
	G1 = data.Gi[:n]
	G2 = data.Gi[n:]
	H1 = data.Hi[:n]
	H2 = data.Hi[n:]

	dL = random_scalar()
	dR = random_scalar()

	cL = wip(a1,b2,data.y)
	cR = wip(a2*data.y**n,b1,data.y)
	data.L.append(G2**(a1*data.y.invert()**n) + H1**b2 + data.H*cL + data.G*dL)
	data.R.append(G1**(a2*data.y**n) + H2**b1 + data.H*cR + data.G*dR)

	data.tr.update(data.L[-1])
	data.tr.update(data.R[-1])
	e = data.tr.challenge()

	data.Gi = G1*e.invert() + G2*(e*data.y.invert()**n)
	data.Hi = H1*e + H2*e.invert()

	data.a = a1*e + a2*data.y**n*e.invert()
	data.b = b1*e.invert() + b2*e
	data.alpha = dL*e**2 + data.alpha + dR*e.invert()**2

# Generate a multi-output proof
def prove(statement,witness):
	if not isinstance(statement,RangeStatement):
		raise TypeError('Bad type for range statement!')
	if not isinstance(witness,RangeWitness):
		raise TypeError('Bad type for range witness!')
	
	# Check the statement validity
	if not len(statement.C) == len(witness.v):
		raise IndexError('Range statement/witness length mismatch!')
	m = len(statement.C)
	for j in range(m):
		if not statement.C[j] == witness.v[j]*statement.H + witness.r[j]*statement.G:
			raise ArithmeticError('Invalid range statement!')

	N = statement.N
	M = len(statement.C)

	# Curve points
	G = statement.G
	H = statement.H
	Gi = statement.Gi
	Hi = statement.Hi

	tr = transcript.Transcript('Bulletproof+')
	tr.update(G)
	tr.update(H)
	tr.update(N)
	for C in statement.C:
		tr.update(C)

	one_MN = ScalarVector([Scalar(1) for _ in range(M*N)])

	# Set amount commitments
	aL = ScalarVector([])
	for j in range(M):
		aL.extend(scalar_to_bits(witness.v[j],N))

	# Set offset bit array
	aR = aL - one_MN

	alpha = random_scalar()
	A = Gi**aL + Hi**aR + G*alpha

	# Get challenges
	tr.update(A)
	y = tr.challenge()
	z = tr.challenge()

	d = ScalarVector([])
	for j in range(M):
		for i in range(N):
			d.append(z**(2*(j+1))*Scalar(2)**i)

	# Prepare for inner product
	aL1 = aL - one_MN*z
	aR1 = aR + d*exp_scalar(y,M*N,desc=True) + one_MN*z
	alpha1 = alpha
	for j in range(M):
		alpha1 += z**(2*(j+1))*witness.r[j]*y**(M*N+1)

	# Initial inner product inputs
	ip_data = InnerProductRound(Gi,Hi,G,H,aL1,aR1,alpha1,y,tr)
	while True:
		inner_product(ip_data)

		# We have reached the end of the recursion
		if ip_data.done:
			return RangeProof(A,ip_data.A,ip_data.B,ip_data.r1,ip_data.s1,ip_data.d1,ip_data.L,ip_data.R)

# Verify a batch of multi-output proofs
def verify(statements,proofs):
	# Check statement consistency
	G = None
	H = None
	N = None
	max_MN = None
	Gi = None
	Hi = None

	if not len(statements) == len(proofs):
		raise IndexError('Range statement/proof length mismatch!')

	for statement in statements:
		if not isinstance(statement,RangeStatement):
			raise TypeError('Bad type for range statement!')

		if G is not None and statement.G != G:
			raise ValueError('Inconsistent range batch statements!')
		else:
			G = statement.G

		if H is not None and statement.H != H:
			raise ValueError('Inconsistent range batch statements!')
		else:
			H = statement.H

		if N is not None and statement.N != N:
			raise ValueError('Inconsistent range batch statements!')
		else:
			N = statement.N
		
		if max_MN is None or len(statement.C)*statement.N > max_MN:
			max_MN = len(statement.C)*statement.N
			Gi = statement.Gi
			Hi = statement.Hi
	
	for proof in proofs:
		if not isinstance(proof,RangeProof):
			raise TypeError('Bad type for range proof!')
	
	# Weighted coefficients for common generators
	G_scalar = Scalar(0)
	H_scalar = Scalar(0)
	Gi_scalars = ScalarVector([Scalar(0)]*max_MN)
	Hi_scalars = ScalarVector([Scalar(0)]*max_MN)

	# Final multiscalar multiplication data
	scalars = ScalarVector([])
	points = PointVector([])

	# Process each proof and add it to the batch
	for index,proof in enumerate(proofs):
		C = statements[index].C
		A = proof.A
		A1 = proof.A1
		B = proof.B
		r1 = proof.r1
		s1 = proof.s1
		d1 = proof.d1
		L = proof.L
		R = proof.R

		if not len(L) == len(R):
			raise IndexError
		if not 2**len(L) == len(C)*N:
			raise IndexError

		# Helpful quantities
		M = len(C)
		one_MN = ScalarVector([Scalar(1) for _ in range(M*N)])

		# Batch weight
		weight = random_scalar()
		if weight == Scalar(0):
			raise ArithmeticError

		# Start transcript
		tr = transcript.Transcript('Bulletproof+')
		tr.update(statement.G)
		tr.update(statement.H)
		tr.update(statement.N)
		for C_ in C:
			tr.update(C_)

		# Reconstruct challenges
		tr.update(proof.A)
		y = tr.challenge()
		if y == Scalar(0):
			raise ArithmeticError('Bad verifier challenge!')
		z = tr.challenge()
		if z == Scalar(0):
			raise ArithmeticError('Bad verifier challenge!')

		# Start preparing data
		d = ScalarVector([])
		for j in range(M):
			for i in range(N):
				d.append(z**(2*(j+1))*Scalar(2)**i)

		# Reconstruct challenges
		challenges = ScalarVector([]) # challenges
		for j in range(len(L)):
			tr.update(L[j])
			tr.update(R[j])
			challenges.append(tr.challenge())
			if challenges[j] == Scalar(0):
				raise ArithmeticError('Bad verifier challenge!')
		challenges_inv = challenges.invert()
		tr.update(A1)
		tr.update(B)
		e = tr.challenge()
		if e == Scalar(0):
			raise ArithmeticError('Bad verifier challenge!')

		# Aggregate the generator scalars
		for i in range(M*N):
			index = i
			g = r1*e*y.invert()**i
			h = s1*e
			for j in range(len(L)-1,-1,-1):
				J = len(challenges)-j-1
				base_power = 2**j
				if index//base_power == 0: # rounded down
					g *= challenges_inv[J]
					h *= challenges[J]
				else:
					g *= challenges[J]
					h *= challenges_inv[J]
					index -= base_power
			Gi_scalars[i] += weight*(g + e**2*z)
			Hi_scalars[i] += weight*(h - e**2*(d[i]*y**(M*N-i)+z))

		# Remaining terms
		for j in range(M):
			scalars.append(weight*(-e**2*z**(2*(j+1))*y**(M*N+1)))
			points.append(C[j])

		H_scalar += weight*(r1*y*s1 + e**2*(y**(M*N+1)*z*one_MN**d + (z**2-z)*one_MN**exp_scalar(y,M*N)))
		G_scalar += weight*d1

		scalars.append(weight*-e)
		points.append(A1)
		scalars.append(-weight)
		points.append(B)
		scalars.append(weight*-e**2)
		points.append(A)

		for j in range(len(L)):
			scalars.append(weight*(-e**2*challenges[j]**2))
			points.append(L[j])
			scalars.append(weight*(-e**2*challenges_inv[j]**2))
			points.append(R[j])

	# Common generators
	scalars.append(G_scalar)
	points.append(G)
	scalars.append(H_scalar)
	points.append(H)
	for i in range(max_MN):
		scalars.append(Gi_scalars[i])
		points.append(Gi[i])
		scalars.append(Hi_scalars[i])
		points.append(Hi[i])

	if not multiexp(scalars,points) == dumb25519.Z:
		raise ArithmeticError('Failed verification!')
