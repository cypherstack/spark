# Parallel one-of-many Groth/Bootle-type proving system
#
# {F,{S,V},S1,V1 ; (l,s,v) | S_l - S1 = sF, V_l - V1 = vF}

from dumb25519 import *
import transcript

class ParallelParameters:
	def __init__(self,F,n,m):
		if not isinstance(F,Point):
			raise TypeError('Bad type for parameter F!')
		if not isinstance(n,int) or not n > 1:
			raise TypeError('Bad type or value for parameter n!')
		if not isinstance(m,int) or not m > 1:
			raise TypeError('Bad type or value for parameter m!')
		
		self.F = F
		self.n = n
		self.m = m

class ParallelStatement:
	def __init__(self,params,S,V,S1,V1):
		if not isinstance(params,ParallelParameters):
			raise TypeError('Bad type for parameters!')
		n = params.n
		m = params.m
		if not isinstance(S,PointVector) or not len(S) == n**m:
			raise TypeError('Bad type or length for parallel statement input S!')
		if not isinstance(V,PointVector) or not len(V) == n**m:
			raise TypeError('Bad type or length for parallel statement input V!')
		if not isinstance(S1,Point):
			raise TypeError('Bad type for parallel statement input S1!')
		if not isinstance(V1,Point):
			raise TypeError('Bad type for parallel statement input V1!')
		
		self.F = params.F
		self.n = n
		self.m = m
		self.S = S
		self.V = V
		self.S1 = S1
		self.V1 = V1
		self.Gi = [PointVector([hash_to_point('Gi',j,i) for i in range(n)]) for j in range(m)]

class ParallelWitness:
	def __init__(self,l,s,v):
		if not isinstance(l,int):
			raise TypeError('Bad type for parallel witness l!')
		if not isinstance(s,Scalar):
			raise TypeError('Bad type for parallel witness s!')
		if not isinstance(v,Scalar):
			raise TypeError('Bad type for parallel witness v!')
		
		self.l = l
		self.s = s
		self.v = v

class ParallelProof:
	def __repr__(self):
		return repr(hash_to_scalar(
			self.A,
			self.B,
			self.C,
			self.D,
			self.Gs,
			self.Gv,
			self.f,
			self.zA,
			self.zC,
			self.zS,
			self.zV
		))

	def __init__(self,A,B,C,D,Gs,Gv,f,zA,zC,zS,zV):
		if not isinstance(A,Point):
			raise TypeError('Bad type for parallel proof element A!')
		if not isinstance(B,Point):
			raise TypeError('Bad type for parallel proof element B!')
		if not isinstance(C,Point):
			raise TypeError('Bad type for parallel proof element C!')
		if not isinstance(D,Point):
			raise TypeError('Bad type for parallel proof element D!')
		if not isinstance(Gs,PointVector):
			raise TypeError('Bad type for parallel proof element Gs!')
		if not isinstance(Gv,PointVector):
			raise TypeError('Bad type for parallel proof element Gv!')
		if not isinstance(f,list):
			raise TypeError('Bad type for parallel proof element f!')
		for f_ in f:
			if not isinstance(f_,ScalarVector):
				raise TypeError('Bad type for parallel proof element f!')
		if not isinstance(zA,Scalar):
			raise TypeError('Bad type for parallel proof element zA!')
		if not isinstance(zC,Scalar):
			raise TypeError('Bad type for parallel proof element zC!')
		if not isinstance(zS,Scalar):
			raise TypeError('Bad type for parallel proof element zS!')
		if not isinstance(zV,Scalar):
			raise TypeError('Bad type for parallel proof element zV!')

		self.A = A
		self.B = B
		self.C = C
		self.D = D
		self.Gs = Gs
		self.Gv = Gv
		self.f = f
		self.zA = zA
		self.zC = zC
		self.zS = zS
		self.zV = zV

# Pedersen matrix commitment
def com_matrix(Gi,F,v,r):
	C = r*F
	for j in range(len(v)):
		for i in range(len(v[0])):
			C += Gi[j][i]*v[j][i]
	return C

# Kronecker delta
def delta(x,y):
	if x == y:
		return Scalar(1)
	return Scalar(0)

# Compute a convolution with a degree-one polynomial
def convolve(x,y):
	if not len(y) == 2:
		raise ValueError('Convolution requires a degree-one polynomial!')

	r = [Scalar(0)]*(len(x)+1)
	for i in range(len(x)):
		for j in range(len(y)):
			r[i+j] += x[i]*y[j]

	return r

# Decompose a value with given base and size
def decompose(val,base,size):
	r = []
	for i in range(size-1,-1,-1):
		slot = base**i
		r.append(int(val/slot))
		val -= slot*r[-1]
	return list(reversed(r))

# Perform a commitment-to-zero proof
def prove(statement,witness):
	if not isinstance(statement,ParallelStatement):
		raise TypeError('Bad type for parallel statement!')
	if not isinstance(witness,ParallelWitness):
		raise TypeError('Bad type for parallel witness!')
	
	# Check the statement validity
	l = witness.l
	n = statement.n
	m = statement.m
	N = n**m

	if l < 0 or l >= N:
		raise IndexError('Invalid parallel witness!')
	if not statement.S[l] - statement.S1 == witness.s*statement.F:
		raise ArithmeticError('Invalid parallel statement!')
	if not statement.V[l] - statement.V1 == witness.v*statement.F:
		raise ArithmeticError('Invalid parallel statement!')
	
	# Begin the proof
	rA = random_scalar()
	rB = random_scalar()
	rC = random_scalar()
	rD = random_scalar()

	# Commit to zero-sum blinders
	a = [[random_scalar() for _ in range(n)] for _ in range(m)]
	for j in range(m):
		a[j][0] = Scalar(0)
		for i in range(1,n):
			a[j][0] -= a[j][i]
	A = com_matrix(statement.Gi,statement.F,a,rA)

	# Commit to decomposition bits
	decomp_l = decompose(l,n,m)
	sigma = [[Scalar(0) for _ in range(n)] for _ in range(m)]
	for j in range(m):
		for i in range(n):
			sigma[j][i] = delta(decomp_l[j],i)
	B = com_matrix(statement.Gi,statement.F,sigma,rB)

	# Commit to a/sigma relationships
	a_sigma = [[Scalar(0) for _ in range(n)] for _ in range(m)]
	for j in range(m):
		for i in range(n):
			a_sigma[j][i] = a[j][i]*(Scalar(1) - Scalar(2)*sigma[j][i])
	C = com_matrix(statement.Gi,statement.F,a_sigma,rC)
	
	# Commit to squared a-values
	a_sq = [[Scalar(0) for _ in range(n)] for _ in range(m)]
	for j in range(m):
		for i in range(n):
			a_sq[j][i] = -a[j][i]*a[j][i]
	D = com_matrix(statement.Gi,statement.F,a_sq,rD)

	# Compute p coefficients
	p = [[] for _ in range(N)]
	for k in range(N):
		decomp_k = decompose(k,n,m)
		p[k] = [a[0][decomp_k[0]],delta(decomp_l[0],decomp_k[0])]
		
		for j in range(1,m):
			p[k] = convolve(p[k],[a[j][decomp_k[j]],delta(decomp_l[j],decomp_k[j])])

	# Generate proof values
	Gs = PointVector([Z for _ in range(m)])
	Gv = PointVector([Z for _ in range(m)])
	rho_S = ScalarVector([random_scalar() for _ in range(m)])
	rho_V = ScalarVector([random_scalar() for _ in range(m)])
	for j in range(m):
		for i in range(N):
			Gs[j] += (statement.S[i] - statement.S1)*p[i][j]
			Gv[j] += (statement.V[i] - statement.V1)*p[i][j]
		Gs[j] += rho_S[j]*statement.F
		Gv[j] += rho_V[j]*statement.F

	# Challenge
	tr = transcript.Transcript('Parallel Groth/Bootle')
	tr.update(statement.F)
	tr.update(n)
	tr.update(m)
	tr.update(statement.S)
	tr.update(statement.V)
	tr.update(statement.S1)
	tr.update(statement.V1)
	tr.update(A)
	tr.update(B)
	tr.update(C)
	tr.update(D)
	tr.update(Gs)
	tr.update(Gv)

	x = tr.challenge()

	f = [ScalarVector([Scalar(0) for _ in range(n-1)]) for _ in range(m)]
	for j in range(m):
		for i in range(1,n):
			f[j][i-1] = sigma[j][i]*x + a[j][i]

	zA = rB*x + rA
	zC = rC*x + rD
	zS = witness.s*x**m
	zV = witness.v*x**m
	for j in range(m):
		zS -= rho_S[j]*x**j
		zV -= rho_V[j]*x**j
	
	return ParallelProof(A,B,C,D,Gs,Gv,f,zA,zC,zS,zV)

# Verify a commitment-to-zero proof
def verify(statement,proof):
	# Check statement consistency
	if not isinstance(statement,ParallelStatement):
		raise TypeError('Bad type for parallel statement!')
	if not isinstance(proof,ParallelProof):
		raise TypeError('Bad type for parallel proof!')
	
	n = statement.n
	m = statement.m
	N = n**m
	f = [[Scalar(0) for _ in range(n)] for _ in range(m)]

	# Transcript and challenge
	tr = transcript.Transcript('Parallel Groth/Bootle')
	tr.update(statement.F)
	tr.update(n)
	tr.update(m)
	tr.update(statement.S)
	tr.update(statement.V)
	tr.update(statement.S1)
	tr.update(statement.V1)
	tr.update(proof.A)
	tr.update(proof.B)
	tr.update(proof.C)
	tr.update(proof.D)
	tr.update(proof.Gs)
	tr.update(proof.Gv)

	x = tr.challenge()

	# Matrix reconstruction
	for j in range(m):
		f[j][0] = x
		for i in range(1,n):
			f[j][i] = proof.f[j][i-1]
			f[j][0] -= f[j][i]

	# A/B check
	if not com_matrix(statement.Gi,statement.F,f,proof.zA) == proof.B*x + proof.A:
		raise ArithmeticError('Failed parallel A/B check!')

	# C/D check
	fx = [ScalarVector([Scalar(0) for _ in range(n)]) for _ in range(m)]
	for j in range(m):
		for i in range(n):
			fx[j][i] = f[j][i]*(x-f[j][i])
	if not com_matrix(statement.Gi,statement.F,fx,proof.zC) == proof.C*x + proof.D:
		raise ArithmeticError('Failed parallel C/D check!')

	# Commitment check
	scalars_S = ScalarVector([])
	points_S = PointVector([])
	scalars_V = ScalarVector([])
	points_V = PointVector([])
	scalar_S1_V1 = Scalar(0)
	for i in range(N):
		s = Scalar(1)
		decomp_i = decompose(i,n,m)
		for j in range(m):
			s *= f[j][decomp_i[j]]
		scalars_S.append(s)
		scalars_V.append(s)
		points_S.append(statement.S[i])
		points_V.append(statement.V[i])
		scalar_S1_V1 -= s
	for j in range(m):
		scalars_S.append(-x**j)
		points_S.append(proof.Gs[j])
		scalars_V.append(-x**j)
		points_V.append(proof.Gv[j])
	scalars_S.append(scalar_S1_V1)
	scalars_V.append(scalar_S1_V1)
	points_S.append(statement.S1)
	points_V.append(statement.V1)
	
	if not multiexp(scalars_S,points_S) == proof.zS*statement.F or not multiexp(scalars_V,points_V) == proof.zV*statement.F:
		raise ArithmeticError('Failed parallel commitment check!')

	return True
