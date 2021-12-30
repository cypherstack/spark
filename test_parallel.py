import parallel
from dumb25519 import random_point, random_scalar, PointVector
from random import randrange
import unittest

class TestParallel(unittest.TestCase):
	def test_complete(self):
		params = parallel.ParallelParameters(random_point(),2,4)
		N = params.n**params.m

		l = randrange(0,N)
		s = random_scalar()
		v = random_scalar()
		witness = parallel.ParallelWitness(l,s,v)
		
		S = PointVector([random_point() for _ in range(N)])
		V = PointVector([random_point() for _ in range(N)])
		S1 = random_point()
		V1 = random_point()
		S[l] = s*params.F + S1
		V[l] = v*params.F + V1
		statement = parallel.ParallelStatement(params,S,V,S1,V1)

		proof = parallel.prove(statement,witness)
		parallel.verify(statement,proof)

if __name__ == '__main__':
	unittest.main()