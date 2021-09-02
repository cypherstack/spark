import bpplus
from dumb25519 import random_point, random_scalar, Scalar, ScalarVector, PointVector
from random import randrange
import unittest

class TestBPPlus(unittest.TestCase):
	def test_complete(self):
		params = bpplus.RangeParameters(random_point(),random_point(),4)
		n_commits = 2
		n_proofs = 4

		statements = []
		proofs = []
		for _ in range(n_proofs):
			v = ScalarVector([Scalar(randrange(0,2**params.N)) for _ in range(n_commits)])
			r = ScalarVector([random_scalar() for _ in range(n_commits)])
			witness = bpplus.RangeWitness(v,r)

			C = PointVector([v[i]*params.H + r[i]*params.G for i in range(n_commits)])
			statement = bpplus.RangeStatement(params,C)
			statements.append(statement)

			proof = bpplus.prove(statement,witness)
			proofs.append(proof)

		bpplus.verify(statements,proofs)

if __name__ == '__main__':
	unittest.main()