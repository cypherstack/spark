import chaum
from dumb25519 import random_point, random_scalar, ScalarVector, PointVector
import unittest

class TestChaum(unittest.TestCase):
	def test_complete(self):
		params = chaum.ChaumParameters(random_point(),random_point(),random_point(),random_point())
		n = 3

		x = ScalarVector([random_scalar() for _ in range(n)])
		y = ScalarVector([random_scalar() for _ in range(n)])
		z = ScalarVector([random_scalar() for _ in range(n)])
		witness = chaum.ChaumWitness(x,y,z)

		S = PointVector([x[i]*params.F + y[i]*params.G + z[i]*params.H for i in range(n)])
		T = PointVector([x[i].invert()*(params.U - y[i]*params.G) for i in range(n)])
		statement = chaum.ChaumStatement(params,'Proof context',S,T)

		proof = chaum.prove(statement,witness)
		chaum.verify(statement,proof)

if __name__ == '__main__':
	unittest.main()