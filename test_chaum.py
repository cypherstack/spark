import chaum
from dumb25519 import random_point, random_scalar
import unittest

class TestChaum(unittest.TestCase):
	def test_complete(self):
		params = chaum.ChaumParameters(random_point(),random_point(),random_point(),random_point())

		x = random_scalar()
		y = random_scalar()
		z = random_scalar()
		witness = chaum.ChaumWitness(x,y,z)

		S = x*params.F + y*params.G + z*params.H
		T = x.invert()*(params.U - y*params.G)
		statement = chaum.ChaumStatement(params,'Proof context',S,T)

		proof = chaum.prove(statement,witness)
		chaum.verify(statement,proof)

if __name__ == '__main__':
	unittest.main()