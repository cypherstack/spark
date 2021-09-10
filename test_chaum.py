import chaum
from dumb25519 import random_point, random_scalar
import unittest

class TestChaum(unittest.TestCase):
	def test_complete(self):
		params = chaum.ChaumParameters(random_point(),random_point(),random_point())

		x = random_scalar()
		y = random_scalar()
		witness = chaum.ChaumWitness(x,y)

		Y = x*params.G + y*params.F
		Z = x.invert()*params.H
		statement = chaum.ChaumStatement(params,'Proof context',Y,Z)

		proof = chaum.prove(statement,witness)
		chaum.verify(statement,proof)

if __name__ == '__main__':
	unittest.main()