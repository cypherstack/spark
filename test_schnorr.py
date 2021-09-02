import schnorr
from dumb25519 import random_point, random_scalar
import unittest

class TestSchnorr(unittest.TestCase):
	def test_complete(self):
		params = schnorr.SchnorrParameters(random_point())

		y = random_scalar()
		witness = schnorr.SchnorrWitness(y)

		Y = y*params.G
		statement = schnorr.SchnorrStatement(params,Y)

		proof = schnorr.prove(statement,witness)
		schnorr.verify(statement,proof)

if __name__ == '__main__':
	unittest.main()