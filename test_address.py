import address
from dumb25519 import random_point
import unittest

class TestAddress(unittest.TestCase):
	def test_generate(self):
		params = address.AddressParameters(random_point(),random_point())
		spend = address.SpendKey()
		full = address.FullViewKey(params,spend)
		incoming = address.IncomingViewKey(full)
		public = address.PublicAddress(params,spend)

		self.assertEqual(incoming.s1,spend.s1)
		self.assertEqual(full.s1,spend.s1)
		self.assertEqual(full.s2,spend.s2)
		self.assertEqual(full.D,spend.r*params.F)
		self.assertEqual(public.Q1,spend.s1*params.G)
		self.assertEqual(public.Q2,spend.s2*params.G + spend.r*params.F)

if __name__ == '__main__':
	unittest.main()