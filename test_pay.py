import address
import coin
import pay
from dumb25519 import random_point
import unittest

class TestPay(unittest.TestCase):
	def test_complete(self):
		address_params = address.AddressParameters(random_point(),random_point())
		coin_params = coin.CoinParameters(address_params.G,address_params.F,random_point(),4)
		pay_params = pay.PayParameters(address_params.G,address_params.F)

		public = address.PublicAddress(address_params,address.SpendKey())
		coin_ = coin.Coin(coin_params,public,1,'Test memo',False,True)

		witness = pay.PayWitness(coin_.k)
		statement = pay.PayStatement(pay_params,'Proof context',coin_,coin_.k*public.Q1,public)

		proof = pay.prove(statement,witness)
		pay.verify(statement,proof)

		with self.assertRaises(ArithmeticError):
			statement.context = 'Evil context'
			pay.verify(statement,proof)

if __name__ == '__main__':
	unittest.main()
