import address
import coin
from dumb25519 import random_point
from random import randrange
import unittest

class TestCoin(unittest.TestCase):
	def test_generate(self):
		address_params = address.AddressParameters(random_point(),random_point())
		coin_params = coin.CoinParameters(address_params.F,address_params.G,random_point(),random_point(),4)

		# Address
		spend = address.SpendKey()
		full = address.FullViewKey(address_params,spend)
		incoming = address.IncomingViewKey(full)
		public = address.PublicAddress(address_params,spend)

		# Coin data
		value = randrange(0,2**coin_params.N)
		memo = 'Test memo'

		for is_mint in [True,False]:
			# Generate the coin
			coin_ = coin.Coin(coin_params,public,value,memo,is_mint,True)

			# Identify
			coin_.identify(coin_params,public,incoming)
			self.assertEqual(int(coin_.value),value)
			self.assertEqual(coin_.memo,memo)

			# Recover
			coin_.recover(coin_params,public,full)
			self.assertEqual(int(coin_.value),value)
			self.assertEqual(coin_.memo,memo)

			# Serial number and tag correctness
			self.assertEqual(coin_.s*coin_params.F + spend.r*coin_params.G,coin_.S)
			self.assertEqual(coin_.s*coin_.T + spend.r*coin_params.G,coin_params.U)

if __name__ == '__main__':
	unittest.main()
