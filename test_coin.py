import address
import coin
from dumb25519 import random_point
from random import randrange
import unittest

class TestCoin(unittest.TestCase):
	def test_generate(self):
		address_params = address.AddressParameters(random_point(),random_point())
		coin_params = coin.CoinParameters(address_params.G,address_params.F,random_point(),4)

		# Address
		spend,full,incoming,public = address.generate(address_params)

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
			self.assertEqual(coin_.s*coin_params.G + spend.r*coin_params.F,coin_.S)
			self.assertEqual(coin_.s*coin_.T,coin_params.H)

if __name__ == '__main__':
	unittest.main()
