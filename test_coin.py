import address
import coin
from dumb25519 import random_point
from random import randrange
import unittest

class TestCoin(unittest.TestCase):
	def test_generate(self):
		value_bytes = 4
		memo_bytes = 16
		address_params = address.AddressParameters(random_point(),random_point())
		coin_params = coin.CoinParameters(address_params.F,address_params.G,random_point(),random_point(),value_bytes,memo_bytes)

		# Address
		spend = address.SpendKey(address_params)
		full = spend.full_view_key()
		incoming = spend.incoming_view_key()
		public = spend.public_address()

		# Coin data
		value = randrange(0,2**(8*coin_params.value_bytes))
		memo = 'Test memo'

		for is_mint in [True,False]:
			# Generate the coin
			coin_ = coin.Coin(coin_params,public,value,memo,is_mint,True)

			# Identify
			coin_.identify(coin_params,incoming)
			self.assertEqual(int(coin_.value),value)
			self.assertEqual(coin_.memo,memo)

			# Recover
			coin_.recover(coin_params,full)
			self.assertEqual(int(coin_.value),value)
			self.assertEqual(coin_.memo,memo)

			# Serial number and tag correctness
			self.assertEqual(coin_.s*coin_params.F + spend.r*coin_params.G,coin_.S)
			self.assertEqual(coin_.s*coin_.T + spend.r*coin_params.G,coin_params.U)
	
	def test_janus(self):
		value_bytes = 4
		memo_bytes = 16
		address_params = address.AddressParameters(random_point(),random_point(),1)
		coin_params = coin.CoinParameters(address_params.F,address_params.G,random_point(),random_point(),value_bytes,memo_bytes)

		# Addresses
		spend = address.SpendKey(address_params)
		full = spend.full_view_key()
		incoming = spend.incoming_view_key()
		public_0 = spend.public_address(0)
		public_1 = spend.public_address(1)

		# Coin data
		value = randrange(0,2**(8*coin_params.value_bytes))
		memo = 'Test memo'

		for is_mint in [True,False]:
			# Generate the coin to diversifier 0
			coin_ = coin.Coin(coin_params,public_0,value,memo,is_mint,True)

			# Manipulate the coin in an attempted Janus attack with diversifier 1
			coin_.S = coin_.S - public_0.Q2 + public_1.Q2

			# Identification should fail
			with self.assertRaises(ArithmeticError):
				coin_.identify(coin_params,incoming)

			# Recovery should fail
			with self.assertRaises(ArithmeticError):
				coin_.recover(coin_params,full)
			
			# Manipulate the recovery key instead
			coin_.K = coin_.k*public_1.Q0

			# Identification should fail
			with self.assertRaises(ArithmeticError):
				coin_.identify(coin_params,incoming)

			# Recovery should fail
			with self.assertRaises(ArithmeticError):
				coin_.recover(coin_params,full)

if __name__ == '__main__':
	unittest.main()
