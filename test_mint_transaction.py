import address
from dumb25519 import random_point
from random import randrange
import mint_transaction
import unittest

class TestMint(unittest.TestCase):
	def test_mint(self):
		protocol_params = mint_transaction.ProtocolParameters(random_point(),random_point(),random_point(),random_point(),4,32)
		address_params = address.AddressParameters(protocol_params.F,protocol_params.G)

		# Mint data
		public = address.SpendKey(address_params).public_address()
		value = randrange(0,2**(8*protocol_params.value_bytes))
		memo = 'Mint memo'

		# Generate the spend transaction
		transaction = mint_transaction.MintTransaction(
			protocol_params,
			public,
			value,
			memo
		)

		# Verify it
		transaction.verify(
			protocol_params
		)

if __name__ == '__main__':
	unittest.main()