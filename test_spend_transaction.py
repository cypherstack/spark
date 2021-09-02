import address
import coin
from dumb25519 import random_point
from random import randrange, sample
import spend_transaction
import unittest

class TestSpend(unittest.TestCase):
	def test_spend(self):
		n = 2
		m = 2
		N = 4
		input_values = [1,2,3]
		output_values = [2,3]
		fee = sum(input_values) - sum(output_values)
		w = len(input_values)
		t = len(output_values)
		delegation_id = 1

		self.assertGreater(n,1)
		self.assertGreater(m,1)
		self.assertGreaterEqual(n**m,w)
		self.assertGreaterEqual(t,1)

		protocol_params = spend_transaction.ProtocolParameters(random_point(),random_point(),random_point(),N,n,m)
		address_params = address.AddressParameters(protocol_params.G,protocol_params.F)
		coin_params = coin.CoinParameters(protocol_params.G,protocol_params.F,protocol_params.H,protocol_params.N)

		# Address
		spend,full,_,delegation,public = address.generate(address_params)

		# Generate the input set and real coins
		inputs = []
		for _ in range(protocol_params.n**protocol_params.m):
			inputs.append(coin.Coin(coin_params,public,randrange(0,2**coin_params.N),'Input memo',False,False))
		l = sample(range(len(inputs)),w)
		for u in range(w):
			inputs[l[u]] = coin.Coin(
				coin_params,
				public,
				input_values[u],
				'Spend memo',
				False,
				False
			)
			inputs[l[u]].recover(coin_params,public,full)
			inputs[l[u]].delegate(coin_params,full,delegation,delegation_id)

		# Generate the output coins and fee
		outputs = []
		for j in range(t):
			# Range is restricted to make balance easier for this example
			outputs.append(coin.Coin(
				coin_params,
				public,
				output_values[j],
				'Output memo',
				False,
				True
			))

		# Generate the spend transaction
		transaction = spend_transaction.SpendTransaction(
			protocol_params,
			full,
			spend,
			inputs,
			l,
			fee,
			outputs
		)

		# Verify it
		transaction.verify(
			protocol_params
		)

if __name__ == '__main__':
	unittest.main()