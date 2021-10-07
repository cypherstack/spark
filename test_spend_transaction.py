import address
import coin
from dumb25519 import random_point
from random import randrange, sample
import spend_transaction
import unittest

def random_public_address():
	return address.PublicAddress(random_point(),random_point(),random_point())

class TestSpend(unittest.TestCase):
	def test_spend(self):
		n = 2
		m = 2
		value_bytes = 4
		memo_bytes = 16
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

		protocol_params = spend_transaction.ProtocolParameters(random_point(),random_point(),random_point(),random_point(),value_bytes,memo_bytes,n,m)
		address_params = address.AddressParameters(protocol_params.F,protocol_params.G,len(input_values))
		coin_params = coin.CoinParameters(protocol_params.F,protocol_params.G,protocol_params.H,protocol_params.U,protocol_params.value_bytes,protocol_params.memo_bytes)

		# Addresses
		spend = address.SpendKey(address_params)
		full = spend.full_view_key()
		incoming = spend.incoming_view_key()
		public = []
		for i in range(len(input_values)):
			public.append(spend.public_address(i))

		# Generate the input set and real coins
		inputs = []
		for _ in range(protocol_params.n**protocol_params.m):
			inputs.append(coin.Coin(coin_params,random_public_address(),randrange(0,2**(8*coin_params.value_bytes)),'Input memo',False,False))
		l = sample(range(len(inputs)),w)
		for u in range(w):
			inputs[l[u]] = coin.Coin(
				coin_params,
				public[u % len(public)],
				input_values[u],
				'Spend memo',
				False,
				False
			)
			inputs[l[u]].identify(coin_params,incoming)
			inputs[l[u]].recover(coin_params,full)
			inputs[l[u]].delegate(coin_params,full,delegation_id)

		# Generate the output coins and fee
		outputs = []
		for j in range(t):
			outputs.append(coin.Coin(
				coin_params,
				random_public_address(),
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