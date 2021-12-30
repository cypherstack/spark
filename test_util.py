from chacha20poly1305 import TagInvalidException
from dumb25519 import random_scalar
import unittest
import util

class TestAEAD(unittest.TestCase):
	def test_encrypt_decrypt(self):
		ciphertext = util.aead_encrypt('key','header','plaintext'.encode('utf-8'))
		plaintext_bytes = util.aead_decrypt('key','header',ciphertext)
		if plaintext_bytes is not None:
			plaintext = plaintext_bytes.decode('utf-8')
			self.assertEqual(plaintext,'plaintext')
		else:
			raise ArithmeticError('Bad decryption!')

		with self.assertRaises(TagInvalidException):
			util.aead_decrypt('evil_key','header',ciphertext)
		with self.assertRaises(TagInvalidException):
			util.aead_decrypt('key','evil header',ciphertext)
		with self.assertRaises(TagInvalidException):
			evil_ciphertext = ciphertext[:-1]
			util.aead_decrypt('evil_key','header',evil_ciphertext)
		with self.assertRaises(TagInvalidException):
			evil_ciphertext = ciphertext[1:]
			util.aead_decrypt('evil_key','header',evil_ciphertext)

class TestViewTag(unittest.TestCase):
	def test_view_tag(self):
		util.view_tag(random_scalar())

if __name__ == '__main__':
	unittest.main()
