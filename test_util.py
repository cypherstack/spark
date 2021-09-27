from chacha20poly1305 import TagInvalidException
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

if __name__ == '__main__':
	unittest.main()
