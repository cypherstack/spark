from chacha20poly1305 import TagInvalidException
import unittest
import util

class TestAEAD(unittest.TestCase):
	def test_encrypt_decrypt(self):
		ciphertext = util.aead_encrypt_utf8('key','header','plaintext')
		plaintext = util.aead_decrypt_utf8('key','header',ciphertext)
		self.assertEqual(plaintext,'plaintext')

		with self.assertRaises(TagInvalidException):
			util.aead_decrypt_utf8('evil_key','header',ciphertext)
		with self.assertRaises(TagInvalidException):
			util.aead_decrypt_utf8('key','evil header',ciphertext)
		with self.assertRaises(TagInvalidException):
			evil_ciphertext = ciphertext[:-1]
			util.aead_decrypt_utf8('evil_key','header',evil_ciphertext)
		with self.assertRaises(TagInvalidException):
			evil_ciphertext = ciphertext[1:]
			util.aead_decrypt_utf8('evil_key','header',evil_ciphertext)

if __name__ == '__main__':
	unittest.main()
