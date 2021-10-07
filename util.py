# Utility functions

from chacha20poly1305 import ChaCha20Poly1305, TagInvalidException
from hashlib import blake2s

def aead_encrypt(prekey,header,plaintext):
	key = blake2s(repr(prekey).encode('utf-8')).digest()
	nonce = bytearray(12)
	cipher = ChaCha20Poly1305(key)
	return cipher.encrypt(nonce,plaintext,header.encode('utf-8'))

def aead_decrypt(prekey,header,ciphertext):
	key = blake2s(repr(prekey).encode('utf-8')).digest()
	nonce = bytearray(12)
	cipher = ChaCha20Poly1305(key)
	plaintext = cipher.decrypt(nonce,ciphertext,header.encode('utf-8'))
	if plaintext is not None:
		return plaintext
