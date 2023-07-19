import argon2
from Cryptodome.Cipher import AES


MODES = {
	0: "AES-GCM",
	1: "AES-CTR",
	2: "AES-CBC"
}


def encrypt_data(key: bytes, data: any, mode: int = 0) -> dict:
	"""Encrypts data using AES-GCM

    ---------------

    The encrypt_data function takes two arguments: 'key' and 'data'. The key argument is the encryption key used
    to encrypt the data argument.

    The function creates a new instance of the AES cipher in Galois/Counter Mode (GCM) using the key argument.
    It then encrypts the data argument using the cipher's encrypt_and_digest method. The resulting ciphertext
    is stored in ct_bytes, and the authentication tag is stored in tag.

    The function generates a nonce (number used once) using the cipher's nonce method and stores it in iv.
    The nonce is a random value that is used only once during encryption to ensure that the same plaintext
    encrypted multiple times does not result in the same ciphertext.

    The function then returns a dictionary containing the ciphertext, authentication tag, and nonce in hexadecimal
    format. These values are represented as strings using the hex() method, so they can be easily serialized and
    transmitted over a network.

    :param key: a byte string of length 16, 24, or 32 bytes
    :param data: any kind of data to encrypt
    :param mode: Default 0 for AES-GCM, 1 for AES-CTR, 2 for AES-CBC
    :return dict: dictionary containing the ciphertext, authentication tag, and nonce in hexadecimal format
    """
	if mode == 0:
		cipher = AES.new(key, AES.MODE_GCM)
		ct_bytes, tag = cipher.encrypt_and_digest(data)
		iv = cipher.nonce
		return {
			"ciphertext": ct_bytes.hex(),
			"tag": tag.hex(),
			"iv": iv.hex()
		}
	elif mode == 1:
		cipher = AES.new(key, AES.MODE_CTR)
		ct_bytes = cipher.encrypt(data)
		iv = cipher.nonce
		return {
			"ciphertext": ct_bytes.hex(),
			"iv": iv.hex()
		}
	elif mode == 2:
		cipher = AES.new(key, AES.MODE_CBC)
		ct_bytes = cipher.encrypt(data)
		iv = cipher.iv
		return {
			"ciphertext": ct_bytes.hex(),
			"iv": iv.hex()
		}
	else:
		raise ValueError("Invalid mode")


def decrypt_data(key: bytes, data: dict, mode: int = 0) -> str | bytes:
	"""Decrypts data using AES-GCM

    ---------------

    The decrypt_data function takes two arguments: 'key' and 'data'. The key argument is the decryption
    key used to decrypt the data argument.

    The function first extracts the ciphertext, authentication tag, and nonce from the data argument,
    which is expected to be a dictionary containing these values in hexadecimal format.

    Next, the function creates a new instance of the AES cipher in GCM mode using the key argument and the
    nonce extracted from the data argument.

    The function then calls the cipher's decrypt_and_verify method, passing the ciphertext and authentication
    tag as arguments. If the authentication tag is invalid, indicating that the ciphertext has been tampered
    with, the method will raise a ValueError exception.

    If the authentication tag is valid, the method will return the decrypted plaintext, which is then decoded
    from bytes to a string using the decode method with the utf-8 encoding.

    The function returns the decrypted plaintext as a string.

    :param key: a byte string of length 16, 24, or 32 bytes used to decrypt the data
    :param data: dictionary containing the ciphertext, authentication tag, and nonce in hexadecimal format
    :param mode: Default 0 for AES-GCM, 1 for AES-CTR, 2 for AES-CBC
    :return str | bytes: decrypted plaintext as a string
    """
	if mode == 0:
		iv = bytes.fromhex(data['iv'])
		ct = bytes.fromhex(data['ciphertext'])
		tag = bytes.fromhex(data['tag'])
		cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
		pt_bytes = cipher.decrypt_and_verify(ct, tag)
		try:
			return pt_bytes.decode('utf-8')
		except UnicodeDecodeError:
			return pt_bytes
	elif mode == 1:
		iv = bytes.fromhex(data['iv'])
		ct = bytes.fromhex(data['ciphertext'])
		cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
		pt_bytes = cipher.decrypt(ct)
		try:
			return pt_bytes.decode('utf-8')
		except UnicodeDecodeError:
			return pt_bytes
	elif mode == 2:
		iv = bytes.fromhex(data['iv'])
		ct = bytes.fromhex(data['ciphertext'])
		cipher = AES.new(key, AES.MODE_CBC, iv=iv)
		pt_bytes = cipher.decrypt(ct)
		try:
			return pt_bytes.decode('utf-8')
		except UnicodeDecodeError:
			return pt_bytes
	else:
		raise ValueError("Invalid mode")


def generate_argon_key(secret: str, salt: str, key_length: int = 32, time_cost: int = 2, memory_cost: int = 100, parallelism: int = 8) -> bytes:
	"""
	Generates a key using Argon2
	
	-----------------
	
	The generate_argon_key function uses the Argon2 key derivation function to generate a key.
	
	Argon2 is a memory-hard function that is designed to be resistant to GPU cracking attacks, what can be used
	to derive cryptographic keys.
	
	The function first sets up the parameters for the Argon2 function:
	
	- secret: The secret value to use as input to the key derivation function.
	- salt: A random value used to add additional randomness to the key.
	- key_length: The length of the derived key, in bytes.
	- time_cost: The amount of time to spend on each iteration of the key derivation function. Increasing this value makes it more difficult to brute-force the derived key.
	- memory_cost: The amount of memory to use during the key derivation function. Increasing this value also makes it more difficult to brute-force the derived key.
	- parallelism: The number of parallel threads to use during the key derivation function.
	
	The function calls the argon2.low_level.hash_secret_raw method to generate the key using the provided
	parameters.
	
	This method returns a byte string containing the derived key.
	
	:param secret: The secret value to use as input to the key derivation function.
	:param salt: A random value used to add additional randomness to the key.
	:param key_length: The length of the derived key, in bytes.
	:param time_cost: The amount of time to spend on each iteration of the key derivation function.
	:param memory_cost: The amount of memory to use during the key derivation function.
	:param parallelism: The number of parallel threads to use during the key derivation function.
	:return bytes:
	"""
	
	# Use Argon2 to derive the key
	key = argon2.low_level.hash_secret_raw(
		secret=secret.encode('utf-8'),
		salt=salt.encode('utf-8'),
		time_cost=time_cost,
		memory_cost=memory_cost * 100,
		parallelism=parallelism,
		hash_len=key_length,
		type=argon2.low_level.Type.ID
	)
	
	return key
