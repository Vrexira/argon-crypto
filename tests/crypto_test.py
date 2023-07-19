import time
import json

from src import argoncrypto as ac


ARGON_KEY = "This is a super secret key no one will ever figure out!"
ARGON_SALT = "An even more secret salt!"


def simulate_client(data_to_encrypt: dict):
	# Generate the argon key
	argon_key = ac.generate_argon_key(ARGON_KEY, ARGON_SALT)
	
	# Encrypt the data
	data_to_send = {
		'argonized_key': ac.encrypt_data(argon_key, argon_key),
		'argonized_data': ac.encrypt_data(argon_key, json.dumps(data_to_encrypt).encode('utf-8'))
	}
	
	# Return the encrypted data
	return data_to_send


def simulate_server(client_data: dict):
	# Generate the argon key
	argon_key = ac.generate_argon_key(ARGON_KEY, ARGON_SALT)
	argonized_key = client_data['argonized_key']
	argonized_data = client_data['argonized_data']
	
	# Decrypt the key and data
	decrypted_key = ac.decrypt_data(argon_key, argonized_key)
	decrypted_data = ac.decrypt_data(decrypted_key, argonized_data)
	
	# Return the decrypted data
	return decrypted_data


def run(runs: int = 1):
	# Sample data
	data_sample = {'name': 'John Doe', 'age': 25, 'email': 'johndoe@example.com'}
	
	for i in range(runs):
		# Simulate encryption
		if runs == 1:
			print("Simulating encryption...")
		client_data_encrypt = simulate_client(data_sample)
		if runs == 1:
			print(f"Encryption time: {round(time.time() - start, 3)}sec")
		
		# Simulate decryption
		if runs == 1:
			print("Simulating decryption...")
		client_data_decrypt = simulate_server(client_data_encrypt)
		if runs == 1:
			print(f"Decryption time: {round(time.time() - start, 3)}sec")
		
		# Print the results if first run
		if runs == i + 1:
			print(f"Data: {client_data_encrypt}")
			print(f"Data: {client_data_decrypt}")
		
		print(f"Run {i + 1}: {round(time.time() - start, 3)}sec")


if __name__ == "__main__":
	# start
	print("Starting...")
	start = time.time()
	run(100)
	print(f"Total time: {round(time.time() - start, 3)}sec")
