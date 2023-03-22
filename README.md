# argon-crypto
Crypto module to en/decrypt data with an Argon2 key

Project: **_argon-crypto_**

### Contact:
You can reach out to us over...  
[E-Mail](mailto:admin@valkyteq.com?Subject=Github)   |    [Website](https://tera-europe.net/)   |    [Twitch](https://www.twitch.tv/valkyfischer)   |    [Discord](https://vteq.cc/discord/)
<br><br>



## About

The `argon-crypto` module includes two functions for encrypting and decrypting data using AES, and another function for generating a key using Argon2 key derivation function. The AES encryption function uses AES-GCM mode by default, but it can also work with AES-CTR and AES-CBC modes.

- The ``encrypt_data`` function takes a key, data, and mode arguments. key is a byte string of length 16, 24, or 32 bytes used to encrypt the data. data can be any kind of data to encrypt, and mode determines which AES mode to use. It returns a dictionary containing the ciphertext, authentication tag, and nonce in hexadecimal format.

- The ``decrypt_data`` function takes a key, data, and mode arguments. key is the decryption key used to decrypt the data. data is a dictionary containing the ciphertext, authentication tag, and nonce in hexadecimal format, and mode determines which AES mode to use. It returns the decrypted plaintext as a string.

- The ``generate_argon_key`` function takes a keyword and salt arguments, and it generates a key using the Argon2 key derivation function. It returns a byte string of the generated key.

## Usage

To use this encryption/decryption module in a communication between two servers, the following steps can be followed:  

  
- #### Generate a secure key: 
    A secure encryption key should be generated using a strong key derivation function such as Argon2. This key should be known only to the two servers and should be kept confidential.
    ```python
    import argoncrypto as ac
    
    key = ac.generate_argon_key(keyword, salt)
    ```
    <br>

- #### Decide on the encryption mode: 
    The two servers should decide on the encryption mode to be used, depending on their specific needs and constraints. 
    The available modes in this module are ``0 = AES-GCM, default``, ``1 = AES-CTR``, and ``2 = AES-CBC``.
    <br><br>

- #### Sender encrypts data: 
    The sender server should use the encrypt_data function to encrypt the data to be transmitted. The function takes the encryption key, data, and the chosen encryption mode as inputs and returns a dictionary containing the ciphertext, authentication tag, and nonce in hexadecimal format.
    ```python
    import argoncrypto as ac
    
    encrypted_data = ac.encrypt_data(decryption_key, encrypted_data, encryption_mode)
    ```
    <br>

- #### Transmit the encrypted data: 
    The sender should transmit the dictionary returned by the ``encrypt_data`` function to the recipient server using a secure communication channel.
    <br><br>

- #### Recipient decrypts the data: 
    The recipient server should use the ``decrypt_data`` function to decrypt the data. The function takes the decryption key and the dictionary containing the ciphertext, authentication tag, and nonce as inputs, along with the chosen encryption mode. The function returns the decrypted plaintext as a string or bytes.
    ```python
    import argoncrypto as ac
    
    decrypted_data = ac.decrypt_data(decryption_key, encrypted_data, encryption_mode)
    ```
    <br>

- #### Use the decrypted data: 
    The recipient server can then use the decrypted plaintext as required.
    <br><br>

## Example
It is important to note that both servers should have the same encryption key and use the same encryption mode to ensure successful decryption. Additionally, it is recommended to use secure communication channels such as SSL/TLS to transmit the encrypted data between the servers.
    
```python
import argoncrypto as ac

# Generate a secure key
key = ac.generate_argon_key(keyword, salt)

# Encrypt data
encrypted_data = ac.encrypt_data(key, data, 0)

# Transmit encrypted data
# ...

# Decrypt data
decrypted_data = ac.decrypt_data(key, encrypted_data, 0)
```
<br>

## Scenario: Server A <-> Server B

Server A encrypts data and sends it to Server B. Server B decrypts the data and uses it. To be able to decrypt 
the data, Server B needs to have the same encryption key as Server A. We encrypt the key using the same key 
to ensure that the key is not transmitted in plain text.  

- Server A: encrypting
    ```python
    import argoncrypto as ac

    # Generate the argon key
    argon_key = ac.generate_argon_key(ARGON_KEY, ARGON_SALT)

    # Encrypt the data
    data_to_send = {
        'argonized_key': ac.encrypt_data(argon_key, argon_key),
        'argonized_data': ac.encrypt_data(argon_key, json.dumps(data_to_encrypt).encode('utf-8'))
    }

    # Return the encrypted data
    return data_to_send
    ```
<br>

Server B receives the encrypted data from Server A and decrypts it. To be able to decrypt the data, Server B 
needs to have the same encryption key as Server A. We decrypt the key first, and then use it to decrypt the data.  

- Server B: decrypting
    ```python
    import argoncrypto as ac
    
    # Generate the argon key
    argon_key = ac.generate_argon_key(ARGON_KEY, ARGON_SALT)
    
    # Get the encrypted data
    argonized_key = client_data['argonized_key']
    argonized_data = client_data['argonized_data']
    
    # Decrypt the key and data
    decrypted_key = ac.decrypt_data(argon_key, argonized_key)
    decrypted_data = ac.decrypt_data(decrypted_key, argonized_data)
    
    # Return the decrypted data
    return decrypted_data
    ```
<br>

## Used libraries
- PyCryptodome
- Argon2
