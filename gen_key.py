from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
# This will generate a new Fernet key and print it to the console.
# You can use this key to encrypt and decrypt data.