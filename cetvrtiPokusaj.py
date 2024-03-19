from Crypto.Cipher import Salsa20
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import sys
import json

# Function for deriving key from MasterPassword and random Salt
def derive_key(password, salt):
   key = scrypt(password, salt, 32, N=2**14, r=8, p=1)
   return key


# Function for encrypting data based on Salsa20 and derived key
def encrypt_data(data, key):
   cipher = Salsa20.new(key=key)
   encrypted_data = cipher.nonce + cipher.encrypt(data.encode())
   return encrypted_data


# Function for decrypting data based on Salsa20 and derived key
def decrypt_data(data, key):
   msg_nonce = data[:8]
   encrypted_text = data[8:]
   cipher = Salsa20.new(key=key, nonce=msg_nonce)
   plaintext = cipher.decrypt(encrypted_text)
   return plaintext


# Function for hashing dictionary in order to preserve integrity
def hash_data(data):
   hashed_data = SHA256.new(data=data.encode())
   hashed_data = hashed_data.digest()
   return hashed_data


# Main
def main():
   # Parsing input arguments
   args = sys.argv[1:]
   operation = args[0]
   master_password = args[1]
   address = None
   password = None
   if len(args) >= 3:
      address = args[2]
      if len(args) == 4: 
         password = args[3]
         
   # Deriving key
   salt = get_random_bytes(32)
   key = derive_key(master_password, salt)
   data = {
      "validate_password":"random_code_for_checking_master_password"
   }
   new_pair = {address:password}
   data.update(new_pair)
   print(data)
   data_string = json.dumps(data)
   print(data_string)

   encrypted_data = encrypt_data(data_string, key)
   print(encrypted_data)
   decrypted_data = decrypt_data(encrypted_data, key)
   print(decrypted_data)


if __name__ == "__main__":
   main()