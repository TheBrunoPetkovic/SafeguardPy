import ast
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


# Function for verifying password
def verify_password():
   pass


# Function for checking integrity
def check_integrity():
   pass


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
   
   # Functionality based on chosen operation  
   if operation == "init":
      # Encrypt data
      salt = get_random_bytes(32)
      key = derive_key(master_password, salt)
      data = {
         "validate_password":"random_code_for_checking_master_password"
      }
      data_string = json.dumps(data)
      hash = hash_data(data_string)
      encrypted_data = encrypt_data(data_string, key) # Bytes

      # Write data in database - initialising
      with open("data.txt", "wb") as database:
         database.write(b"Salt: " + salt + b"\n")
         database.write(b"Hash: " + hash + b"\n")
         database.write(encrypted_data)

      print("Password manager initialized. ")
      sys.exit()
   
   if operation == "put":
      with open("data.txt", "rb") as database:
         # Process data.txt
         lines = database.readlines()
         salt = lines[0].strip()[6:]
         #salt = ast.literal_eval(salt) # Salt is now type - Bytes
         hash = lines[1].strip()[6:]
         #hash = ast.literal_eval(hash) # Hash is now type - Bytes
         data = lines[2]
         
         # Decrypt data and get dictionary
         try:
            key = derive_key(master_password, salt)
            decrypted_data = decrypt_data(data, key).decode() # Works
            data = ast.literal_eval(decrypted_data) # Data is now type - Dictionary
         except Exception as e:
            print("Master password incorrect or integrity check failed.")
            sys.exit()

         # Validate Master Pasword
         if data["validate_password"] != "random_code_for_checking_master_password":
            print("Master password incorrect or integrity check failed.")
            sys.exit()
         else:
            print("Sifra je dobra")
            
         # Create new hash
         try:
            data_string = json.dumps(data)
            new_hash = hash_data(data_string)
         except Exception as e:
            print("Master password incorrect or integrity check failed.")
            sys.exit()
         
         # Check integrity by comparing new hash and old hash
         if new_hash != hash:
            print("Master password incorrect or integrity check failed.")
            sys.exit()
         else:
            print("Hash je dobar")
         
         # Overwrite address - password pair in database if already exists
         data[address] = password
         
         # Create new hash encrypt data
         salt = get_random_bytes(32)
         key = derive_key(master_password, salt)
         data_string = json.dumps(data)
         new_hash = hash_data(data_string)
         encrypted_data = encrypt_data(data_string, key) # Bytes
         
         # Store it all in data.txt
         with open("data.txt", "wb") as database:
            database.write(b"Salt: " + salt + b"\n")
            database.write(b"Hash: " + hash + b"\n")
            database.write(encrypted_data)
         
         print(f"Stored password for {address}. ")
         sys.exit()
         
   if operation == "get":
      with open("data.txt", "rb") as database:
         # Process data.txt
         lines = database.readlines()
         salt = lines[0].strip()[6:]
         #salt = ast.literal_eval(salt) # Salt is now type - Bytes
         hash = lines[1].strip()[6:]
         #hash = ast.literal_eval(hash) # Hash is now type - Bytes
         data = lines[2]
         
         # Decrypt data and get dictionary
         try:
            key = derive_key(master_password, salt)
            decrypted_data = decrypt_data(data, key).decode() # Works
            data = ast.literal_eval(decrypted_data) # Data is now type - Dictionary
         except Exception as e:
            print("Master password incorrect or integrity check failed.")
            sys.exit()

         # Validate Master Pasword
         if data["validate_password"] != "random_code_for_checking_master_password":
            print("Master password incorrect or integrity check failed.")
            sys.exit()
         else:
            print("Sifra je dobra")
            
         # Create new hash
         try:
            print(data)
            data_string = json.dumps(data)
            print(data_string)
            new_hash = hash_data(data_string)
            print(new_hash)
         except Exception as e:
            print("Master password incorrect or integrity check failed.")
            sys.exit()
         
         # Check integrity by comparing new hash and old hash
         print(new_hash)
         print(hash)
         if new_hash != hash:
            print("Master password incorrect or integrity check failed.")
            sys.exit()
         else:
            print("Hash je dobar")
            
         password = data[address]
         print(f"Password for {address} is: {password}.")
         sys.exit()


if __name__ == "__main__":
   main()