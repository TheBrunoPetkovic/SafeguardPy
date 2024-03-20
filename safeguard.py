from Crypto.Cipher import Salsa20
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import sys
import json
import base64


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


# Function for validating provided password
def validate_password(data):
   if data["validate_password"] == "random_code_for_checking_master_password":
      return True
   else:
      print("Master password incorrect or integrity check failed. ")
      sys.exit()

# Function for checking integrity of database
def check_integrity(data, hash):
   # Check integrity by comparing hash from data and new hash
   data_string = json.dumps(data) # Type - String
   new_hash = hash_data(data_string) # Type - Bytes
   if new_hash == hash:
      return True
   else:
      print("Master password incorrect or integrity check failed. ")
      sys.exit()   


# Function for reading database, validating password and checking integrity
def read_database(master_password):
   with open("data.txt", "r") as database:
      lines = database.readlines()
   # Process data.txt
   salt_b64 = lines[0].split(": ")[1].strip()
   hash_b64 = lines[1].split(": ")[1].strip()
   encrypted_data_b64 = lines[2].split(": ")[1].strip()
   
   try:
      # Decode form Base64
      salt = base64.b64decode(salt_b64) # Type - Bytes
      hash = base64.b64decode(hash_b64) # Type - Bytes
      encrypted_data = base64.b64decode(encrypted_data_b64) # Type - Bytes
      
      # Decrypt data using derived key and validate safety requests
      key = derive_key(master_password, salt) # Type - Bytes
      decrypted_data = decrypt_data(encrypted_data, key) # Type - Bytes
      data = decrypted_data.decode() # Type - String
      data = json.loads(data) # Type - Dict
      validate_password(data)
      check_integrity(data, hash)
   except Exception as e:
      print("Master password incorrect or integrity check failed. ")
      sys.exit()
      
   return data


# Function for encoding data and storing it in database
def store_data(data, master_password):
   salt = get_random_bytes(32) # Type - Bytes
   key = derive_key(master_password, salt) # Type - Bytes
   data_string = json.dumps(data) # Type - String
   hash = hash_data(data_string) # Type - Bytes
   encrypted_data = encrypt_data(data_string, key) # Type - Bytes
      
   # Encode binary data into Base64
   salt_b64 = base64.b64encode(salt).decode('utf-8')
   hash_b64 = base64.b64encode(hash).decode('utf-8')
   encrypted_data_b64 = base64.b64encode(encrypted_data).decode('utf-8')
      
   # Write data in database - initialising
   with open("data.txt", "w") as database:
      database.write(f"Salt: {salt_b64}\n")
      database.write(f"Hash: {hash_b64}\n")
      database.write(f"Data: {encrypted_data_b64}\n")
   return True

   
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
      data = {
         "validate_password":"random_code_for_checking_master_password"
      } # Type - Dict
      
      # Store data
      store_data(data, master_password)
      print("Password manager initialized. ")
      sys.exit()
      
   if operation == "put":
      data = read_database(master_password)
      # Update data by inserting new pair address:password
      data[address] = password
      
      store_data(data, master_password)
      print(f"Stored password for {address}. ")
      sys.exit()
      
   if operation == "get":
      data = read_database(master_password) # Type - Dict
      password = data[address]
      print(f"Password for {address} is: {password}.")

         
if __name__ == "__main__":
   main()