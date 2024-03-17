from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
import base64
import sys

# Function for checking if entered password is the defined MasterPassword
def check_master_password(master_password_args, data):
   key = generate_key(master_password_args)
   decrypted_data = decrypt_data(key, data)
   if decrypted_data[0] == "hardkodirano sifrom":
      return True
   else:
      return False

# Function for generating/derivating key from master password
def generate_key(master_password_args):
   salt = get_random_bytes(16)
   key = scrypt(master_password_args, salt, key_len=32, N=2**14, r=8, p=1)
   return key

# Function for encrypting data using the provided key
def encrypt_data(key, data):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext)
 
# Function for decrypting data using the provided key
def decrypt_data(key, encrypted_data):
    raw_data = base64.b64decode(encrypted_data)
    nonce = raw_data[:16]
    tag = raw_data[16:32]
    ciphertext = raw_data[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# Function for initialising the database
def init(master_password_args, args):
   if check_master_password(master_password_args):
      if len(args) != 2:
         print("Incorrect number of arguments for operation - init.")
         return
      print("Password manager initialized.")
      with open("data.txt", "w") as file:
         data = "hardkodirano sifrom"
         key = generate_key(master_password_args)
         encrypted_data = encrypt_data(key, data)
         file.write(encrypted_data)

# Function for adding new pair of address and password to database
def new_data(master_password_args, address_args, password_args, args):
   if check_master_password(master_password_args):
      if len(args) != 4:
         print("Incorrect number of arguments for operation - put.")
         return
      with open("data.txt", "r+") as data:
         lines = data.readlines()
         data.seek(0)
         address_exists = False
         for line in lines:
            if not line.strip():
               continue
            couple = line.split()
            if couple[0] == address_args:
               data.write(f"{address_args} {password_args}\n")
               address_exists = True
            else:
               data.write(line)
         if not address_exists:
            data.write(f"{address_args} {password_args}\n")
      print(f"Stored password for {address_args}.")

# Function for fetching password with address from database
def get_data(master_password_args, address_args, args):
   if check_master_password(master_password_args):
      if len(args) != 3:
         print("Incorrect number of arguments for operation - get.")
         return
      password_from_data = None
      with open("data.txt", "r") as data:
         lines = data.readlines()
         for line in lines:
            couple = line.split(" ")
            if couple[0] == address_args:
               password_from_data = couple[1]
               password_from_data = password_from_data[:-1]
      if password_from_data == None:
         print(f"There is no password associated with address: {address_args}")
      else: 
         print(f"Password for www.fer.hr is: {password_from_data}")

# Main
def main():
   args = sys.argv[1:]

   operation = args[0]
   master_password_args = args[1]
   address_args = None
   password_args = None
   if len(args) >= 3:
      address_args = args[2]
      if len(args) == 4: 
         password_args = args[3]
         
   with open("data.txt", "r") as data:
      content = data.readlines()
   
   if check_master_password(master_password_args, content) == False:
      print("Master password incorrect or integrity check failed.")
      sys.exit()
         
   
   if operation == "init":
      init(master_password_args, args)

   if operation == "put":
      if address_args is not None and password_args is not None:
         new_data(master_password_args, address_args, password_args, args)

   if operation == "get":
      if address_args is not None:
         get_data(master_password_args, address_args, args)

if __name__ == "__main__":
   main()
   