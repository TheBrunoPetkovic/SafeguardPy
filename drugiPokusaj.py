from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
import base64
import sys

# Function for derivating key from MasterPassword
def generate_key(master_password_args, salt):
   key = scrypt(master_password_args.encode("utf-8"), salt, key_len=32, N=2**14, r=8, p=1)
   return key

# Function for encrypting data using derived key and IV
def encrypt_data(data, key, iv):
   cipher = AES.new(key, AES.MODE_GCM, iv)
   encrypted_data = cipher.encrypt(data.encode())
   return encrypted_data

# Function for decrypting data using key and old IV
def decrypt_data(data, key, iv):
   cipher = AES.new(key, AES.MODE_GCM, iv)
   decrypted_data = cipher.decrypt(data)
   return decrypted_data.decode()

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
         
   if operation == "init":
      salt = get_random_bytes(16)
      iv = get_random_bytes(AES.block_size)
      key = generate_key(master_password_args, salt)
      
      with open("data.txt", "w") as database:
         database.write(f"IV: {iv}\n")
         database.write(f"Salt: {salt}\n")
      print("Password manager initialized. ")
         
   if operation == "put":
      if address_args is not None and password_args is not None:
         data = ""
         # Reading old database
         with open("data.txt", "r") as database:
            content = database.readlines()
            old_iv = content[0].split(": ")[1]
            old_iv = old_iv[2:]
            old_iv = old_iv[:-2]
            old_iv = old_iv.encode()
            old_salt = content[1].split(": ")[1]
            old_salt = old_salt[2:]
            old_salt = old_salt[:-2]
            old_salt = old_salt.encode()
            try:
               if content[2]:
                  old_data = content[2].encode()
                  key = generate_key(master_password_args, old_salt)
                  decrypted_data = decrypt_data(old_data, key, old_iv)
                  print(decrypted_data)
                  data += "".join(decrypted_data)
            except Exception as e:
               print(e)
               
         # Adding new pair to database
         new_salt = get_random_bytes(16)
         new_iv = get_random_bytes(AES.block_size)
         key = generate_key(master_password_args, new_salt)
         new_data = f" {address_args},{password_args}"
         data = data + new_data
         data = data.strip()
         encrypted_data = encrypt_data(data, key, new_iv)
         
         with open("data.txt", "wb") as database:
            database.write(f"IV: {new_iv}\n".encode())
            database.write(f"Salt: {new_salt}\n".encode())
            database.write(encrypted_data)
            
         print(f"Stored password for {address_args}")

   if operation == "get":
      if address_args is not None:
         pass

if __name__ == "__main__":
   main()
