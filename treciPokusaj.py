from Crypto.Cipher import Salsa20
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import sys

def derive_key(password, salt):
   key = scrypt(password, salt, 32, N=2**14, r=8, p=1)
   return key


def encrypt_data(data, key):
   cipher = Salsa20.new(key=key)
   encrypted_data = cipher.nonce + cipher.encrypt(data)
   return encrypted_data


def decrypt_data(data, key):
   msg_nonce = data[:8]
   encrypted_text = data[8:]
   cipher = Salsa20.new(key=key, nonce=msg_nonce)
   plaintext = cipher.decrypt(encrypted_text)
   return plaintext


def hash_data(data):
   hashed_data = SHA256.new(data=data.encode())
   hashed_data = hashed_data.digest()
   return hashed_data

   
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
      salt = get_random_bytes(32)
      key = derive_key(master_password, salt)
       
      random_code = "random_code_for_checking_master_password"
      hash = hash_data("-" + random_code)
      authentication_part = f"{hash}-{random_code}".encode()
      encrypted_data = encrypt_data(authentication_part, key)
      
      with open("data.txt", "w") as database:
         database.write(f"Salt: {salt}\n")
         database.write(f"{encrypted_data}")
         
      print("Password manager initialized. ")
      sys.exit()
   
   if operation == "put":
      # otvorit data.txt - NAPRAVIA
      # uzet salt - NAPRAVIA 
      # desifrirat donji dio podataka - NAPRAVIA
      # izracunat hash od - pa nadalje - NAPRAVIA
      # gledat jeli isti ka hash iz datoteke - NAPRAVIA
      # ako je onda super, ako nije onda ispisi error - NAPRAVIA
      # provjerit masterPass kod - NAPRAVIA
      # ako je minjan ispisat error ako nije super - NAPRAVIA
      # loopat kroz podatke i nac adresu koja je zadana
      # ako nije u baziu dodat novu adresu, aklo je onda prominit sifru za tu adresu
      # formatirat nove podatke
      # hashirat to 
      # pohranit u data.txt
      
      with open("data.txt", "r") as database:
         old_data = database.read()
         
         # Check integrity and master password from args
         salt = old_data[0].split(": ")
         rest_of_data =  old_data[1]
         key = derive_key(master_password, salt)
         decrypted_rest_of_data = decrypt_data(rest_of_data, key)
         only_hash_and_code = decrypted_rest_of_data.split(",")[0]
         coded_part = only_hash_and_code.split("-")[0]
         hashed_part = only_hash_and_code.split("-")[1]
         
         if coded_part != "random_code_for_checking_master_password":
            print("Master password incorrect or integrity check failed.")
            sys.exit()
         
         content = decrypted_rest_of_data.replace(hashed_part, "")
         hash_for_checking_integrity = hash_data(content)
         if hash_for_checking_integrity != hashed_part:
            print("Master password incorrect or integrity check failed.")
            sys.exit()
         
         
         
         
      
      
   
   
   
   
   
   # Derivate key      
   salt = get_random_bytes(32)
   key = derive_key(master_password, salt)
   
   poruka = f"{address}-{password}".encode()
   print(poruka)
   encrypted_data = encrypt_data(poruka, key)
   print(encrypted_data)
   decrypted_data = decrypt_data(encrypted_data, key)
   print(decrypted_data)
  
   
if __name__ == "__main__":
   main()