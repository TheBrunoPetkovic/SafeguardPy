import ast
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
      hash = hash_data(random_code)
      authentication_part = str(hash) + "-" + random_code
      authentication_part = authentication_part.encode()
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
      # DEBUGat sve gori - NAPRAVIA
      # loopat kroz podatke i nac adresu koja je zadana
      # ako nije u baziu dodat novu adresu, aklo je onda prominit sifru za tu adresu
      # formatirat nove podatke
      # hashirat to 
      # pohranit u data.txt
      
      with open("data.txt", "r") as database:
         old_data = database.read()
         
      # Check integrity and master password from args
      #try:
         salt = old_data.split("\n")[0].split(": ")[1] # Dobar
         salt = ast.literal_eval(salt) # salt tribaju bit bajtovi zato je ode ova linija
         rest_of_data = old_data.split("\n")[1] # Dobar
         rest_of_data = ast.literal_eval(rest_of_data) # pritvori ih u bytes
         
         key = derive_key(master_password, salt) # oke
         decrypted_rest_of_data = decrypt_data(rest_of_data, key).decode() # kaze da je string

         only_hash_and_code = decrypted_rest_of_data.split(",", 1)[0]
         #print("decrypted_rest_of_data: " + decrypted_rest_of_data)
         all_data = ",".join(decrypted_rest_of_data.split("-", 1)[1:])
         #print(all_data)
         #print(only_hash_and_code)
         coded_part = only_hash_and_code.split("-")[1] # ovo je string 
         #print(coded_part)
         hashed_part = only_hash_and_code.split("-")[0]
         hashed_part = ast.literal_eval(hashed_part)
      
         if coded_part != "random_code_for_checking_master_password":
            print("Master password incorrect or integrity check failed.")
            sys.exit()
         else:
            print("sifra je dobra")
      
         # Checking integrity of stored data
         hash_of_coded_part = hash_data(all_data)
         print(all_data)
         if hash_of_coded_part != hashed_part:
            
            
            print("Master password incorrect or integrity check failed.")
            sys.exit()
         else:
            print("hash je isti ka i prije")
      
      #except Exception as e:
         #print(e)
         #print("Master password incorrect or integrity check failed.")
         #sys.exit()
      print(decrypted_rest_of_data)
      old_data = decrypted_rest_of_data.split(",", 1)[1:]
      print("old data: " + "".join(old_data))
      new_pair = f",{address}-{password}"
      old_data.append(new_pair)
      print("old data with new pair: " + "".join(old_data))
      old_data_as_string = "".join(old_data)
      
      if decrypted_rest_of_data != str(hash_of_coded_part) + "-random_code_for_checking_master_password":
         old_data_as_string = "," + old_data_as_string
      print("old_data_as_string: " + old_data_as_string)
      
      full_data = "random_code_for_checking_master_password" + old_data_as_string
      print("full data: " + "".join(full_data))
      hashed_full_data = hash_data(full_data)
      ready_to_store_data = str(hashed_full_data) + "-" + full_data
      ready_to_store_data = ready_to_store_data.encode()
      
      salt = get_random_bytes(32)
      key = derive_key(master_password, salt)
      encrypted_data = encrypt_data(ready_to_store_data, key)
      
      with open("data.txt", "w") as database:
         database.write(f"Salt: {salt}\n")
         database.write(f"{encrypted_data}")
         
      print(f"Stored password for {address}. ")
      sys.exit()
      

         
      

         
         
      
      
   
   
   
   
   
   # Derivate key      
   salt = get_random_bytes(32)
   key = derive_key(master_password, salt)
   poruka = f"{address}-{password}".encode()
   print(poruka)
   encrypted_data = encrypt_data(poruka, key)
   decrypted_data = decrypt_data(encrypted_data, key)
   print(decrypted_data)
  
   
if __name__ == "__main__":
   main()