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
   encrypted_data = cipher.encrypt(data.encode('utf-8'))
   return encrypted_data

# Function for decrypting data using key and old IV
def decrypt_data(data, key, iv):
   cipher = AES.new(key, AES.MODE_GCM, iv)
   decrypted = cipher.decrypt(data)
   return decrypted

def main():
   master_password_args = input("upisi sifru: ")
   salt = get_random_bytes(16)
   iv = get_random_bytes(AES.block_size)
   key = generate_key(master_password_args, salt)
   data = "adresa1,sifra1 adresa2,sifra2"
   kriptirano = encrypt_data(data, key, iv)
   print(kriptirano)
   dekriptirano = decrypt_data(kriptirano, key, iv)
   print(dekriptirano)

if __name__ == "__main__":
   main()