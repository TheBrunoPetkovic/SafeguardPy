import sys

def check_master_password(master_password_args):
   return True

def init(master_password_args, args):
   if check_master_password(master_password_args):
      if len(args) != 2:
         print("Incorrect number of arguments for operation - init.")
         return
      print("Password manager initialized.")
      with open("data.txt", "w") as file:
         file.truncate(0)
   
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

def get_data(master_password_args, address_args, args):
   if check_master_password(master_password_args):
      if len(args) != 3:
         print("Incorrect number of arguments for operation - get.")
         return
      password_from_data = None
      with open("data.txt", "r") as data:
         lines = data.read()
         for line in lines:
            couple = line.split(" ")
            if couple[0] == address_args:
               password_from_data = couple[1]
      if
      print(f"Password for {address_args} is: {password_from_data}")

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
      init(master_password_args, args)

   if operation == "put":
      if address_args is not None and password_args is not None:
         new_data(master_password_args, address_args, password_args, args)

   if operation == "get":
      if address_args is not None:
         get_data(master_password_args, address_args, args)

if __name__ == "__main__":
   main()
   