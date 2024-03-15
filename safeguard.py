import sys

def init(master_password_args):
   print("Operacija - init")

def new_data(master_password_args, adress_args, password_args):
   print("Operacija - new data")

def get_data(master_password_args, adress_args):
   print("Operacija - get data")

def main():
   args = sys.argv[1:]

   operation = args[0]
   master_password_args = args[1]
   if len(args) >= 3:
      adress_args = args[2]
      if len(args) == 4: 
         password_args = args[3]
   
   if operation == "init":
      init(master_password_args)

   if operation == "put":
      new_data(master_password_args, adress_args, password_args)

   if operation == "get":
      get_data(master_password_args, adress_args)

if __name__ == "__main__":
   main()

# DODAT UVJETE DA AKO JE NPR INIT DA MOZE BIT MAX 2 ARGUMENTA