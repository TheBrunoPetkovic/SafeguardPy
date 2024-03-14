import sys

# Getting the arguments
args = sys.argv[1:]

# Function that handles new initialisation
def init():
   pass

# Function that handles new pair of data - adress and password
def new_data():
   pass

# Function that handles request for stored data - password
def get_data():
   pass

# args[0] - Name of operation
operation = args[0]
# args[1] - Master Password
master_password_args = args[1]
# args[2] - If exists - Adress
if len(args) >= 3:
   adress = args[2]
   # args[3] - If exists - Password
   if len(args) == 4: 
      password_args = args[3]

def main():
   
   if args[0] == "init":
      init()

   if args[0] == "put":
      pass

   if args[0] == "get":
      pass

if __name__ == "__main__":
   main()