import sys
import email, email.header
from email.utils import getaddresses

f = open("../samples/exo_validator.eml", "r")
email = email.message_from_file(f)
from_hdr = email.get_all("From")
print("from_hdr: " + str(from_hdr))
if(len(from_hdr) > 1):
  print("Multiple From-headers found!")
  sys.exit(1)
elif(len(from_hdr) == 1):
  print("Exactly one From-header found :)")
  print(from_hdr)
  from_addr = getaddresses(from_hdr)
  print(str(from_addr[0][1]))
