from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography import exceptions
import binascii
import sys
private_key = ec.generate_private_key(ec.SECP384R1())
data = b"test"
if (len(sys.argv)>2):
	type=int(sys.argv[2])
if (len(sys.argv)>1):
	data=str(sys.argv[1]).encode()
if (type==1): private_key = ec.generate_private_key(ec.SECP192R1())
elif (type==2): private_key = ec.generate_private_key(ec.SECP224R1())
elif (type==3): private_key = ec.generate_private_key(ec.SECP256K1())
elif (type==4): private_key = ec.generate_private_key(ec.SECP256R1())
elif (type==5): private_key = ec.generate_private_key(ec.SECP384R1())
elif (type==6): private_key = ec.generate_private_key(ec.SECP521R1())
elif (type==7): private_key = ec.generate_private_key(ec.BrainpoolP256R1())
elif (type==8): private_key = ec.generate_private_key(ec.BrainpoolP384R1())
elif (type==9): private_key = ec.generate_private_key(ec.BrainpoolP512R1())
elif (type==10): private_key = ec.generate_private_key(ec.SECT163K1())
elif (type==11): private_key = ec.generate_private_key(ec.SECT163R2())
elif (type==12): private_key = ec.generate_private_key(ec.SECT233K1())
elif (type==13): private_key = ec.generate_private_key(ec.SECT233R1())
elif (type==14): private_key = ec.generate_private_key(ec.SECT283K1())
elif (type==15): private_key = ec.generate_private_key(ec.SECT233R1())
private_vals = private_key.private_numbers()
no_bits=private_vals.private_value.bit_length()
print (f"Private key value: {private_vals.private_value}. Number of bits {no_bits}")
public_key = private_key.public_key()
pub=public_key.public_numbers()
print ("Name of curve: ",pub.curve.name)
print ("Message: ",data.decode())
try:
  signature = private_key.sign(data,ec.ECDSA(hashes.SHA256()))
  print ("Good Signature: ",binascii.b2a_hex(signature).decode())
  public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
except exceptions.InvalidSignature:
  print("A bad signature failed")
else:
  print("Good signature verified")
try:
  signature = private_key.sign(b"bad message",ec.ECDSA(hashes.SHA256()))
  print ("Bad Signature: ",binascii.b2a_hex(signature).decode())
  public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
except exceptions.InvalidSignature:
  print("A bad signature failed")
else:
  print("Good signature verified")
pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption())
der = private_key.private_bytes(encoding=serialization.Encoding.DER,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption())
print ("\nPrivate key (PEM):\n",pem.decode())
print ("Private key (DER):\n",binascii.b2a_hex(der))
pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
der = public_key.public_bytes(encoding=serialization.Encoding.DER,format=serialization.PublicFormat.SubjectPublicKeyInfo)
print ("\nPublic key (PEM):\n",pem.decode())
print ("Public key (DER):\n",binascii.b2a_hex(der))