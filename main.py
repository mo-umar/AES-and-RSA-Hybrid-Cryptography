'''
By Bryan Nix, Jason Paek, and Mohammad Umar
KSU Fall 2021 CS 3622 Section 03
'''


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from hybrid_rsa_aes import HybridCipher
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
import time
import csv


def RSAexample(data):
  
  data = bytes(data,'utf-8')
  start = time.time()
  keyPair = RSA.generate(2048)
  pubKey = keyPair.publickey()
  pubKeyPEM = pubKey.exportKey()
  privKeyPEM = keyPair.exportKey()

  encryptor = PKCS1_OAEP.new(pubKey)
  encrypted = encryptor.encrypt(data)

  decryptor = PKCS1_OAEP.new(keyPair)
  decrypted = decryptor.decrypt(encrypted)
  
  end = time.time()  
  return end-start


def AESexample(data):
  start = time.time()
  data = b"GOLDENTICKET"  
  key = get_random_bytes(32)  #256-bit encryption
  cipher = AES.new(key, AES.MODE_EAX)
  ciphertext, tag = cipher.encrypt_and_digest(data)

  file_out = open("encryptedfile.txt","wb")
  [file_out.write(x) for x in (cipher.nonce, tag, ciphertext)]
  file_out.close()

  file_in = open("encryptedfile.txt","rb")
  nonce,tag,ciphertext = [file_in.read(x) for x in (16,16,-1)]

  cipher = AES.new(key, AES.MODE_EAX, nonce)
  data = cipher.decrypt_and_verify(ciphertext,tag)
  end = time.time()
  
  return end-start


# Implementation from https://github.com/bigbag/hybrid-rsa-aes

def Hybridexample(data):  
  start = time.time()
  rsa_private_key = rsa.generate_private_key(
    public_exponent=65537, key_size=2048, 
    backend=default_backend()
  )

  rsa_public_key = rsa_private_key.public_key()

  encrypt_message = HybridCipher().encrypt(
    rsa_public_key=rsa_public_key, data=data)

  decrypt_message = HybridCipher().decrypt(
    rsa_private_key=rsa_private_key, cipher_text = encrypt_message)
  end = time.time()
  
  return end-start


def avgList(list):
  total = 0
  count = len(list)

  for i in list:
    total += i
  
  avg = total / count
  return avg


if __name__ == '__main__':
  looptimes = 50
  i=0
  data = "GOLDENTICKET"  
  


  rsa_data = []
  aes_data = []
  hybrid_data = []

  print("Test data to be encrypted: ", data)

  
  print()
  print("RSA encryption: ")
  while i < looptimes:    
    rsa_data.append(RSAexample(data))
    i +=1
  i=0
  for data in rsa_data:
    print(data)
  print("Average: ",avgList(rsa_data))
  print()

  print("AES encryption:")
  while i < looptimes:
    aes_data.append(AESexample(data))
    i += 1
  i=0
  for data in aes_data:
    print(data)
  print("Average: ",avgList(aes_data))
  print()


  print("Hybrid RSA/AES example:")
  while i < looptimes:
    hybrid_data.append(Hybridexample(data))
    i += 1
  i=0
  for data in hybrid_data:
    print(data)
  print("Average: ",avgList(hybrid_data))

  
  with open('data.csv','w') as f:
    write = csv.writer(f)
    write.writerow(rsa_data)
    write.writerow(aes_data)
    write.writerow(hybrid_data)
