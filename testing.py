import scrypt
import string
import random
 
password='RandomPassword'
salt_len= 7
salt = ''.join(random.choices(string.ascii_lowercase + string.digits, k=salt_len))
 

hash_ = scrypt.hash(password, salt)

print('Password: ',password)
print('Salt: ',salt)
print('Hash: ',hash_)
print(len(hash_))
