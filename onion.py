import base64
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad,pad
from Crypto import *



def numToStr(inp):
    out=""
    while inp!=0:
        out=chr(inp & 255)+out
        inp=inp>>8
    return out


def invert_bits_in_bytes(data):
    return bytes(~b & 0xFF for b in data)

def xor_with_pattern(data, pattern):
    pattern_bytes = pattern.encode('utf-8')
    pattern_length = len(pattern_bytes)
    result = bytes([b ^ pattern_bytes[i % pattern_length] for i, b in enumerate(data)])
    return result
def decrypt(data, key_stream):
    return bytes([b ^ k for b, k in zip(data, key_stream)])
def bitsoncount(x):
    return bin(x).count('1')

class LFSR:
    def __init__(self, taps, fill, reg_len):
      #Code here
      self.register = int(fill)
      self.mask = 0
      for t in taps:
        self.mask+=(1<<t)
      self.reg_len = reg_len

      #


    def produce_key_stream(self, n):
      #Code Here
      out=''
      for i in range(n):
        out +=str(self.register & 1)
        newbit = bitsoncount(self.register&self.mask)%2
        self.register = (self.register>>1)+newbit*2**(self.reg_len-1)
      return out
      #
with open("Onion_1", 'r') as file:
        data = file.read()
        data = base64.b64decode(data)
        ##print(data)
data = invert_bits_in_bytes(data)
##print(data)
byte_list = list(data)
index = 365
byte_list = [b for i,b in enumerate(byte_list) if i > index]
data = bytes(byte_list)
##print(data)

# Example usage

pattern = 'CRYPTOGRAPHY'
data = xor_with_pattern(data, pattern)
##print(data)

byte_list = list(data)
index = 280
byte_list = [b for i,b in enumerate(byte_list) if i > index]
data = bytes(byte_list)
#print(data)

def lcg(x0, a, c, N, length):
    x = x0
    key_stream = []
    for _ in range(length):
        x = (a * x + c) % N
        key_stream.append(x & 0xFF)  # Use the 8 least significant bits
    return key_stream


'''Layer 3 - Decrypt this Layer using an LCG; x_{n+1} = a * x_n + c (mod N),using a = 1664525, c = 1013904223 and N = 2^32.
  Each x_n produces 32 bits. Use x_0 = \x15\xfa\xe3..
 At each step only use the 8 least significant bits in the key stream.Note-The first byte of the key is NOT the seed:'''

a = 1664525
c = 1013904223
N = 2**32
x_0 = int.from_bytes(b'\x15\xfa\xe3', byteorder='big')  


key_stream_length = len(data)
for i in range(0,0xFF):
    x = (x_0 << 24)|i
    key_stream = lcg(x, a, c, N, key_stream_length)
    decrypted = decrypt(data,bytes(key_stream))
    if  decrypted[0] == ord('L'):
        seed = x        
        ##print(decrypted)
        data = decrypted
        break

'''Layer 4-Decrypt this Layer using a Linear Feedback Shift Register
 which is 9 bits long and has taps at position 0,1,3,4, and 8. The initial fill is 0x155 = (101010101)'''
byte_list = list(data)
index = 166
byte_list = [b for i,b in enumerate(byte_list) if i > index]
data = bytes(byte_list)
##print("\n",data)
helpLFSR=LFSR([0,1,3,4,8],0x155,9)
key_stream = helpLFSR.produce_key_stream(len(data)*8)
integer_value = int(key_stream, 2)
num_bytes = (len(key_stream) + 7) // 8
key_stream = integer_value.to_bytes(num_bytes, byteorder='big')
data = decrypt(data,key_stream)
##print(data)


'''Layer 5-Decrypt this layer using DES in Electronic Code Book mode.
 They key is 16 bits repeated 4 times, Note: there is padding on the last block you will need to remove:'''
byte_list = list(data)

index = 168
byte_list = [b for i,b in enumerate(byte_list) if i > index and i != len(byte_list)]


#padd it to be multiple of 8
for i in range(7):
    byte_list.append(0)

data = bytes(byte_list)
print(data)
#code to find correct key

'''
outputs = []
for i in range(0x0000,0xFFFF):
    key = i|i<<16|i<<32|i<<48
    key = key.to_bytes(8, byteorder='big')
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_data = cipher.decrypt(data)
    output=""
    for j in range(0,7):
        output += numToStr(decrypted_data[j])
    if output == "Layer 6-":
        print(i,output)
        break
    good = True
    count = 0
    for a in range(0,len(output)-1):
        if output[a] not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-_=+:;'.,":
            count += 1
    if count >=2:
        good = False
    if good == True:
        outputs.append((i,output))'''



correct = [28234,28235,28491]
i=correct[0]
key = i|i<<16|i<<32|i<<48
key = key.to_bytes(8, byteorder='big')
cipher = DES.new(key, DES.MODE_ECB)
decrypted_data = cipher.decrypt(data)
#print(decrypted_data)
data=decrypted_data







'''LAYER 6'''
byte_list = list(data)
index = 207
##print((data))

#remove padding and instructions
byte_list = [b for i,b in enumerate(byte_list) if i > index and i<=len(byte_list)-7]
data = bytes(byte_list)
##print(data)



def smallest_prime_factor(n):
    """Find the smallest prime factor of a number."""
    if n % 2 == 0:
        return 2
    factor = 3
    while factor * factor <= n:
        if n % factor == 0:
            return factor
        factor += 2
    return n  # n is prime

# Determine the key




from Crypto.Cipher import AES

def XOR_blocks(a,b):
    """XORs two blocks of data."""
    out = b''
    for x, y  in zip(a,b):
        out += bytes((x^y,))
    return out

def decrypt_aes_block(key, ciphertext):
    """Decrypts a single AES block."""
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

def encrypt_aes_block(key, ciphertext):
    """Decrypts a single AES block."""
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.encrypt(ciphertext)
    return plaintext


'''Decrypt this layer using AES-128 in Counter mode.
Use 0X 0000 0000 0000 0000 as the IV. They key is the smallest prime factor of 2181730801 filled to the left with zero bytes:'''
number = 2181730801
smallest_prime = smallest_prime_factor(number)


key = (smallest_prime).to_bytes(16)
##print(len(key))

counter = (1).to_bytes(16) #IV
print(data)

'''decrypt using code from another lab to do CTR mode'''
def increment_counter(iv):
    iv_int = int.from_bytes(iv, byteorder='big')
    iv_int += 1
    return iv_int.to_bytes(len(iv), byteorder='big')

num_blocks = len(data) // 16
plaintext = b''
for i in range(0,num_blocks):

    counter_block = counter
    ##print(counter)
    encrypted_counter_block = encrypt_aes_block(key,counter_block)

    # Get the current ciphertext block
    current_block = data[i * 16:(i + 1) * 16]

    # XOR the encrypted counter block with the ciphertext block
    decrypted_block = XOR_blocks(encrypted_counter_block, current_block)

    # Append the decrypted block to the plaintext
    plaintext += decrypted_block
    counter = increment_counter(counter)
#print(plaintext)

'''decrypt 6 using built in ctr'''

from Crypto.Cipher import AES
from Crypto.Util import Counter

IV = 0x0000000000000000
ctr = Counter.new(128, initial_value=1)
cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
plaintext = cipher.decrypt(data)
print(plaintext.decode(errors="ignore"))

