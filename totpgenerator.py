#!/usr/bin/python3
#
# MIT License

# Please see
# https://nbviewer.jupyter.org/github/algorithmic-space/cryptoy/blob/master/rfc6238.ipynb
# Start with https://en.wikipedia.org/wiki/HMAC-based_One-time_Password_algorithm

# Our secret key, which is a base32 encoded 80-bit integer in bytes, it would
# look something like this 'LZITFRQJLUEF7VFY'.  Don't reuse that key, it's 
# all over the Internet now!
K = input("Secret key?  ")


# To create your own key, try
# import base64, random
# K = base64.b32encode(random.getrandbits(80).to_bytes(10, byteorder='big'))

import base64

# Remember, K above is a base32 encoded integer, so before we can work with
# it we need to decode it
K = base64.b32decode(K)

# K is now 10 bytes

# C, the counter, is Unix time (seconds since the Epoch) divided by 30
# That is we break this up into 30-second chunks

import time
C = int(time.time() / 30) # time.time()/30 is floating point, which we dont want
C = C.to_bytes(8, byteorder='big')

# We now have our K and C and will compute HMAC(K,C) with SHA-1 as the
# hashing function

# HMAC(K, C)
import hmac, hashlib

# NOTE:  K and C must be in bytes
H = hmac.new(K, msg=C, digestmod=hashlib.sha1).digest()

# This remaining is taking the computed hash and extracting the definition
# of the TOTP which is "a truncation of the HMAC".  
#
# First, get the resulting integer
H_int = int.from_bytes(H, byteorder='big')

# Obtain an offset which is defined as the last 4 bits of the integer
offset = H_int & 0xf 

# Compute how much we need to take shift the integer to get the TOTP
shift = (8 * (len(H) - offset)) - 32
MASK = 0xFFFFFFFF << shift
hex_mask = "0x"+("{:0"+str(2*len(H))+"x}").format(MASK)
# Clever routine from cryptoy

# Extract the value
P = (H_int & MASK) >> shift # Get rid of left zeros
LSB_31 = P & 0x7FFFFFFF     # Return only the lower 31 bits

# Take modulo 10^6 and print with leading zeros if necessary
print("%06d" % (LSB_31 % 1000000))

