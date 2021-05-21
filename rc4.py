#implementation of RC4
#Written by Howard Straubing

#The key is a string of bytes,
#which can be up to 128 bits
#long.  The state is a list
#of 256 bytes with integer values.

import conversions
def rc4_initialize(key,verbose=False):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        (s[i], s[j])= (s[j], s[i])
        if verbose:
            print (s[:16])
            input('hit return to continue')
    return s
    
#Given the initial state, update the generator
#of the state and emit the next byte. Do ths
#numbytes times in succession.  The output is a string
#of numbytes bytes
def rc4_genbytes(state, numbytes):
    output =b''
    i = j = 0
    for k in range(numbytes):
        i = (i+1) % 256
        j = (j+state[i]) % 256
        (state[i], state[j])= (state[j], state[i])
        output+=bytes([(state[(state[i]+state[j])%256])])
    return output

#Encrypt or decrypt a  bytes object with a given key.
def rc4(key,text):
    initstate=rc4_initialize(key)
    keystream=rc4_genbytes(initstate,len(text))
    return conversions.xor(keystream,text)

def test():
    key=b'Here is a random key that you cannot possibly guess.'
    plaintext=b"Once upon a time you dressed so fine, threw the bums a dime in your prime, didn't you?"
    return rc4(key,plaintext)

seed = b'MyPassword'
initState = rc4_initialize(seed)

#eunning the for loop below shows that the inital state that results when seed value is used is 255 long
#j=0
#for i in init:
    #print(j)
    #j+=1
#print(initState)

#print(update)
#print(len(update))
c = 'xfF9WiQA/iBTKofu/Fls4dNuPX8eHK6ETXEI2Go4bgFL16Xhun1sBeA/aF/iGhnVzEk3087mJFY988RqAdVLVJcmRCo8SBq19OXPfXdrcLYbB+kw/qeZsCXBCj0lwS258EfVDWJJuEPa+NcU5tVOXDEm6h372KJw3rAadPIPKyKfW+ASMiMv6LMU'
c2 = conversions.b64_to_bytes(c)
update = rc4_genbytes(initState, len(c2))
print(conversions.xor(update, c2))
