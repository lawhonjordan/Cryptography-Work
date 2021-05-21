import conversions
import string
import time

#scores how English-like a text is based on letter frequencies 
def score(text):
    #collect all letters to string
    t = text.lower()
    freq=[0.0817, 0.0153, 0.0224, 0.0470, 0.121, 0.0217, 0.0210, 0.0606, 0.0724, 0.0010, 0.0090, 0.0379, 0.0315, 0.0684, 0.0773, 0.0170, 0.0009, 0.0575, 0.0605, 0.0885, 0.0283, 0.0092, 0.0260, 0.0013, 0.0226, 0.0002]
    if t == 'a':
        return freq[0]
    elif t =='b':
        return freq[1]
    elif t== 'c':
        return freq[2]
    elif t == 'd':
        return freq[3]
    elif t =='e':
        return freq[4]
    elif t=='f':
        return freq[5]
    elif t=='g':
        return freq[6]
    elif t=='h':
        return freq[7]
    elif t=='i':
        return freq[8]
    elif t=='j':
        return freq[9]
    elif t=='k':
        return freq[10]
    elif t=='l':
        return freq[11]
    elif t=='m':
        return freq[12]
    elif t=='n':
        return freq[13]
    elif t=='o':
        return freq[14]
    elif t=='p':
        return freq[15]
    elif t=='q':
        return freq[16]
    elif t=='r':
        return freq[17]
    elif t=='s':
        return freq[18]
    elif t=='t':
        return freq[19]
    elif t=='u':
        return freq[20]
    elif t=='v':
        return freq[21]
    elif t=='w':
        return freq[22]
    elif t=='x':
        return freq[23]
    elif t=='y':
        return freq[24]
    else:
        return freq[25]

#decrypting a binary version of Caesar Cipher    
def one_byte_xor(word):
    s= open(word)
    encrypted = s.read()
    t= conversions.b64_to_bytes(encrypted)
    s.close()
    i = 0
    maxScore = 0
    key = 0
    while(i < 256):
        k= bytes([i] * len(t))
        y = conversions.xor(t, k)
        letters= "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        printable_letters = conversions.string_to_bytes(letters)
        count=0
        dist=0
        currentScore=0
        d=''
        #counts numnber of printable letters corresponding to each key
        for c in y:
            if c in printable_letters:
                count +=1
                temp= bytes([c])
                #create a string containing only printable letters
                d += conversions.bytes_to_string(temp)
        for ch in d:
                #add letter distribution for each character in string d
                dist += score(ch)  
        #keeps track of the max number of printable letters/key associated with this max
        currentScore = 200000*count + 1000*dist
        if currentScore > maxScore:
            maxScore = currentScore
            key=i
        i+=1
    #makes repeating byte key that is length of the ciphertext
    line = bytes([key] * len(t))
    #print the string plaintext after xor conversion 
    return(conversions.xor(t, line))

#decrypt XOR-encrypted MS Word files when the key is known
#use this information to calculate time required for a brute force attack
def decrypt_msword(filename, k):
    s= open(filename, 'rb')
    encrypted = s.read()
    time1= time.time()
    i = encrypted[540]
    j= encrypted[541]

        end = i*256 + j + 512
    else:
        end = j*256 + i + 512

    ct = encrypted[2560:end]
    key= k * len(ct)
    y = conversions.xor(ct, key)
    time2 = time.time() - time1
    seconds = time2 * (2**128)
    years= seconds/(60*60*24*365)
    return y

#returns plaintext of an encrypted file when only ciphertext is known
def ct_only_msword(filename):
    s= open(filename, 'rb')
    t = s.read()
    s.close()
    x = t[540]
    y= t[541]
    if(x<y):
        end = x*256 + y + 512
    else:
        end = y*256 + x + 512
    ct = t[2560:end]
    #print(ct)

    subtext = [b''] * 16
    decoder = []
    
    i = 0
    #split text into 16 subtexts: all 1st letters go together, then 2nd, ..., 16th
    while i < len(ct):
        mod = i % 16
        subtext[mod] += bytes([ct[i]])
        i+=1

    for text in subtext:
        z=0
        maxScore=0
        key=0
        while(z < 256):
            k= bytes([z] * len(text))
            y = conversions.xor(text, k)
            letters= "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            punctuation =":;,.?!-/()&"
            printable_punctuation = conversions.string_to_bytes(punctuation)
            printable_letters = conversions.string_to_bytes(letters)

            count=0
            dist=0
            punc=0
            d=''

            currentScore=0
            for c in y:
                if c in printable_letters:
                    temp= bytes([c])
                    #create a string containing only printable letters
                    d += conversions.bytes_to_string(temp)
                    count +=1
                if c in printable_punctuation:
                    punc+=1
            for ch in d:
                #add letter distribution for each character in string d
                dist += score(ch)

            #include weighted distrubtion, punctuation, printable letters in score
            currentScore = 200000*count + 1000*dist + punc
            if currentScore > maxScore:
                maxScore = currentScore
                key = z
            z+=1
        decoder.append(key)
    line = bytes(decoder)* len(ct)
    return(conversions.xor(ct, line))
        

#Tests code functions on given ciphertexts:

#print(one_byte_xor("ciphertext1.txt"))
#correct key is 94      

#print(one_byte_xor("ciphertext2.txt"))
#correct key is 211

#ourkey1 = 'b624bd2ab42a39a235a0b4a9b6a734cd'
#ourkey2 = conversions.hex_to_bytes(ourkey1)
#print(decrypt_msword('MSWordXOR1.doc',ourkey2))

#print(ct_only_msword('MSWordXOR6.doc'))
#print(ct_only_msword('MSWordXOR8.doc'))
#print(ct_only_msword('MSWordXOR9.doc'))


