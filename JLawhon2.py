
import conversions
import string
import time
import rc4
import javarandom

#finding the key when given the message and corresponding ciphertext in a stream cipher
#idea: xor-ing ciphertext with plaintext will produce key
def find_key():
    s=open('KerckhoffsPlain.txt','rb')
    decryption= s.read()
    s.close()
    #print(decryption)
    x=open("HW2Ciphertext1")
    y = x.read()
    encryption= conversions.b64_to_bytes(y)
    #print(encryption)

    k= conversions.xor(decryption, encryption)
    #print(k)
    return k

#using the key to decrypt a ciphertext encoded by stream cipher
def HW2ProgrammingProblem1():
    x=open("HW2Ciphertext2")
    y = x.read()
    encryption= conversions.b64_to_bytes(y)
    key = find_key()
    return conversions.xor(encryption,key)


#see assingment 1 solutions
def englishiness(text):
    numprintable=0
    numletters=0
    letter_table=[0]*26
    for b in text:
        if 9<=b<=13 or 32<=b<=126:
            numprintable+=1
            if 65<=b<=90:
                numletters+=1
                letter_table[b-65]+=1
            elif 97<=b<=122:
                numletters+=1
                letter_table[b-97]+=1
    score1=numprintable/len(text)
    if score1==0:
        score2=0
    else:
        score2=numletters/numprintable
    english_frequencies=[0.0817, 0.0153, 0.0224, 0.0470, 0.121, 0.0217, 0.0210, 0.0606, 0.0724, 0.0010, 0.0090, 0.0379, 0.0315, 0.0684, 0.0773, 0.0170, 0.0009, 0.0575, 0.0605, 0.0885, 0.0283, 0.0092, 0.0260, 0.0013, 0.0226, 0.0002]
    if score2==0:
        score3=0
    else:
        score3=sum([english_frequencies[j]*letter_table[j]/numletters/0.065 for j in range(26)])
    return 4*score1+2*score2+ 0.5*score3


def HW2ProgrammingProblem2():
    s=open("HW2Ciphertext3")
    y = s.read()
    #print(y)
    encryption= conversions.b64_to_bytes(y)
    #print(encryption)
    
    #t = time.time()
    #print(t)
    #used time.time() to get time at 4:00 PM on 2/16/2021, saved result in seconds in the timeNow variable
    timeNow = int(1613509231.217139)
    
    #subtract seconds to get to 12:00 PM on 2/10/2021:
    #want to subtract 4 hours and 6 days worth of seconds; 86400 seconds in a day and  3600  in an hour
    timeAway = (4 * 36000) + (6*86400)

    startTime = timeNow-timeAway
    endTime = startTime + (6*36000)
    maxScore = 0
    while(startTime <= endTime):
        key = conversions.string_to_bytes(str(startTime))
        decrypted = rc4.rc4(key[:20],encryption[:20])
        #print(decrypted)
        score= englishiness(decrypted)
        if(score > maxScore):
            maxScore = score
            finalKey= key
        startTime +=1
    return rc4.rc4(finalKey,encryption)
    

def HW2ProgrammingProblem3():
    s=open("HW2Ciphertext4")
    y = s.read()
    encryption= conversions.b64_to_bytes(y)
    byte1= bytes([encryption[0]])
    byte2= bytes([encryption[1]])
    byte3= bytes([encryption[2]])
    byte4= bytes([encryption[3]])
    fourCipher = byte1 + byte2 + byte3 + byte4
    #print(fourCipher)
    fourPlain = conversions.string_to_bytes("FROM")
    #print(fourPlain)
    key1 = conversions.xor(fourCipher, fourPlain)
    #print(key1)
    i=0
    j=0
    maxScore=0
    for i in range (2**16):
        lowOrder = i%256
        highOrder= i//256
        key2= key1 + bytes([highOrder]) + bytes([lowOrder])
        #print(key2)
        plain = javarandom.encdec(key2, encryption[4:])
        currentScore = englishiness(plain)
        if(currentScore > maxScore):
            maxScore = currentScore
            finalKey = key2
    return javarandom.encdec(finalKey, encryption[4:])
            
        

#print(HW2ProgrammingProblem1())
#print(HW2ProgrammingProblem2())
#print(HW2ProgrammingProblem3())
