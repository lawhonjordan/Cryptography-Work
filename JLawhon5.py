from Cryptodome.Util import number
from Cryptodome.Util.Padding import pad
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import math
import conversions

#Finds the floor of N**(1/k)
def kthroot(N,k):
    high=N
    low=1
    while low+1<high:
        mid=(low+high)//2
        power=mid**k
        if power==N:
            return mid
        elif power>N:
            high=mid
        else:
            low=mid
    return low

#finds solution x to a*x + b*y = gcd(x,y)
def extendedEuclid(a,b):
    #if a is 0, the gcd will be b; thus 0*a + 1*b=b soln
    if a==0:
        return (0,1)
    #otherwise, use recursion to find soln to next line of euclid's algorithm
    else:
        (x,y)=extendedEuclid(b%a,a)
        return (y-(b//a)*x, x)
        
def problem1(c,RSA,mod):
    AES_K= conversions.int_to_bytes(kthroot(RSA,3))
    c_bytes=conversions.b64_to_bytes(c)

    #IV is the first 16 bytes; the rest is the encrypted message
    IV=c_bytes[:16]
    c_bytes=c_bytes[16:]

    #AES decryption using decrypted AES key:
    cipher = AES.new(AES_K, AES.MODE_CBC,iv=IV)
    plaintext = cipher.decrypt(c_bytes)

    return(plaintext)

def problem2(c2, RSA_k1, RSA_k2, RSA_k3, mod1, mod2, mod3):
    a= RSA_k1 * (number.inverse(mod2*mod3, mod1)) *(mod2 * mod3)
    b= RSA_k2 * (number.inverse(mod1*mod3, mod2)) *(mod1 * mod3)
    c= RSA_k3 * (number.inverse(mod1*mod2, mod3)) *(mod1 * mod2)
    x= (a+b+c)%(mod1*mod2*mod3)

    #perform RSA decryption to find AES key
    AES_K=conversions.int_to_bytes(kthroot(x,3))
    AES_K=AES_K[100:]

    #convert ciphertext to bytes
    c_bytes=conversions.b64_to_bytes(c2)

    #IV is the first 16 bytes; the rest is the encrypted message
    IV=c_bytes[:16]
    c_bytes=c_bytes[16:]

    #AES decryption using decrypted AES key:
    cipher = AES.new(AES_K, AES.MODE_CBC,iv=IV)
    plaintext = cipher.decrypt(c_bytes)
    
    return(plaintext)

def problem3(c,RSA_k1, RSA_k2, mod, e1, e2):
    #find coefficients x,y such that e1*x + e2*y = gcd(e1,e2)=1:
    x=extendedEuclid(e1,e2)[0]
    y=extendedEuclid(e1,e2)[1]

    #use this information to find decrypted AES key
    k=conversions.int_to_bytes(pow(RSA_k1,x,mod) * pow(RSA_k2,y,mod) % mod)[100:]

    #extract iv from ciphertext
    c_bytes = conversions.b64_to_bytes(c)
    iv=c_bytes[:16]
    c_bytes=c_bytes[16:]
    
    AEScipher= AES.new(k, AES.MODE_CBC,iv=iv)
    AESplaintext= AEScipher.decrypt(c_bytes)
    return AESplaintext
   
    
#arguments are: b64 ciphertext,RSA-encrypted AES encrypted keys,2 moduli
def problem4(c, RSA_k1, RSA_k2, mod1, mod2):
    #encryption exponent (given):
    exp=65537

    #lucky prime
    q= number.GCD(mod4_1, mod4_2)

    #use lucky prime to factor the two moduli:
    p= mod4_1//q
    r= mod4_2//q

    #need only find one secret key; we can use this to get AES key
    d1=number.inverse(exp,(p-1)*(q-1))

    #perform RSA decryption to find AES key
    AES_K=conversions.int_to_bytes(pow(RSA_k1,d1,mod1))
    AES_K=AES_K[100:]

    #convert ciphertext to bytes
    c_bytes=conversions.b64_to_bytes(c)

    #IV is the first 16 bytes; the rest is the encrypted message
    IV=c_bytes[:16]
    c_bytes=c_bytes[16:]

    #AES decryption using decrypted AES key:
    cipher = AES.new(AES_K, AES.MODE_CBC,iv=IV)
    plaintext = cipher.decrypt(c_bytes)
    
    return(plaintext)
    
def problem5(p,g,gx,x,alpha,beta):
    #alpha will be our g^y; compute g^(xy) by raising alpha to the x power
    g_xy= pow(alpha, x, p)

    #find the modular inverse of g^(xy) mod p
    inverse=number.inverse(g_xy,p)

    #beta will be our (g^(xy) * m)mod p.
    #To get m, mulitply beta=(g^(xy) * m)mod p by our inverse to cancel out the g^(xy)
    m=(beta * inverse)%p

    #convert ints to bytes to get readable message
    return conversions.int_to_bytes(m)

def problem6(p,g,gx,alpha,beta1,m,beta2):
    #find the modular inverse of m mod p, where m is the decrypted plaintext:
    inverse1= number.inverse(conversions.bytes_to_int(m),p)

    #use this inverse to remove m from (g^(xy) * m)mod p
    g_xy=(beta1*inverse1)%p

    #find the modular inverse of g^(xy)mod p
    inverse2=number.inverse(g_xy,p)%p

    #use this inverse to decrypt beta2:    
    m2=(inverse2 * beta2)%p

    #convert to bytes so it will be readable
    return conversions.int_to_bytes(m2)

def problem7(p,g,gx,alpha3,beta3,y)  :
    #use the discrete log to find g^(xy)
    g_xy = pow(gx,y,p)

    #find the modular inverse of g^(xy)
    inverse=number.inverse(g_xy,p)

    #use this inverse to cancel out g^(xy) from beta= (g^(xy)*m)mod p:
    m=(inverse*beta3)%p

    #convert to bytes so it will be readable
    return conversions.int_to_bytes(m)

#PROBLEM 1 INFO:

mod1= 120696137586355496698728165551568989637089271817902047988651990803595226652684266264577099609172412794784690621468470362316950240036893845066808315597298992511982439867925631204979386032742576515513461355580607636111526975040856889287815487424957232007530623699046255131811211953056283477854310014259954619987
Alice1= 3429984293039807285576023456236152099314797756593051862961979030674908291702329741694125198007512059541814312565056
c1='oVmlFMio8nXyVmR6mbXLNYU4H3ygjOnBN8iMBTZt2lshK7sQJ3EIBGun2WqRxxMOP27Lbs+mZtAcb027XsMTL1Spj7TD6WxItc6AmHZ4qmgne6UKdNRXQKVVfx3jR/UYt63n4Rg8n8HhyMwDMfLYvweGHAEd3mfAOfDvisVSp/0GUmqwYKM4FNjx+kCxF2AC/ytco3LZBtCQTxbrwuIr6KuzfldwV/0gv/Kgl5ZRYHmMYbnJT8h2Kf3bgbflMNoTOSK+UEZ9zUOplxtc9KL0MQL+ISI4sEaMLJEdJfk0/sgKf0/BYS5noz6oCiJMU1BiS7sU6KQUWSWmI2diK04fdFSLRmvHbuK8x89n3/mfhn+ZieGV6q6uwyIHyJOoYcumx2SE86L1dOnPn2Dr7kWOf4fK1D2sQF4hpwtelCcRWCLcRdPNVQGK0DKD/7tZQmuj+JTEm15XrqHaBNoNi87Z2tEDfTGvRB4vHxNMxRo6XJ/KWQu/kK2Lb4OS18BxJAZMhp0UYZ4tHSTxP4ZB/RBI12F1TMHwKu1caHWI+fpsOi4aX2o0h1QU3NrH+tyToi98c/6BYUvoUjjfYm0fSirQfXbr3bkSgmsHd70bPrAM4P9zdcVO1QuxIbq0TiIPxgIPuA6VjjcFqYOpWAteQ1gFpMLTpF75EdNzIqCRgYtRP7qrdTZkKpgANQ4dlTe5awKPm/Us7bo1FpMfo6kivIiI0b5CgbKIrswnOuzC2NIPZEzgDRpHdxfuNlgOWJVe/2D8vBx9bRFvf4Wr5RnjVaNHcA=='

#PROBLEM 2 INFO:

mod2_1= 87579612990618314102124871679268923167970966779183539617574750483692757201437451261555001186499440892871200314167408133975760699439917897917730369451802595992117946860833662917355842621708737226657232355225809713919654357498417868996471796645169437879472174954627274613333825083817197156500592990009673653727
mod2_2= 74768154632746358446462665964207348812047719977476328440118270548676061931095051243180342522713845750994830040030330094530542513564471837086118666962554938753282044777644246921008318538440139118320394469872538377532307406443581150451495708751944005308278597049997288016781187689770387634149438058178520653269
mod2_3= 77404121448305723774812205269947855048220861580169143300319551198562851467325680832161497448734958928336280550369278108559117419958831721746887966479327230708350509949626311971993675246727938882850481010567581032934723082312953446579638118684381082219176891517705734647641679120991168094809010024123019060397

#RSA-encrypted AES keys:
Alice2= 57338259262961978757373212768068382187569208143651578763477552151716838114884653239711282158078378301746680987821387594938629503851818075437923683616636767448078993227344061765339324473092450930172572397747300169187332630436683307999051240505402501857027972184770325516647588674556282704120235076694746547128
Alex= 27126570318661104798461106082544511590874070104958403018268320598375647804736025596632943933646342883329738160954047392420962011130219190264275000946009232810404901517490837683846312643001946722907873251093120431412993193624200355666593345847202879871107097329535401433623904395740313695114336631456820735470
Alison= 5299563034774846334487988153977393707344236509380072427711116275843312629260104650228331306732034055503161010199464981077696288677828420405436013033131508423632748702677443361795276049351007520212129254702323069102946146230520842219689642924497634743331345070434279030580579981722258701669659409447698069086

#Ciphertext:
c2='lNWYzsPbNYpO5bv5W+YM+UPtw4IZV24cF5S9F6BCdmRGlet7lygW03avNo54SFQNl56w2/RnsQW2WdsSHUBwc3CeTdps0QOKe7aXlWepjCI150JIRaSEXelsdxxY9T2PDLEvLcXsr6xOPNqJq+n6AUisXI48uN3yXdZCoUc+FzujWYkBgPl7TwCPLs2p6JmcJTQhwzGwrrfQPJEmiPGC6is56bWtnlXmix/3LZ1Y9VK7iYyvM/wYGD8nKP57mJpRDBuop2FjQ147Tp4T8FUfuLXTavnT+RQtMz0TeMfZSRDzcHuVwatXAY/v/1l/d9LCIf5kJ5lMZWRnPZcA29f3XiV4WcBTl7oRNhBc5Rpf7MY4OF4QIY2hEb8vn0vN6sim1ieerMT4bIsC4cAlovOJ4JdakgbBTdPJgqEJmSHKIBxVWGFxfVNL34ruyIkeiVeAq1b7xsV8qrtrh6yUQcEJg0g/9fchD4Ll7nDMvzEHit3fSNZGKRUCxApXL5h0Bus4RweqOhc+Zz5BSGI9ySmc01BV1wlTICuGgDVyrT1cX4BB3FTaAYgteVFeqmldOvWMOjY6C/riG9lrL+LXX3ghoifjmHk6NwHolW3jXkteNz64aZBhcTouhhThtEdRJCaC4JFPGotCt9AAa+YMHT0YbCOAvcBPlD7TmswFFfDVJhBx/QRn220mJ+UsZteAfAAG9Pwr/PTgRXqy3Az00cZLe4FrFH/vqkAvaBxOEpELnkNgd4deU9OVuZOuja9d/ldjCorIpgVdE0p0qCjyDlfVQF+cHxaf1QR51YPTotK6c/U3huiva4dAksBRXCp3iy/MRehvxjn18giljutsdnG+1G/YiVs4Od45XFX4sVR5U3/ET1KIxezny0h12x6VnlbVqSN9uVUl+RB+3+QFpXT9+zWjVMg2vTmR0M/t8hirk8ju2/u+DUCNKAGlnBypo+Umty6umZd0BVB9Y8K/tWk7n9YDYUZr7GTrUqpyWVe7F31xa4DCvAJ4xcm7gi9230mR73hZaxtvsug7qZ1nAi5Zc4iWxwjrZFuJ1yt95eEoLG3i/rYFhaH2W78gieWp/x4M3BJqptvFoFp3s7wPAphEeUdvqs1eStA6LBQaFM2jaSrVJFQDwudk7gMGhoika8Yzvc/ZcKTvrZ719AADV//7VkVnEuFiBGkW64mBABBFCJegJG+YPMuMinZTElJ/9r297uf1SEO3s2BiYnIe1oZZkA=='

#PROBLEM 3 INFO:

#Modulus:
mod3= 86927869148068721800205646535390173442221039784752216879593016189242827038254628814626577519582588085832753395967466359400722667373335087224830243493497166251650965934580888309607048068298875521279658783115879745660681843724085646857721837162283105707463654370401002277881428145166798554522742774423057053973

#RSA-Encrypted AES keys:
Ellis=25868686356670515975399174526272991440281227445630655190459020494965175881948127374910106877671164212293087635958763034567653349292528935169712931444232131796725226620844513244119432953849193603781122837321558144697880336424648955074101122474563391805148455541168906756518273025634976959052965621077957409575
Eliza=80301397431222221668659314493225725764594153834848384896395807889798033280151808120762557627587051830584834618606748996189679730074692330954790953123000589058609437773435073140414824000150571002463567873902140324228121812721513959087227942302701269975198848421929819682382242235533939300380731657187905393014

#Ciphertext:
c3='QIbNbtrgNTLFFdjXUTeGHjGlhXGh0Jtt/YA9dUnKwiaeTZGiO5nrQVyvhhPlTNzujIOjtIrmhlNUIJ5jLqhgaUeZbIVE0P4NHHEP/SQ6dachdG55CCuiqXZokUZDjXhbC9sN027ANn0tBgN7Hehb81Q03nXjsgsP38sn027/jfDW7u+D1k0vGwRAsTiCRHqw75fwPW+/he8GYavGlsYYrqU+aZOTmF+uFmPb2bVokGX8dnOVVX8kXzaKzGQ18cA2eAoWj4Ohzgbmaa+9ZnSgBMUMl4lo5+bZHW2X3pR2+fOnt3XAsoKNDlKEktGfaKmDmt0jBUNZZikfCz0dGsMxzy/XNDmXj3PPU3PPTWjl30FQO9zGhyBFGtruWIq9IwO8OqbVlzvMLL1SPTIElRsQPJrUUiES9zwdPC/DhhkeJ+e40aqc5W4ixVYhPTNhfOOaX+R+aYoMqvsGe7HbsnDF37cmE14+HpEx8XLgetOsESdNN/UDaTSRyuT/BUQ+lWoWtzxVp9wYUv+B/AH0Q5EiXXpDdKFJ8MYSAysC9XVje9k1VqP0ih3uF5W+eBV1FQPgsEoenr4IR53UdHZ9R7ohjQxW3ERHL7hbePyTL0VYPU6wmun2Am7FlkCtuS8tzRhMKuxxWjitMx68TDu2oenLYGl95/ZzN3Abee6O8ddhy9u8Dw1B6g/eeSyVo/B8/nSyRe2CeSYut/PUajIFmbKAD9fsX75atmRRvoufmDC4OEKdvZPzKRIklrgx4rcbySS9XV4Hye0CKSVX/UARR7/hb8zUHWxjaOTpe5Cw6OKGVVMo9go+h8MgySj465ZWxmMhF+O7MCCRruPuBprHNO18am1FdE6DCE76AX7pjP32KxLnM0Vu4iUIQoSMEd/3l21TmXXA/0ufWfT9seDIKtKXjUuv8ii2lrZPrYm8qrA131p8ujdgARggYzJj7KvxT7xfN9tLL4uBm0k+lx0djqtw8Ovl12k9yLQYUR2+v9Gezmvz8F1m1JI/zBsgA7X07QL6bN+6HVe+VZgSRbpYTL1SuuWW0eNdpN5iRd0MjpRIJYp+zHlNv6RfYlw9zVrqlRH3nr+N+ouzoSa2iLLvfP8Jx62xItlBBE1P2yWLCe6ySl3wJVl7QH0lDyEFU8pFio4oj90bcI+xRGSLx1NvniYtg66B3jaxq3+HutgxK1FZktlSXN4uVAEBCFoLFWechWHRDMgYEJfANo/SU1xWIHc/rakVZjXwjlV17lh/ucorT8VmaeyFp9c8LadJYBaYdW1S9L0r5MmTyW1hPbriQ9tYnB9LW4ZYo/fBQUmwzgD8lAQ='

#PROBLEM 4 INFO:

#Moduli:
mod4_1= 84185973630693291349268428850337667984743183199582755169179599069649839239628953821813268678130819942798609949831341905638148777260537267828667659418324263960173684590582941322592543140299626304183582068739655652103378369658431765171089730673084628663724685365536963633547247716497994957761414251349084831549
mod4_2= 109907522111790168063036254295648598173777602083423743997365534553871306459697314822774438061238202564199462632478702499422995236891650031008233402947021837148433963550666744464481308653198538204096147510389199098739481982159356227099274217843759490247795137166573014385604341327132264437982767964731456436199

#RSA-encrypted AES keys:
Bubba= 26077578949627703387518841077774125901711252791539535271256545676769592214575671519489929265866126318317462318282581466286964779897595399016984153892727494324673279144717280449049286309264584009929874740899072538355363022734649769367727778279153042802253856310460817838081611846773381905989018154144000069112
Barb= 21413753568031267670125988805196624235041091504892244774587365020033755126683555742127205351660642319410047381357117323905036660165503173887130452934400758245236533073826083399921923229376617194942434443674267014288140982992220116061452693156011937523961628043204691325730979435055335924232256308714975615054

#Ciphertext:
c4='cUvl/jO5oqC/O40oK7TpsPMX3GSaAgneVhB4H6mEXMx3W323Ld6lXVNy2of5KdBQkqSlTnu33vMYuIZ0aUmi6KJWzbvA63mi/mt3DZV+hYZGTm1HAqwLVcMI8yNbr/exymlPFd2TeZPxbfNcNxTDXm/Lrcsla8nfRVv14WMAQlgfU4QBpQnbGZHuNRzVn+x3FwHQeI7P5A3GaSBPeyKR+3Gvot12HdJaLTw6fbcGYLAdPiXANZmIzVgac7xop46MZEPTsJsmzcNo2/b1y7IWwyRkp97kIagMTYuwLPsfekTBW2eTFaObtDBkVbnnDOt0nU0c0c8xnumnfs5PyxvJ3w5O2pQKNNTbrvgDcSkFknLHsMjUMRiS1jGDV4L4k7dkH3BI/2829kFQgvo0JydLWV6NpJPadqMKqEk0b59kmSHagT8JErUq63mKE65aqjtBkW5s/JA1KO0Dvq62GTJoSCpBky66m2D+BYxmyz4stNuPNPgdWhnINV6qyLQMXW6ZpHIzc4jELDUYsALy6SXxCxcSx/qB/2xyps9RaTvy5VSiBnf4ZMEWhQrn+BFlhmPNDQI/0dQJnA+NW0PcS0gZj6yzIPJmj4omUvPv9dXjy7WvDUZU5IXv62xvg+sJu5mLWoFFbXIAlh3Nc2yUp7W5fDacJj5NPjQaDXpuPtGbZZY='

#PROBLEM 5 INFO:

#prime modulus:
p=191147927718986609689229466631454649812986246276667354864188503638807260703436799058776201365135161278134258296128109200046702912984568752800330221777752773957404540495707852046983

#primitive root mod p:
g=5

#g^x mod p:
gx=176478319826764259370406117740489882944142268114222243573886354279989450112247437716236796057251798300509450763347865746885560883563075519833320667906000345397226327059751213369961

#secret exponent:
x=42694797205671621659845608467948077104282354898632405210027867058530843815065930986742716022222447350595400603633273172816767784236961837688169657044396569579700949515830214254992

#g^y mod p:
alpha1= 73982478796308483406582889587923018499575337266536017447507799702797406257043632101045569763590982806403627704785985032506296784648293661856246199184245278019913797261546316759270

#g^xy * m (mod p):
beta= 1227561673735205443986782574414500194775280963876704725208507831364630528829422611287956320336912905023628854115065478249082243473610928313596901712034514819305660036543382454852

#PROBLEM 6 INFO:

#shared alpha= g^y mod p:
alpha2= 104862672745740711919811315922065122010281934991422240638097533405207971405689057652673577043484488015740722326384001808611695005135028713487234715202873484670021923322009761545457

#g^(xy)*m1 mod p:
beta1= 17606878671981551311137298337848994393797765223509173646178261989274226953505667592410786573428076963287971811161509360601971410344413313700739795932040261074709506491861567699546

#g^(xy)*m2 mod p:
beta2= 116115839773157782821329377087409766815814624668492668098672866213651171163182813304753241741593566110843721045751605192482170477996370202802973966889697676265503034822908949368607

#decrypted message
message= b"Now my charms are all o'erthrown and what strength I have's mine own."


#PROBLEM 7 INFO:

#alpha=g^y mod p:
alpha3=68188080109582330879868861330998506151774854600403700625797299927558995162740321112260973638619757922646242302104885437536745080299248852065080008358309735875192480724496530325927

#eve's discrete log y:
y=138670566126823584879625861326333326312363943825621039220215583346153783336272559955521970357301302912046310782908659450758549108092918331352215751346054755216673005939933186397777

#beta=g^(xy)mod p:
beta3=112018886720018236580229932176683955946063514397085867696250318378121351302079624330821244744748925197792097406122146093507280201522804485024833199924734248052247065779216659451112


#TESTS
#print(problem1(c1,Alice1, mod1))
#print(problem2(c2, Alice2, Alex, Alison, mod2_1, mod2_2, mod2_3))
#print(problem3(c3, Ellis, Eliza, mod3, 17, 23))
#print(problem4(c4, Bubba, Barb, mod4_1, mod4_2))
#print(problem5(p,g,gx,x,alpha1,beta))
#print(problem6(p,g,gx,alpha2,beta1,message,beta2))
#print(problem7(p,g,gx,alpha3,beta3,y))
