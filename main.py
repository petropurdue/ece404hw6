# Homework Number: 06
# Name: Ziro Petro
# ECN Login: petrop
# Due Date: March 09 2020
# Python Interpreter: Python 3.8

#globals
e = 65537

from BitVector import *
import sys
import random
import math

##  PrimeGenerator function
##  Author: Avi Kak
##  Date used: 7 MAR 2021
class PrimeGenerator(object):  # (A1)

    def __init__(self, **kwargs):  # (A2)
        bits = debug = None  # (A3)
        if 'bits' in kwargs:     bits = kwargs.pop('bits')  # (A4)
        if 'debug' in kwargs:     debug = kwargs.pop('debug')  # (A5)
        self.bits = bits  # (A6)
        self.debug = debug  # (A7)
        self._largest = (1 << bits) - 1  # (A8)

    def set_initial_candidate(self):  # (B1)
        candidate = random.getrandbits(self.bits)  # (B2)
        if candidate & 1 == 0: candidate += 1  # (B3)
        candidate |= (1 << self.bits - 1)  # (B4)
        candidate |= (2 << self.bits - 3)  # (B5)
        self.candidate = candidate  # (B6)

    def set_probes(self):  # (C1)
        self.probes = [2, 3, 5, 7, 11, 13, 17]  # (C2)

    # This is the same primality testing function as shown earlier
    # in Section 11.5.6 of Lecture 11:
    def test_candidate_for_prime(self):  # (D1)
        'returns the probability if candidate is prime with high probability'
        p = self.candidate  # (D2)
        if p == 1: return 0  # (D3)
        if p in self.probes:  # (D4)
            self.probability_of_prime = 1  # (D5)
            return 1  # (D6)
        if any([p % a == 0 for a in self.probes]): return 0  # (D7)
        k, q = 0, self.candidate - 1  # (D8)
        while not q & 1:  # (D9)
            q >>= 1  # (D10)
            k += 1  # (D11)
        if self.debug: print("q = %d  k = %d" % (q, k))  # (D12)
        for a in self.probes:  # (D13)
            a_raised_to_q = pow(a, q, p)  # (D14)
            if a_raised_to_q == 1 or a_raised_to_q == p - 1: continue  # (D15)
            a_raised_to_jq = a_raised_to_q  # (D16)
            primeflag = 0  # (D17)
            for j in range(k - 1):  # (D18)
                a_raised_to_jq = pow(a_raised_to_jq, 2, p)  # (D19)
                if a_raised_to_jq == p - 1:  # (D20)
                    primeflag = 1  # (D21)
                    break  # (D22)
            if not primeflag: return 0  # (D23)
        self.probability_of_prime = 1 - 1.0 / (4 ** len(self.probes))  # (D24)
        return self.probability_of_prime  # (D25)

    def findPrime(self):  # (E1)
        self.set_initial_candidate()  # (E2)
        if self.debug:  print("    candidate is: %d" % self.candidate)  # (E3)
        self.set_probes()  # (E4)
        if self.debug:  print("    The probes are: %s" % str(self.probes))  # (E5)
        max_reached = 0  # (E6)
        while 1:  # (E7)
            if self.test_candidate_for_prime():  # (E8)
                if self.debug:  # (E9)
                    print("Prime number: %d with probability %f\n" %
                          (self.candidate, self.probability_of_prime))  # (E10)
                break  # (E11)
            else:  # (E12)
                if max_reached:  # (E13)
                    self.candidate -= 2  # (E14)
                elif self.candidate >= self._largest - 2:  # (E15)
                    max_reached = 1  # (E16)
                    self.candidate -= 2  # (E17)
                else:  # (E18)
                    self.candidate += 2  # (E19)
                if self.debug:  # (E20)
                    print("    candidate is: %d" % self.candidate)  # (E21)
        return self.candidate  # (E22)

def encrypt(bitvec,n):
    return BitVector(intVal = pow(bitvec.int_val(),e,n),size=256)

def RSAencrypt(filename,n):
    bv = BitVector(filename=filename)
    finbitvec = BitVector(size = 0)
    while (bv.more_to_read):
        bitvec = bv.read_bits_from_file(128)
        if bitvec.length() > 0:
            if bitvec.length() != 128:
                fazoodle = 128 - (bitvec.length()) % 128
                if (fazoodle == 128):
                    fazoodle = 0
                bitvec.pad_from_right(fazoodle)
        bitvec.pad_from_left(128)
        bitvec = encrypt(bitvec, n)
        #print("encrypted length is",bitvec.length())
        #we now have the 256-bit encrypted bitvec string. Nice.
        finbitvec += bitvec
    return finbitvec

def inputtobv(key_file):
    #file reading
    kptr = open(key_file,"r")
    key = kptr.readline()
    key = key.strip()

def writeinttofile(filename, sendint):
    fptr = open(filename, "w")
    fptr.write(str(sendint))
    fptr.close()

def readfileint(filename):
    ptr = open(filename, "r")
    readstr = ptr.readline()
    return int(readstr)

def writebitvectofile(bitvec,filename):
    fptr = open(filename,"w")
    hexstring = bitvec.get_bitvector_in_hex()
    fptr.write(hexstring)
    fptr.close()

def writebvtoascii(filename, inputvec):
    print(inputvec.size)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(inputvec.get_bitvector_in_ascii())

def modinverse(a,b):# mult inverse of a mod b
    multinverse = BitVector(intVal = a)
    bvb = BitVector(intVal=b)
    multinverse.multiplicative_inverse(bvb)
    return multinverse.int_val()

def decrypt(bitvec,d,n): #appears to be identical to encrypt.... WHY IS THERE A 4-BIT RELATED ERROR WHEN IT'S DOING THE EXACT SAME PROCESS BUT WITHOUT THE FLUFF 128-ZEROS?
    tempbv = BitVector(intVal = pow(bitvec.int_val(),d,n),size=256)
    return tempbv[tempbv.size//2:tempbv.size]

def RSAdecrypt(filename,n,d):
    finbitvec = BitVector(size=0)
    fptr = open(filename,"r")
    readline = fptr.readline()
    bitvec = BitVector(hexstring = readline.rstrip())
    print(bitvec.size)
    #NOW ENCRYPT EVERY 256 bits!!!
    for i in range(0,len(bitvec),256):
        print(i)
        finbitvec+=(decrypt(bitvec[i:i+256],d,n))
        #print(i,i+256)
    #print("!",len(finbitvec),len(bitvec),"!")
    return finbitvec
# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    if (sys.argv[1] == "-g"):
        print("beginning key generation!")
        num_of_bits_desired = 128
        for i in range(2):
            prime = 0
            #print(sys.argv[1], sys.argv[2], sys.argv[3])
            while (math.gcd(prime,e) != 1):
                generator = PrimeGenerator(bits=num_of_bits_desired)
                prime = generator.findPrime()
            print("Prime returned: %d" % prime)
            writeinttofile(sys.argv[i+2],prime)
    if (sys.argv[1] == "-e"): #y -e message.txt p.txt q.txt encrypted.txt
        print(sys.argv[1], sys.argv[2], sys.argv[3],sys.argv[4],sys.argv[5])
        print("encryption time, baby")
        p = readfileint(sys.argv[3])
        q = readfileint(sys.argv[4])
        n = p*q
        phi = (p-1)*(q-1)
        bitvec = RSAencrypt(sys.argv[2], n)
        writebitvectofile(bitvec, sys.argv[5])
    if (sys.argv[1] == "-d"):
        print(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
        print("decryption time, baby")
        p = readfileint(sys.argv[3])
        q = readfileint(sys.argv[4])
        n = p*q
        phi = (p-1)*(q-1)
        d = modinverse(e,phi)
        bitvec = RSAdecrypt(sys.argv[2],n,d)
        writebvtoascii(sys.argv[5],bitvec)


    #RSAencrypt(filename)
    #message = inputtobv()

    print("!!")



#pow(base,exp,mod)
#c= pow(m,e,n)
#RSA GEN:
# X plaintext padded with 128 bits to the left
'''
X) generate primes p,q
X) n=pq
X) o(n)= (p-1)(q-1)
X) select e such that k<3<o(n) and gcd(o(n),p)=1 (confirm this works!!)
5) calculate d = e^-1mod(o(n))
pub key = e,n
priv key = d,n
priv exponent = d



loop through primegen until gcd(p-1,e)=gcd(q-1,e)=1
primegen ensures first 2 bits are set

'''