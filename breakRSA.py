# Homework Number: 06
# Name: Ziro Petro
# ECN Login: petrop
# Due Date: March 09 2020
# Python Interpreter: Python 3.8

#globals
#e = 65537
e = 3

from BitVector import *
import sys
import random
import math
from functools import reduce


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


def readprimes(filename):
    temparr = []
    fptr = open(filename, 'r')
    prime = fptr.readline()
    temparr.append(int(prime.rstrip()))
    prime = fptr.readline()
    temparr.append(int(prime.rstrip()))
    prime = fptr.readline()
    temparr.append(int(prime.rstrip()))
    return temparr

def chinese_remainder(n, a): #chinese remainder theorem implementation by Fangya, https://fangya.medium.com/chinese-remainder-theorem-with-python-a483de81fbb8
    sum=0
    prod=reduce(lambda a, b: a*b, n)
    for n_i, a_i in zip(n,a):
        p=prod//n_i
        sum += a_i* mul_inv(p, n_i)*p
    return sum % prod
def mul_inv(a, b):
    b0= b
    x0, x1= 0,1
    if b== 1: return 1
    while a>1 :
        q=a// b
        a, b= b, a%b
        x0, x1=x1 -q *x0, x0
    if x1<0 : x1+= b0
    return x1

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

def writebitvectofile(bitvec,filename):
    fptr = open(filename,"w")
    hexstring = bitvec.get_bitvector_in_hex()
    fptr.write(hexstring)
    fptr.close()

def bvfromhex(filename):
    fptr = open(filename,"r")
    hexline = fptr.readline()
    bitvec = BitVector(hexstring = hexline.rstrip())
    return bitvec

def writebvtoascii(filename, inputvec):
    with open(filename, "w", encoding="utf-8") as f:
        f.write(inputvec.get_bitvector_in_ascii())


if __name__ == '__main__':
    print("test")
    if (sys.argv[1] == "-e"):
        print(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5],sys.argv[6])
        #generate p,q
        primearr = []
        num_of_bits_desired = 128
        for i in range(6):
            prime = 0
            #print(sys.argv[1], sys.argv[2], sys.argv[3])
            while (math.gcd(prime,e) != 1):
                generator = PrimeGenerator(bits=num_of_bits_desired)
                prime = generator.findPrime()
            print("Prime returned: %d" % prime)
            primearr.append(prime)

        #generate n's
        narr = []
        for i in range(0,len(primearr),2):
            narr.append(primearr[i]*primearr[i+1])

        for i in range(len(narr)):
            bitvec = RSAencrypt(sys.argv[2], int(narr[i]))
            writebitvectofile(bitvec, sys.argv[i+3])
            print(i+3)
    if (sys.argv[1] == "-c"):
        print("let's get crackin'")
        print(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5],sys.argv[6])
        narr = readprimes(sys.argv[5])
        enc1 = bvfromhex(sys.argv[2])
        enc2 = bvfromhex(sys.argv[3])
        enc3 = bvfromhex(sys.argv[4])
        encarr = []
        encarr.append(enc1.int_val())
        encarr.append(enc2.int_val())
        encarr.append(enc3.int_val())
        Me = chinese_remainder(narr,encarr)
        M=pow(10,math.log(Me)/e)
        print(M)
        Mbitvector = BitVector(intVal=int(M))
        for i in range(8 - len(Mbitvector) % 8):
            Mbitvector.pad_from_right(1)
        writebvtoascii(sys.argv[6],Mbitvector)