# Homework Number: 06
# Name: Ziro Petro
# ECN Login: petrop
# Due Date: March 09 2020
# Python Interpreter: Python 3.8

#globals
e = 65537

from BitVector import *

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print("AAAA")


pow(base,exp,mod)

#RSA KEYGEN:
'''
1) generate primes p,q
2) n=pq
3) o(n)= (p-1)(q-1)
4) select e such that k<3<o(n) and gcd(o(n),p)=1 
5) calculate d = e^-1mod(o(n))
pub key = e,n
priv key = d,n
priv exponent = d

'''