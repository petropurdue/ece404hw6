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

def readprimes(filename):
    temparr = []
    fptr = open(filename, 'r')
    temparr.append(fptr.readline())
    temparr.append(fptr.readline())
    temparr.append(fptr.readline())
    return temparr


if __name__ == '__main__':
    print("test")
    if (sys.argv[1] == "-e"):
        print(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5],sys.argv[6])
        primearr = readprimes(sys.argv[6])
    if (sys.argv[1] == "-c"):
        print("uwu")