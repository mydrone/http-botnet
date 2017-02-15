#!/usr/bin/env python
import os
f = "http_botnet.cpp" #// name
os.system("g++ -std=c++11  -pthread -O2 " + format(f) + "  -L/usr/local/lib -lcurl -lssl  -lcrypto -lboost_system -lz -ldl -o " + format(f.replace(".cpp", "")))
os.system("chmod 777 " + format(f.replace(".cpp", "")))
r = input("Do you want to run this file?: ")
if r == "y" or r == "yes":
    os.system("./" + format(f.replace(".cpp", "")))
