#!/usr/bin/python3
#20171014
#WEP crack exercise for crypto 300
#Mark Nesbitt

import socket

def getCT(bytestring):
    #byte string format: b'AA AB AC'
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("172.19.5.133",6000))
    s.sendall(bytestring)
    reply = s.recv(1000)
    altreply = str(reply)[4:6]
    return altreply

def most_common(alist):
    return max(set(alist), key=alist.count)

def mostCommon(ivindex, prevkeys):
    results = []
    for i in range(256):
        iv = format(ivindex,'#04x')[2:] +' '+ format(255, '#04x')[2:]+' ' + format(i,'#04x')[2:]
        thisCT = getCT(iv.encode())
        decimalCT = int(thisCT, 16)
        firstkeystreambyte = 170 ^ decimalCT
        w0 = (firstkeystreambyte - ivindex*(ivindex+1)/2 - i - prevkeys)%256
        results.append(w0)
    return most_common(results), results.index(most_common(results)), format(int(most_common(results)), '#04x') , results.count(most_common(results))

def main():
    #key is deadbeef\n 22,173,190,239,0
    keytotal = 0
    key = ''
    for i in range(3,8):
        deckey , ivvalue , hexkey , count = mostCommon(i, keytotal)
        keytotal += deckey 
        key += hexkey[2:]
    print("Final key is", key)

if __name__ == '__main__':
    main()
