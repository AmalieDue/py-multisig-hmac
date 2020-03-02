#!/usr/bin/env python
# coding: utf-8

# In[ ]:

import os
import binascii
import base64
from hashlib import sha256, sha512, sha384
import hmac

class MultisigHMAC:
    
    SHA256_PRIMITIVE = sha256
    SHA256_KEYBYTES = sha256().block_size
    SHA256_BYTES = sha256().digest_size

    SHA512_PRIMITIVE = sha512
    SHA512_KEYBYTES = sha512().block_size
    SHA512_BYTES = sha512().digest_size

    SHA384_PRIMITIVE = sha384
    SHA384_KEYBYTES = sha384().block_size
    SHA384_BYTES = sha384().digest_size

    PRIMITIVE = SHA256_PRIMITIVE
    KEYBYTES = SHA256_KEYBYTES
    BYTES = SHA256_BYTES
    
    def __init__(self, alg = PRIMITIVE):
        h = alg()
        self.__bytes = h.digest_size
        self.__keybytes = h.block_size
        self.__alg = alg

    def keygen(self, index): # generates a new cryptographically random key
        key = os.urandom(self.__keybytes)
        return (index,key)
    
    def seedgen(self): # generates a new cryptographically random master seed
        return os.urandom(self.__keybytes)
    
    def deriveKey(self, masterSeed, index): # derives a new sub key from a master seed
        data = bytearray(b'derived')
        indexarray = index.to_bytes(length=4, byteorder='little')
        _scratch = data + indexarray
        h1 = hmac.new(masterSeed, _scratch, self.__alg) ; h1.update(bytearray([0])) ; h1.digest()
        h2 = hmac.new(masterSeed, h1.digest(), self.__alg) ; h2.update(bytearray([1])) ; h2.digest()
        return (index,h1.digest() + h2.digest())

    def popcount(self, x): # counts 1-bits, corresponding to the number of keys
        x = x - ((x >> 1) & 0x55555555)
        x = (x & 0x33333333) + ((x >> 2) & 0x33333333)
        x = (x + (x >> 4)) & 0x0F0F0F0F
        x = x + (x >> 8)
        x = x + (x >> 16)
        return x & 0x0000003F

    def keyIndexes(self, x): # x should be of type int. Returns the indexes of the keys
        xs = []
        i = 0
        while(x > 0):
            if(x & 0x1):
                xs.append(i)
            x >>= 1
            i += 1
        return xs

    def nlz(self, x): # counts number of leading zeros
        n = 32
        c = 16
        while(c != 0):
            y = x >> c
            if(y != 0):
                n = n - c
                x = y
            c = c >> 1
        return n - x

    def xorBytes(self, a, b):
        result = bytearray()
        for b1, b2 in zip(a, b):
            result.append(b1 ^ b2)
        return result

    def sign(self, keyObj, data): # signs data with key
        assert type(data) == bytes, "data must be bytes"
        digest = hmac.new(keyObj[1], data, self.__alg).digest()
        return (1 << keyObj[0], digest)

    def combine(self, signatures): # combines a list of signatures which have all been signed independently
        bitfield = 0
        sigs = bytearray(self.__bytes)
        for i in signatures:
            bitfield ^= i[0]
            sigs = self.xorBytes(sigs, i[1])
        assert self.popcount(bitfield) == len(signatures), "one or more signatures cancelled out"
        return (bitfield, sigs)

    def verify(self, keys, signature, data, threshold): # verifies signature of data against a list of keys
        assert len(signature[1]) == self.__bytes, "signature must be BYTES long" 
        assert type(data) == bytes, "data must be bytes"
        assert threshold > 0, "threshold must be at least 1"
        bitfield = signature[0]
        nKeys = self.popcount(bitfield)
        highestKey = 32 - self.nlz(bitfield)
        assert len(keys) >= nKeys and len(keys) >= highestKey, "Not enough keys given based on signature[0]"
        
        if (nKeys < threshold):
            return False

        usedKeys = self.keyIndexes(bitfield)
        sig = signature[1]
        for i in usedKeys:
            key = keys[i]
            keySig = self.sign(key, data)
            sig = self.xorBytes(sig, keySig[1])

            bitfield ^= keySig[0]

        return (bitfield == 0 and sum(sig) == 0)
    
    def verifyDerived(self, masterSeed, signature, data, threshold): #verifies signature of data against derived keys
        assert type(masterSeed) == bytes, "masterSeed must be bytes"
        assert len(masterSeed) == self.__keybytes, "masterSeed must be KEYBYTES long"
        assert len(signature[1]) == self.__bytes, "signature must be BYTES long"
        assert type(data) == bytes, "data must be bytes"
        assert threshold > 0, "threshold must be at least 1"
        bitfield = signature[0]
        nKeys = self.popcount(bitfield)
        
        if (nKeys < threshold):
            return False
        
        usedKeys = self.keyIndexes(bitfield)
        sig = signature[1]
        
        for i in range(len(usedKeys)):
            key = self.deriveKey(masterSeed, usedKeys[i])
            keySig = self.sign(key, data)
            sig = self.xorBytes(sig, keySig[1])
            
            bitfield ^= keySig[0]
        
        return (bitfield == 0 and sum(sig) == 0)

        