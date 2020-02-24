#!/usr/bin/env python
# coding: utf-8

# In[ ]:

import os, sys
sys.path.insert(0, os.path.abspath(".."))

from multisig_hmac_python_code import MultisigHMAC

import base64

# Example
m = MultisigHMAC()

k0 = m.keygen(0)
k1 = m.keygen(1)
k2 = m.keygen(2)
k3 = m.keygen(3)
k4 = m.keygen(4)

data = b'Hello world'

s0 = m.sign(k0, data)
s1 = m.sign(k1, data)
s2 = m.sign(k2, data)
s3 = m.sign(k3, data)
s4 = m.sign(k4, data)

out = m.combine([s1,s3,s4])

sent = (out[0], base64.urlsafe_b64encode(out[1]))

# --- network ---

received = (sent[0], base64.urlsafe_b64decode(sent[1]))

threshold = 3
keys = [k0, k1, k2, k3, k4]
signature = received

print(m.verify(keys, signature, data, threshold))

