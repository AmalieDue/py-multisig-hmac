#!/usr/bin/env python
# coding: utf-8

# In[ ]:

import pytest
from multisig_hmac.multisig_hmac import MultisigHMAC
import base64

class TestDerivedKeys(object):
    def test_simple(self):
        m = MultisigHMAC() # ...

    def test_success(self):
        m = MultisigHMAC()

        seed = m.seedgen()

        k0 = m.deriveKey(seed, 0)
        k1 = m.deriveKey(seed, 1)
        k2 = m.deriveKey(seed, 2)

        data = b'hello world'

        s0 = m.sign(k0, data)
        s2 = m.sign(k2, data)

        out = m.combine([s0, s2])

        sent = (out[0], base64.urlsafe_b64encode(out[1]))

        # --- network ---

        received = (sent[0], base64.urlsafe_b64decode(sent[1]))

        threshold = 2
        signature = received

        assert m.verifyDerived(seed, signature, data, threshold)

        