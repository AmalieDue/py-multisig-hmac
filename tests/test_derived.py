#!/usr/bin/env python
# coding: utf-8

# In[ ]:

import pytest
from multisig_hmac.multisig_hmac import MultisigHMAC
import base64

class TestDerivedKeys(object):

    # Inputs to the verifyDerived function have the following equiv classes

    def test_masterseed(self):
        # masterseed:
        # - no masterseed
        # - incorrect masterseed (len - 1, len, len + 1, wrong)
        # - correct masterseed

        m = MultisigHMAC()

        seed = m.seedgen()

        k0 = m.deriveKey(seed, 0)
        k2 = m.deriveKey(seed, 2)

        data = b''

        s0 = m.sign(k0, data)
        s2 = m.sign(k2, data)
        out = m.combine([s0, s2])

        # no masterseed
        with pytest.raises(AssertionError):
            assert m.verifyDerived(b'', out, data, 2)

        # len - 1
        seed_minus1 = seed[:-1]
        with pytest.raises(AssertionError):
            assert m.verifyDerived(seed_minus1, out, data, 2)

        # len + 1
        seed_plus1 = seed + b'\x00'
        with pytest.raises(AssertionError):
            assert m.verifyDerived(seed_plus1, out, data, 2)

        # wrong masterSeed
        seed_new = m.seedgen()
        assert m.verifyDerived(seed_new, out, data, 2) == False

    def test_signature(self):
        # signature:
        # - empty signature
        # - signature with wrong bitfield
        # - signature with too many signatures
        # - signature with too few signatures
        # - signature with exactly correct signatures
        
        m = MultisigHMAC()

        seed = m.seedgen()

        k0 = m.deriveKey(seed, 0)
        k1 = m.deriveKey(seed, 1)
        k2 = m.deriveKey(seed, 2)
        data = b''
        s0 = m.sign(k0, data)
        s1 = m.sign(k1, data)
        s2 = m.sign(k2, data)

        out = m.combine([s0, s2])

        # empty signature
        with pytest.raises(AssertionError):
            assert m.verifyDerived(seed, [out[0], b''], data, 2)

        # signature with wrong bitfield
        assert m.verifyDerived(seed, [0, out[1]], data, 2) == False

        # signature with too many signatures
        out_allkeys = m.combine([s0, s1, s2])
        assert m.verifyDerived(seed, [out[0], out_allkeys[1]], data, 2) == False

        # signature with too few signatures
        assert m.verifyDerived(seed, [out_allkeys[0], out[1]], data, 2) == False

    def test_data(self):
        # data:
        # - empty, less than block size, larger than block size
        # - incorrect data (len - 1, len, len + 1, wrong data)

        m = MultisigHMAC()

        seed = m.seedgen()

        k0 = m.deriveKey(seed, 0)
        k1 = m.deriveKey(seed, 1)

        # empty, less than block size, larger than block size
        data_empty = b''
        data_short = b'hello world'
        data_long = data_short * 100

        s0_empty = m.sign(k0, data_empty)
        s1_empty = m.sign(k1, data_empty)
        s0_short = m.sign(k0, data_short)
        s1_short = m.sign(k1, data_short)
        s0_long = m.sign(k0, data_long)
        s1_long = m.sign(k1, data_long)

        out_empty = m.combine([s0_empty, s1_empty])
        out_short = m.combine([s0_short, s1_short])
        out_long = m.combine([s0_long, s1_long])

        assert m.verifyDerived(seed, out_empty, data_empty, 2) # (success)
        assert m.verifyDerived(seed, out_short, data_short, 2) # (success)
        assert m.verifyDerived(seed, out_long, data_long, 2) # (success)

        # incorrect data
        data_wrong1 = b'hello worl'
        data_wrong2 = b'hello worldd'
        data_wrong3 = 'hello world'
        assert m.verifyDerived(seed, out_short, data_wrong1, 2) == False
        assert m.verifyDerived(seed, out_short, data_wrong2, 2) == False
        with pytest.raises(AssertionError):
            assert m.verifyDerived(seed, out_short, data_wrong3, 2)

    def test_threshold(self):
        # threshold:
        # - -1
        # - 0 
        # - 1
        # - len(keys) - 1
        # - len(keys)
        # - len(keys) + 1
        # - some happy path

        m = MultisigHMAC()

        seed = m.seedgen()

        k0 = m.deriveKey(seed, 0)
        k1 = m.deriveKey(seed, 1)
        data = b''
        s0 = m.sign(k0, data)
        s1 = m.sign(k1, data)

        out = m.combine([s0, s1])

        # threshold = -1
        with pytest.raises(AssertionError):
            assert m.verifyDerived(seed, out, data, -1)
        
        # threshold = 0
        with pytest.raises(AssertionError):
            assert m.verifyDerived(seed, out, data, 0)

        # threshold = 1
        assert m.verifyDerived(seed, out, data, 1) # (success)

        # threshold = len(keys) - 1
        keys = [k0, k1]
        assert m.verifyDerived(seed, out, data, len(keys) - 1) # (success, unless len(keys) = 1)

        # threshold = len(keys)
        assert m.verifyDerived(seed, out, data, len(keys)) # (success)

        # threshold = len(keys) + 1
        assert m.verifyDerived(seed, out, data, len(keys) + 1) == False

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

        