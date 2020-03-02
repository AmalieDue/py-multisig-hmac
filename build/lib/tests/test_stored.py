#!/usr/bin/env python
# coding: utf-8

# In[ ]:

import pytest
from multisig_hmac.multisig_hmac import MultisigHMAC
import base64

class TestStoredKeys(object):
    def test_simple(self):
        m = MultisigHMAC()

        key = m.keygen(0)
        assert type(key[0]) == int
        assert type(key[1]) == bytes
        assert len(key[1]) == MultisigHMAC.KEYBYTES

        # The data-input to the sign function has 3 equiv classes: empty, less than block size, larger than block size
        # These are tested below
        data_empty = b''
        data_short = b'hello world'
        data_long = data_short * 100
        s_empty = m.sign(key, data_empty)
        s_short = m.sign(key, data_short)
        s_long = m.sign(key, data_long)
        assert type(s_empty[0]) == int
        assert type(s_empty[1]) == bytes
        assert len(s_empty[1]) == MultisigHMAC.BYTES
        assert type(s_short[0]) == int
        assert type(s_short[1]) == bytes
        assert len(s_short[1]) == MultisigHMAC.BYTES
        assert type(s_long[0]) == int
        assert type(s_long[1]) == bytes
        assert len(s_long[1]) == MultisigHMAC.BYTES

        out = m.combine([s_empty])
        assert type(out[0]) == int
        assert type(out[1]) == bytearray
        assert len(out[1]) == MultisigHMAC.BYTES

    # The inputs to the verify function have more equiv classes

    def test_keys(self):
        # The following keys-inputs are tested:
        #  - no keys
        #  - missing some keys
        #  - too many keys
        #  - keys in random order
        #  - keys in right order

        m = MultisigHMAC()

        k0 = m.keygen(0)
        k1 = m.keygen(1)
        k2 = m.keygen(2)
        data = b''
        s0 = m.sign(k0, data)
        s2 = m.sign(k2, data)

        out = m.combine([s0, s2])

        # no keys
        keys = []
        with pytest.raises(AssertionError):
            assert m.verify(keys, out, data, 2)

        # missing some keys
        keys = [k0]
        with pytest.raises(AssertionError):
            assert m.verify(keys, out, data, 2)
        
        # too many keys
        keys = [k0, k1, k2]
        assert m.verify(keys, out, data, 2) # (success)

        # keys in random order
        keys = [k0, k2, k1]
        assert m.verify(keys, out, data, 2) == False

    def test_signature(self):
        # The following signature-inputs are tested:
        #  - empty signature
        #  - signature with wrong bitfield
        #  - signature with too many signatures
        #  - signature with too few signatures
        #  - signature with exactly correct signatures
        m = MultisigHMAC()

        k0 = m.keygen(0)
        k1 = m.keygen(1)
        k2 = m.keygen(2)
        data = b''
        s0 = m.sign(k0, data)
        s1 = m.sign(k1, data)
        s2 = m.sign(k2, data)

        out = m.combine([s0, s2])

        # empty signature
        keys = [k0, k1, k2]
        with pytest.raises(AssertionError):
            assert m.verify(keys, [out[0], b''], data, 2)

        # signature with wrong bitfield
        assert m.verify(keys, [0, out[1]], data, 2) == False

        # signature with too many signatures
        out_allkeys = m.combine([s0, s1, s2])
        assert m.verify(keys, [out[0], out_allkeys[1]], data, 2) == False

        # signature with too few signatures
        assert m.verify(keys, [out_allkeys[0], out[1]], data, 2) == False

    def test_data(self):
        # The following data-inputs are tested:
        #  - Same equiv classes as for the sign function
        #  - Incorrect data (len - 1, len, len + 1, wrong data)
        m = MultisigHMAC()

        k0 = m.keygen(0)
        k1 = m.keygen(1)
        
        # same equiv classes as for the sign function
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

        keys = [k0, k1]
        assert m.verify(keys, out_empty, data_empty, 2) # (success)
        assert m.verify(keys, out_short, data_short, 2) # (success)
        assert m.verify(keys, out_long, data_long, 2) # (success)

        # incorrect data
        data_wrong1 = b'hello worl'
        data_wrong2 = b'hello worldd'
        data_wrong3 = 'hello world'
        assert m.verify(keys, out_short, data_wrong1, 2) == False
        assert m.verify(keys, out_short, data_wrong2, 2) == False
        with pytest.raises(AssertionError):
            assert m.verify(keys, out_empty, data_wrong3, 2)

    def test_threshold(self):
        # The following threshold-inputs are tested:
        #  - -1
        #  - 0
        #  - 1
        #  - len(keys) - 1
        #  - len(keys)
        #  - len(keys) + 1
        #  - Some happy path
        m = MultisigHMAC()

        k0 = m.keygen(0)
        k1 = m.keygen(1)
        data = b''
        s0 = m.sign(k0, data)
        s1 = m.sign(k1, data)

        out = m.combine([s0, s1])

        keys = [k0, k1]
        # threshold = -1
        with pytest.raises(AssertionError):
            assert m.verify(keys, out, data, -1)

        # threshold = 0
        with pytest.raises(AssertionError):
            assert m.verify(keys, out, data, 0)

        # threshold = 1
        assert m.verify(keys, out, data, 1) # (success)

        # threshold = len(keys) - 1
        assert m.verify(keys, out, data, len(keys) - 1) # (success, unless len(keys) = 1)

        # threshold = len(keys)
        assert m.verify(keys, out, data, len(keys)) # (success)

        # threshold = len(keys) + 1
        assert m.verify(keys, out, data, len(keys) + 1) == False

    def test_success(self):
        m = MultisigHMAC()

        k0 = m.keygen(0)
        k1 = m.keygen(1)
        k2 = m.keygen(2)

        data = b'hello world'

        s0 = m.sign(k0, data)
        s2 = m.sign(k2, data)

        out = m.combine([s0,s2])

        sent = (out[0], base64.urlsafe_b64encode(out[1]))

        # --- network ---

        received = (sent[0], base64.urlsafe_b64decode(sent[1]))

        threshold = 2
        keys = [k0, k1, k2]
        signature = received

        assert m.verify(keys, signature, data, threshold) # (success)

