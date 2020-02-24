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

        # Data has 3 equiv classes: empty, less than block size, larger than block size
        data = b''
        s0 = m.sign(key, data)
        assert type(s0[0]) == int
        assert type(s0[1]) == bytes
        assert len(s0[1]) == MultisigHMAC.BYTES

        out = m.combine([s0])
        assert type(out[0]) == int
        assert type(out[1]) == bytearray
        assert len(out[1]) == MultisigHMAC.BYTES

        # Verify has more equiv classes
        # Keys:
        #  - no keys
        #  - missing some keys
        #  - too many keys
        #  - keys in random order
        #  - keys in right order (happy path)
        # Signature:
        #  - empty signature
        #  - signature with wrong bitfield
        #  - signature with too many signatures
        #  - signature with too few signatures
        #  - signature with exactly correct signatures
        # Data:
        #  - Same equiv as for sign
        #  - Incorrect data (len - 1, len, len + 1, wrong data)
        # Threshold:
        #  - -1
        #  - 0
        #  - 1
        #  - len(keys) - 1
        #  - len(keys)
        #  - len(keys) + 1
        #  - Some happy path

    def test_keys(self):
        m = MultisigHMAC()

        k0 = m.keygen(0)
        k1 = m.keygen(1)
        k2 = m.keygen(2)
        data = b''
        s0 = m.sign(k0, data)
        s2 = m.sign(k2, data)

        out = m.combine([s0, s2])

        keys = [k0, k1, k2]
        #with pytest.raises(AssertionError):
        #    assert m.verify(0, out[1], data, 2)

    def test_data(self):
        m = MultisigHMAC()

        k0 = m.keygen(0)
        data = ''
        with pytest.raises(AssertionError):
            assert m.sign(k0, data)

    def test_threshold(self):
        m = MultisigHMAC()

        k0 = m.keygen(0)
        k1 = m.keygen(1)
        data = b''
        s0 = m.sign(k0, data)
        s1 = m.sign(k1, data)

        out = m.combine([s0, s1])

        threshold = -1
        with pytest.raises(AssertionError):
            assert m.verify(out[0], out[1], data, threshold)

        threshold = 0
        with pytest.raises(AssertionError):
            assert m.verify(out[0], out[1], data, threshold)

        #threshold = m.popcount(out[0])
        with pytest.raises(AssertionError):
            assert m.verify(out[0], out[1], data, threshold)

    def test_happy_path(self):
        m = MultisigHMAC()

        k0 = m.keygen(0)
        k1 = m.keygen(1)
        k2 = m.keygen(2)
        k3 = m.keygen(3)

        data = b'Hello world'

        s0 = m.sign(k0, data)
        s1 = m.sign(k1, data)
        s3 = m.sign(k3, data)

        out = m.combine([s0,s1,s3])

        sent = (out[0], base64.urlsafe_b64encode(out[1]))

        # --- network ---

        received = (sent[0], base64.urlsafe_b64decode(sent[1]))

        threshold = 2
        keys = [k0, k1, k2, k3]
        signature = received

        assert m.verify(keys, signature, data, threshold) == True

