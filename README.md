# multisig-hmac-python-version

> Multisig scheme for HMAC authentication. Python implementation of [multisig-hmac](https://github.com/emilbayes/multisig-hmac).

Work in progress

## Usage
Key management can happen in either of two modes, either by storing every of the component keys, or by storing a single master seed and using that to derive keys ad hoc.

Using stored keys:

```python
from multisig_hmac.multisig_hmac import MultisigHMAC
import base64

m = MultisigHMAC()

# generate keys which need to be stored securely and need to be shared securely with each party
k0 = m.keygen(0)
k1 = m.keygen(1)
k2 = m.keygen(2)

# sign by each client with 2-of-3
data = b'hello world'

s0 = m.sign(k0, data)
s2 = m.sign(k2, data)

# combine the used signatures
out = m.combine([s0, s2])

sent = (out[0], base64.urlsafe_b64encode(out[1]))

# --- network ---

received = (sent[0], base64.urlsafe_b64decode(sent[1]))

# verify on the server
threshold = 2
keys = [k0, k1, k2]
signature = received

m.verify(keys, signature, data, threshold)

```

Using a derived master key:

```python
from multisig_hmac.multisig_hmac import MultisigHMAC
import base64

m = MultisigHMAC()

# generate a master seed which needs to be stored securely
# this seed must NOT be shared with any other party
seed = m.seedgen()

k0 = m.deriveKey(seed, 0)
k1 = m.deriveKey(seed, 1)
k2 = m.deriveKey(seed, 2)

# sign by each client with 2-of-3
data = b'hello world'

s0 = m.sign(k0, data)
s2 = m.sign(k2, data)

# combine the used signatures
out = m.combine([s0, s2])

sent = (out[0], base64.urlsafe_b64encode(out[1]))

# --- network ---

received = (sent[0], base64.urlsafe_b64decode(sent[1]))

# verify on the server, but now keys are dynamically derived
threshold = 2
signature = received

m.verifyDerived(seed, signature, data, threshold)

```

## Installation
```console
$ pip install multisig-hmac
```

## Running tests
```console
$ pip install -U pytest
$ py.test
```

## License

[ISC](LICENSE)
