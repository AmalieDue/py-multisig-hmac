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
k1 = m.keygen()
k2 = m.keygen()
k3 = m.keygen()

# sign by each client with 2-of-3
data = b'Hello world'

s1 = m.sign(k1, data)
s3 = m.sign(k3, data)

# combine the used signatures
out = m.combine([s1, s3])

sent = (out[0], base64.urlsafe_b64encode(out[1]))

# --- network ---

received = (sent[0], base64.urlsafe_b64decode(sent[1]))

# verify on the server
threshold = 2
keys = [k1, k2, k3]
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

k1 = m.keygen()
k2 = m.keygen()
k3 = m.keygen()

# sign by each client with 2-of-3
data = b'Hello world'

s1 = m.sign(k1, data)
s3 = m.sign(k3, data)

# combine the used signatures
out = m.combine([s1, s3])

sent = (out[0], base64.urlsafe_b64encode(out[1]))

# --- network ---

received = (sent[0], base64.urlsafe_b64decode(sent[1]))

# verify on the server, but now keys are dynamically derived
threshold = 2
keys = [k1, k2, k3]
signature = received

m.verifyDerived(keys, signature, data, threshold)

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
