# multisig-hmac

> Multisig scheme for HMAC authentication. Python implementation of [multisig-hmac](https://github.com/emilbayes/multisig-hmac).

## Usage
Key management can happen in either of two modes, either by storing every of the component keys, or by storing a single master seed and using that to derive keys ad hoc.

The following two examples return `true` when they are executed, for example inside a virtual environment.

Using stored keys:

```python
import multisig_hmac
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

print(m.verify(keys, signature, data, threshold))

```

Using a derived master key:

```python
import multisig_hmac
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

print(m.verifyDerived(seed, signature, data, threshold))

```

## API
### Constants
* `MultisigHMAC.BYTES` signature length in bytes (default)
* `MultisigHMAC.KEYBYTES` key length in bytes (default)
* `MultisigHMAC.PRIMITIVE` is `sha256` (default)

Specific algorithms:
* `MultisigHMAC.SHA256_BYTES` signature length in bytes
* `MultisigHMAC.SHA256_KEYBYTES` key length in bytes
* `MultisigHMAC.SHA256_PRIMITIVE` is `sha256`
* `MultisigHMAC.SHA512_BYTES` signature length in bytes
* `MultisigHMAC.SHA512_KEYBYTES` key length in bytes
* `MultisigHMAC.SHA512_PRIMITIVE` is `sha512`
* `MultisigHMAC.SHA384_BYTES` signature length in bytes
* `MultisigHMAC.SHA384_KEYBYTES` key length in bytes
* `MultisigHMAC.SHA384_PRIMITIVE` is `sha384`

### `n = MultisigHMAC.popcount(bitfield)`
Returns the number of keys (i.e. high bits) in `bitfield`. `bitfield` must be a 32-bit unsigned integer.
Example:
```python
assert MultisigHMAC.keysCount(3) == 2
```
### `xs = MultisigHMAC.keyIndexes(bitfield`

### `m = MultisigHMAC([alg = MultisigHMAC.PRIMITIVE])`

### `key = MultisigHMAC.keygen(index)`

### `masterSeed = MultisigHMAC.seedgen()`

### `key = MultisigHMAC.deriveKey(masterSeed, index)`

### `signature = MultisigHMAC.sign(key, data)`

### `signature = MultisigHMAC.combine([signatures...])`

### `valid = MultisigHMAC.verify(keys, signature, data, threshold)`

### `valid = MultisigHMAC.verifyDerived(masterSeed, signature, data, threshold)`

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
