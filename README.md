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
Returns the number of keys (i.e. high bits) in `bitfield`. `bitfield` must be a 32-bit unsigned integer. Example:
```python
assert MultisigHMAC.popcount(5) == 2
```

### `xs = MultisigHMAC.keyIndexes(bitfield)`
Returns the indexes of the keys (i.e. high bits) in `bitfield` as a list. `bitfield` must be a 32-bit unsigned integer. Example:
```python
assert MultisigHMAC.keyIndexes(5) == [0,2]
```

### `m = MultisigHMAC([alg = MultisigHMAC.PRIMITIVE])`
Create a new instance of `MultisigHMAC` which can be used as a global singleton. Just sets the algorithm to be used for subsequent methods and associated constants. Example:
```python
m = MultisigHMAC()
assert (m.popcount(5) == 2 and m.keyIndexes(5) == [0,2])
```

### `key = MultisigHMAC.keygen(index)`
Generate a new cryptographically random key. The function returns `{ index: 32-bit unsigned integer, key: bytes of length MultisigHMAC.KEYBYTES }`.

Note: `index` should be counted from 0.

### `masterSeed = MultisigHMAC.seedgen()`
Generate a new cryptographically random master seed. Example:
```python
masterSeed = MultisigHMAC.seedgen()

masterSeed

    b'a"f-\xe7\xe8\xbe\xc7yY\xdc|\xe1\xca\xf3ry9\xc7\xf2\xa4\r\xe3\xcc\xd9\xdd\xf6J\xeeP*\x0f\xce\t\xed\x80\xc3\x00\xe3\x86~\x93s\xe7\x10`\xd7\x1a\x1b\xa0d`\xbfQ7\x00\xc9I\\\xaa\xf3\xeb\xe4\xbc'
```

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
