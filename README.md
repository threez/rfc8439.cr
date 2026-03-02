# rfc8439

Pure crystal implementation of the **ChaCha20** stream cipher and **Poly1305** authenticator defined in RFC 8439. Includes multiple backends with automatic compile-time selection of the fastest available.

## Architecture

Both ChaCha20 and Poly1305 expose abstract base classes (`Crypto::ChaCha20::Cipher`, `Crypto::Poly1305::MAC`) with multiple backend implementations. The best backend is selected at compile time and exposed as `Default`:

```
ChaCha20::Cipher (abstract)          Poly1305::MAC (abstract)
  ├── Native (pure Crystal)            ├── Native (BigInt)
  │     └── Neon (aarch64 SIMD)        ├── Fast (limb arithmetic)
  └── OpenSSL (>= 1.1.0)               └── OpenSSL (>= 3.0.0)
```

**Compile-time priority:**

| Component | 1st choice | 2nd choice | 3rd choice |
|---|---|---|---|
| ChaCha20 | OpenSSL (>= 1.1.0) | Neon (aarch64) | Native |
| Poly1305 | OpenSSL (>= 3.0.0) | Fast | - |

The factory methods (`Crypto::ChaCha20.new`, `Crypto::Poly1305.new`, `Crypto::Poly1305.chacha20`) return the abstract type using `Default`, so callers program against the common interface. You can also instantiate a specific backend directly (e.g. `Crypto::ChaCha20::Native.new`).

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     rfc8439:
       github: threez/rfc8439.cr
   ```

2. Run `shards install`

## Usage

### ChaCha20

```crystal
require "rfc8439"

# key and nonce are usually given using Bytes,
# but for convinience can be done as a hex string
key = "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f"
nonce = "00:00:00:09:00:00:00:4a:00:00:00:00"
msg = "Hello World".to_slice

cipher = Crypto::ChaCha20.new(key, nonce)
encrypted = cipher.encrypt(msg)

# encryption is done using XOR so decryption is done
# by encrypting the cypher text
cipher = Crypto::ChaCha20.new(key, nonce)
plaintext = cipher.encrypt(encrypted)

puts plaintext
```

### Poly1305

```crystal
require "rfc8439"

key = "85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b"
msg = "Cryptographic Forum Research Group".to_slice

mac = Crypto::Poly1305.new(key)
mac.update(msg)
tag = mac.final

puts tag
```

### AEADChaCha20Poly1305

Writes the cipher text to `ciphertext` an `IO` target and returns the
16 byte (128 bit) Tag for the text.

```crystal
require "rfc8439"

key = Crypto::Hex.bytes("00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f")
nonce = Crypto::Hex.bytes("00:00:00:09:00:00:00:4a:00:00:00:00")
ciphertext = IO::Memory.new
aead = Crypto::AeadChacha20Poly1305.new(key, nonce, ciphertext)
aead.aad("Header".to_slice)
aead.update("Hello World!".to_slice)
tag = aead.final

puts tag
```

## Benchmarks

Measured on Apple M1 Pro, Crystal 1.19.1, OpenSSL 3.6.1, compiled with `--release`:

```
                                    user     system      total        real
CHACHA20 Native (1GB)           1.546549   0.012450   1.558999 (  1.564214)
CHACHA20 NEON (1GB)             0.819080   0.006326   0.825406 (  0.827881)
CHACHA20 OpenSSL (1GB)          0.539303   0.006543   0.545846 (  0.549548)
POLY1305 Native (64MB)          0.547995   0.005824   0.553819 (  0.555176)
POLY1305 Fast (64MB)            0.041017   0.000254   0.041271 (  0.041274)
POLY1305 OpenSSL (64MB)         0.010014   0.000124   0.010138 (  0.010501)
AEAD_CHACHA20_POLY1305 (64MB)   0.047310   0.000826   0.048136 (  0.048204)
```

**Throughput (real time):**

| Backend | Throughput |
|---|---|
| ChaCha20 Native | ~654 MB/s |
| ChaCha20 NEON | ~1.24 GB/s |
| ChaCha20 OpenSSL | ~1.86 GB/s |
| Poly1305 Native | ~118 MB/s |
| Poly1305 Fast | ~1.58 GB/s |
| Poly1305 OpenSSL | ~6.23 GB/s |

Run benchmarks yourself:

```sh
crystal build bench/chacha20.cr --release -o bench/chacha20_bench && bench/chacha20_bench
```

## Contributing

1. Fork it (<https://github.com/threez/rfc8439/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Vincent Landgraf](https://github.com/threez) - creator and maintainer
