# rfc8439

ChaCha20 stream cipher as well as the use of the Poly1305 authenticator
defined in rfc8439.

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     rfc8439:
       github: threez/rfc8439.cr
   ```

2. Run `shards install`

## Usage

```crystal
require "rfc8439"


key = "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f"
nonce = "00:00:00:09:00:00:00:4a:00:00:00:00"

chipher = Crypto::ChaCha20.new(key, nonce)
encrypted = chipher.encrypt("Hello World")

chipher = Crypto::ChaCha20.new(key, nonce)
plaintext = chipher.decrypt(encrypted)

puts plaintext
```

## Contributing

1. Fork it (<https://github.com/threez/rfc8439/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Vincent Landgraf](https://github.com/threez) - creator and maintainer
