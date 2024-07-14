require "benchmark"
require "../src/rfc8439"

key = Bytes.new(32, 0x00)
nonce = Bytes.new(12, 0x00)
plaintext = Bytes.new(1024**2)
encrypted = Bytes.new(1024**2)

Benchmark.bm do |x|
  x.report("encrypt") do
    1024.times do
      cipher = Crypto::ChaCha20.new(key, nonce, 0)
      cipher.encrypt(plaintext, encrypted)
    end
  end
end
