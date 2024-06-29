require "benchmark"
require "../src/rfc8439"

key = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
nonce = "00 00 00 00 00 00 00 00 00 00 00 00"
plaintext = Bytes.new(1024**2)

Benchmark.bm do |x|
  x.report("encrypt") do
    1024.times do
      chipher = Crypto::ChaCha20.new(key, nonce, 0)
      chipher.encrypt(plaintext)
    end
  end
end
