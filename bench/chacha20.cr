require "benchmark"
require "../src/rfc8439"
require "openssl"

key = Bytes.new(32, 0xfe)
nonce12 = Bytes.new(12, 0xfe)
nonce16 = Bytes.new(16, 0xfe)
plaintext = Bytes.new(1024**2)
encrypted = Bytes.new(1024**2)

Benchmark.bm do |x|
  x.report("CHACHA20 Native (1GB)") do
    1024.times do
      cipher = Crypto::ChaCha20.new(key, nonce12, 0)
      cipher.encrypt(plaintext, encrypted)
    end
  end

  x.report("CHACHA20 OpenSSL (1GB)") do
    1024.times do
      cipher = OpenSSL::Cipher.new("chacha20")
      cipher.encrypt
      cipher.key = key
      cipher.iv = nonce16
      cipher.update(plaintext) + cipher.final
    end
  end

  x.report("POLY1305 Native (64MB)") do
    64.times do
      mac = Crypto::Poly1305.chacha20(key, nonce12)
      mac.update(encrypted)
      mac.final
    end
  end

  x.report("AEAD_CHACHA20_POLY1305 (64MB)") do
    64.times do
      mem = IO::Memory.new
      aead = Crypto::AeadChacha20Poly1305.new(key, nonce12, mem)
      aead.update(plaintext)
      aead.final
    end
  end
end
