require "openssl"

{% if compare_versions(LibCrypto::OPENSSL_VERSION, "1.1.0") >= 0 %}
  # OpenSSL-backed ChaCha20 backend.
  # Wraps OpenSSL::Cipher for hardware-accelerated encryption where available.
  class Crypto::ChaCha20::OpenSSL < Crypto::ChaCha20::Cipher
    BLOCK_SIZE = Crypto::ChaCha20::BLOCK_SIZE

    def initialize(@key : Bytes, @nonce : Bytes, @counter : UInt32 = 0_u32)
      raise "key needs to be 32 bytes" unless @key.size == 32
      raise "nonce needs to be 12 bytes" unless @nonce.size == 12
    end

    def initialize(key : String, nonce : String, counter : UInt32 = 0_u32)
      initialize(Crypto::Hex.bytes(key), Crypto::Hex.bytes(nonce), counter)
    end

    def encrypt(plaintext : Bytes) : Bytes
      cipher = ::OpenSSL::Cipher.new("chacha20")
      cipher.encrypt
      cipher.key = @key
      cipher.iv = make_iv
      blocks = (plaintext.size + BLOCK_SIZE - 1) // BLOCK_SIZE
      @counter &+= blocks.to_u32
      cipher.update(plaintext) + cipher.final
    end

    def encrypt(plaintext : Bytes, encrypted : Bytes) : Nil
      raise "encrypted needs to be multiple of #{BLOCK_SIZE}" unless encrypted.size % BLOCK_SIZE == 0

      # Copy plaintext into encrypted buffer (pad remainder with zeros)
      encrypted.copy_from(plaintext)
      if plaintext.size < encrypted.size
        encrypted[plaintext.size..].fill(0_u8)
      end

      cipher = ::OpenSSL::Cipher.new("chacha20")
      cipher.encrypt
      cipher.key = @key
      cipher.iv = make_iv
      result = cipher.update(encrypted) + cipher.final
      encrypted.copy_from(result)

      blocks = encrypted.size // BLOCK_SIZE
      @counter &+= blocks.to_u32
    end

    def next_key_block : UInt32[16]
      zeros = Bytes.new(BLOCK_SIZE, 0_u8)
      cipher = ::OpenSSL::Cipher.new("chacha20")
      cipher.encrypt
      cipher.key = @key
      cipher.iv = make_iv
      keystream = cipher.update(zeros) + cipher.final
      @counter &+= 1

      block = uninitialized UInt32[16]
      16.times do |i|
        block[i] = IO::ByteFormat::LittleEndian.decode(UInt32, keystream[i &* 4, 4])
      end
      block
    end

    def clone
      klone = self.class.new(@key.dup, @nonce.dup, @counter)
      klone.reset
      klone
    end

    def reset
      @counter = 0_u32
    end

    private def make_iv : Bytes
      iv = Bytes.new(16)
      IO::ByteFormat::LittleEndian.encode(@counter, iv[0, 4])
      iv[4, 12].copy_from(@nonce)
      iv
    end
  end
{% end %}
