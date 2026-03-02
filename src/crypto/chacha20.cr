require "./chacha20/cipher"
require "./chacha20/native"
{% if flag?(:aarch64) %}
  require "./chacha20/neon"
{% end %}
require "./chacha20/openssl"

module Crypto::ChaCha20
  BLOCK_SIZE = 64

  {% if compare_versions(LibCrypto::OPENSSL_VERSION, "1.1.0") >= 0 %}
    alias Default = OpenSSL
  {% elsif flag?(:aarch64) %}
    alias Default = Neon
  {% else %}
    alias Default = Native
  {% end %}

  def self.new(key : Bytes, nonce : Bytes, counter : UInt32 = 0_u32) : Cipher
    Default.new(key, nonce, counter)
  end

  def self.new(key : String, nonce : String, counter : UInt32 = 0_u32) : Cipher
    Default.new(key, nonce, counter)
  end

  # :nodoc:
  # converts a block to bytes
  def self.block_bytes(block : UInt32[16], be : Bool = true) : Bytes
    block_bytes = Bytes.new(block.size &* 4)
    block.each_with_index do |val, i|
      block_slice = block_bytes[(i &* 4)..((i &+ 1) &* 4 &- 1)]
      if be
        IO::ByteFormat::BigEndian.encode(val, block_slice)
      else
        IO::ByteFormat::LittleEndian.encode(val, block_slice)
      end
    end
    block_bytes
  end
end
