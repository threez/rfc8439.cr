require "./poly1305/mac"
require "./poly1305/native"
require "./poly1305/fast"
require "./poly1305/openssl"

module Crypto::Poly1305
  BLOCK_SIZE = 16

  {% if compare_versions(LibCrypto::OPENSSL_VERSION, "3.0.0") >= 0 %}
    alias Default = OpenSSL
  {% else %}
    alias Default = Fast
  {% end %}

  def self.new(key : Bytes) : MAC
    Default.new(key)
  end

  def self.new(key : String) : MAC
    Default.new(key)
  end

  def self.auth(key : Bytes, message : Bytes) : Bytes
    Default.auth(key, message)
  end

  def self.chacha20(key : Bytes, nonce : Bytes) : MAC
    Default.chacha20(key, nonce)
  end

  def self.chacha20(cipher : ChaCha20::Cipher) : MAC
    Default.chacha20(cipher)
  end
end
