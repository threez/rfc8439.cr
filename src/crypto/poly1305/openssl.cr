require "openssl"
require "../chacha20"

{% if compare_versions(LibCrypto::OPENSSL_VERSION, "3.0.0") >= 0 %}

lib LibCrypto
  fun evp_mac_fetch = EVP_MAC_fetch(libctx : Void*, algorithm : LibC::Char*, properties : LibC::Char*) : Void*
  fun evp_mac_free = EVP_MAC_free(mac : Void*)
  fun evp_mac_ctx_new = EVP_MAC_CTX_new(mac : Void*) : Void*
  fun evp_mac_ctx_free = EVP_MAC_CTX_free(ctx : Void*)
  fun evp_mac_init = EVP_MAC_init(ctx : Void*, key : UInt8*, keylen : LibC::SizeT, params : Void*) : LibC::Int
  fun evp_mac_update = EVP_MAC_update(ctx : Void*, data : UInt8*, datalen : LibC::SizeT) : LibC::Int
  fun evp_mac_final = EVP_MAC_final(ctx : Void*, tag_out : UInt8*, outl : LibC::SizeT*, outsize : LibC::SizeT) : LibC::Int
end

# Poly1305 message authentication code (OpenSSL EVP_MAC backend).
class Crypto::Poly1305::OpenSSL < Crypto::Poly1305::MAC
  BLOCK_SIZE = 16

  getter key : Bytes

  # Generating the Poly1305 Key Using ChaCha20
  def self.chacha20(key : Bytes, nonce : Bytes) : self
    chacha20(Crypto::ChaCha20.new(key, nonce))
  end

  # Generating the Poly1305 Key Using ChaCha20
  def self.chacha20(cipher : ChaCha20::Cipher) : self
    block = Crypto::ChaCha20.block_bytes(cipher.clone.next_key_block, false)
    new(block[0..31])
  end

  # Initializes the Poly1305 context with a given 32-byte key.
  def initialize(@key : Bytes)
    raise "key needs to be 256 bits (32 bytes)" if @key.size != 32

    @mac = LibCrypto.evp_mac_fetch(Pointer(Void).null, "POLY1305", Pointer(LibC::Char).null)
    raise "EVP_MAC_fetch failed" if @mac.null?

    @ctx = LibCrypto.evp_mac_ctx_new(@mac)
    if @ctx.null?
      LibCrypto.evp_mac_free(@mac)
      raise "EVP_MAC_CTX_new failed"
    end

    rc = LibCrypto.evp_mac_init(@ctx, @key, @key.size, Pointer(Void).null)
    if rc != 1
      LibCrypto.evp_mac_ctx_free(@ctx)
      LibCrypto.evp_mac_free(@mac)
      raise "EVP_MAC_init failed"
    end

    @finalized = false
  end

  # Initializes the Poly1305 context with a given 32-byte **hex-encoded** key.
  def initialize(key : String)
    initialize(Crypto::Hex.bytes(key))
  end

  # Processes a message fragment.
  def update(msg : Bytes)
    rc = LibCrypto.evp_mac_update(@ctx, msg, msg.size)
    raise "EVP_MAC_update failed" if rc != 1
  end

  # Finalizes the MAC computation and returns the 16-byte authenticator.
  def final : Bytes
    tag = Bytes.new(BLOCK_SIZE)
    outl = LibC::SizeT.new(0)
    rc = LibCrypto.evp_mac_final(@ctx, tag, pointerof(outl), BLOCK_SIZE)
    raise "EVP_MAC_final failed" if rc != 1
    free_resources
    tag
  end

  # A convenience method to compute a Poly1305 MAC for a single message.
  def self.auth(key : Bytes, message : Bytes) : Bytes
    pa = new(key)
    pa.update(message)
    pa.final
  end

  def finalize
    free_resources
  end

  private def free_resources
    return if @finalized
    @finalized = true
    LibCrypto.evp_mac_ctx_free(@ctx)
    LibCrypto.evp_mac_free(@mac)
  end
end

{% end %}
