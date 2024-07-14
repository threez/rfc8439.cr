# AEAD_CHACHA20_POLY1305 is an authenticated encryption with additional
# data algorithm.  The inputs to AEAD_CHACHA20_POLY1305 are:
#
# * key: A 256-bit key
# * nonce: A 96-bit nonce -- different for each invocation with the same key
# * aead: the buffer to write the authenticated plain and ciphertext to
class Crypto::AeadChacha20Poly1305
  def initialize(key : Bytes, nonce : Bytes, @aead : IO)
    @cipher = Crypto::ChaCha20.new(key, nonce, 1)
    @mac = Crypto::Poly1305.chacha20(@cipher)
    @aad_size = 0_u64
    @plaintext_size = 0_u64
  end

  # Arbitrary length additional authenticated data (AAD).
  # Needs to be written before the plaintext. Can be called multiple
  # times, but only the last block can be less then 16 bytes.
  def aad(data : Bytes)
    @aad_size += data.size
    write(data)
  end

  # An arbitrary length plaintext, has to be multiples of 16 bytes
  # last call might be with less then 16 bytes
  def update(data : Bytes)
    @plaintext_size += data.size
    write(@cipher.encrypt(data))
  end

  def final : Bytes
    footer = Bytes.new(16, 0)
    IO::ByteFormat::LittleEndian.encode(@aad_size, footer[0..8])
    IO::ByteFormat::LittleEndian.encode(@plaintext_size, footer[8..15])
    write(footer)
    @mac.final
  end

  private def write(data : Bytes)
    pad = data.size % 16

    if data.size >= 16
      aligned_data = data[0..(data.size-pad-1)]
      @aead.write(aligned_data)
      @mac.update(aligned_data)
    end

    if pad > 0
      data_with_padding = Bytes.new(16, 0)
      remainder = data[(data.size - pad)..]
      Intrinsics.memcpy(data_with_padding.to_unsafe, remainder.to_unsafe, pad, false)

      @aead.write(data_with_padding)
      @mac.update(data_with_padding)
    end
  end
end
