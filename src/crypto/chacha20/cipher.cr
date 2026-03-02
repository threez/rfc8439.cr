abstract class Crypto::ChaCha20::Cipher
  abstract def encrypt(plaintext : Bytes) : Bytes
  abstract def encrypt(plaintext : Bytes, encrypted : Bytes) : Nil
  abstract def next_key_block : UInt32[16]
  abstract def reset
end
