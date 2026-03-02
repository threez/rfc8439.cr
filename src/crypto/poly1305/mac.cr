abstract class Crypto::Poly1305::MAC
  abstract def key : Bytes
  abstract def update(msg : Bytes)
  abstract def final : Bytes
end
