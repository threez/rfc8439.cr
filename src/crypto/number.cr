{% for n in [8, 12, 32, 64] %}
struct UInt{{n}}
  # bitwise rotation (or circular shift) operation. It’s named rotl,
  # which stands for “rotate left {{n}}-bit”.
  # The rotation is performed by n places.
  def rotl(n : Int{{n}}) : UInt{{n}}
    (self << n) | (self >> ({{n}}.to_u{{n}} - n))
  end
end
{% end %}
