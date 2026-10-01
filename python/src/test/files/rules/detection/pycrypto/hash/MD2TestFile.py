from Crypto.Hash import MD2

hash_md2 = MD2.new() # Noncompliant {{(MessageDigest) MD2}}
